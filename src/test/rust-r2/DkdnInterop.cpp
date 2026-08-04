#include "base/Event.h"
#include "base/EventQueueTimer.h"
#include "base/EventTarget.h"
#include "base/IEventQueue.h"
#include "base/IEventQueueBuffer.h"
#include "base/Log.h"
#include "inputleap/PacketStreamFilter.h"
#include "inputleap/ProtocolUtil.h"
#include "inputleap/protocol_types.h"
#include "io/IStream.h"

#ifdef _WIN32
#define NOMINMAX
#include <Windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace inputleap {
namespace {
constexpr std::size_t kPayloadSize = 10;
constexpr std::size_t kFrameSize = 14;

class Events final : public IEventQueue {
public:
    void loop() override {}
    void set_buffer(std::unique_ptr<IEventQueueBuffer>) override {}
    bool getEvent(Event&, double) override { return false; }
    bool dispatchEvent(const Event&) override { return false; }
    void add_event(Event&& event) override { Event::deleteData(event); }
    EventQueueTimer* newTimer(double, const EventTarget*) override { return nullptr; }
    EventQueueTimer* newOneShotTimer(double, const EventTarget*) override { return nullptr; }
    void deleteTimer(EventQueueTimer*) override {}
    void add_handler(EventType, const EventTarget*, const EventHandler&) override {}
    void remove_handler(EventType, const EventTarget*) override {}
    void remove_handlers(const EventTarget*) override {}
    void waitForReady() const override {}
    const EventTarget* getSystemTarget() override { return &target_; }
private:
    EventTarget target_;
};

class Capture final : public IStream {
public:
    void close() override {}
    std::uint32_t read(void*, std::uint32_t) override { return 0; }
    void write(const void* data, std::uint32_t size) override {
        if (size != 0 && data == nullptr) throw std::invalid_argument("null capture data");
        const auto* begin = static_cast<const std::uint8_t*>(data);
        bytes_.insert(bytes_.end(), begin, begin + size);
    }
    void flush() override {}
    void shutdownInput() override {}
    void shutdownOutput() override {}
    const EventTarget* get_event_target() const override { return nullptr; }
    bool isReady() const override { return false; }
    std::uint32_t getSize() const override { return static_cast<std::uint32_t>(bytes_.size()); }
    const std::vector<std::uint8_t>& bytes() const { return bytes_; }
private:
    std::vector<std::uint8_t> bytes_;
};

std::uint16_t parseU16(std::string_view value) {
    unsigned int parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (value.empty() || result.ec != std::errc{} || result.ptr != value.data() + value.size() ||
        parsed > (std::numeric_limits<std::uint16_t>::max)())
        throw std::invalid_argument("field must be a decimal u16");
    return static_cast<std::uint16_t>(parsed);
}

std::vector<std::uint8_t> payload(std::uint16_t keyId, std::uint16_t modifierMask,
                                  std::uint16_t button) {
    Capture capture;
    ProtocolUtil::writef(&capture, kMsgDKeyDown, static_cast<int>(keyId),
                         static_cast<int>(modifierMask), static_cast<int>(button));
    if (capture.bytes().size() != kPayloadSize ||
        !std::equal(capture.bytes().begin(), capture.bytes().begin() + 4, "DKDN"))
        throw std::logic_error("ProtocolUtil DKDN writer emitted unexpected payload");
    return capture.bytes();
}

std::vector<std::uint8_t> frame(std::uint16_t keyId, std::uint16_t modifierMask,
                                std::uint16_t button) {
    const auto bytes = payload(keyId, modifierMask, button);
    Events events;
    auto stream = std::make_unique<Capture>();
    auto* capture = stream.get();
    PacketStreamFilter packetizer(&events, std::move(stream));
    packetizer.write(bytes.data(), static_cast<std::uint32_t>(bytes.size()));
    if (capture->bytes().size() != kFrameSize)
        throw std::logic_error("PacketStreamFilter DKDN frame size mismatch");
    return capture->bytes();
}

void writeFile(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes,
               bool exclusive) {
    if (exclusive) {
#ifdef _WIN32
        const auto handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                        FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE)
            throw std::runtime_error("refusing to overwrite existing output");
        DWORD written = 0;
        const bool ok = WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &written,
                                  nullptr) != 0 &&
                        written == bytes.size() && FlushFileBuffers(handle) != 0 &&
                        CloseHandle(handle) != 0;
        if (!ok) throw std::runtime_error("exclusive output write failed");
#else
        const auto descriptor = ::open(path.string().c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (descriptor < 0) throw std::runtime_error("refusing to overwrite existing output");
        const auto written = ::write(descriptor, bytes.data(), bytes.size());
        const bool ok = written == static_cast<ssize_t>(bytes.size()) && ::fsync(descriptor) == 0 &&
                        ::close(descriptor) == 0;
        if (!ok) throw std::runtime_error("exclusive output write failed");
#endif
        return;
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("unable to open output");
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!output) throw std::runtime_error("unable to write output");
}

std::vector<std::uint8_t> readExact(const std::filesystem::path& path, std::size_t size) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input || input.tellg() != static_cast<std::streamoff>(size))
        throw std::runtime_error("input is not an exact DKDN file");
    std::vector<std::uint8_t> bytes(size);
    input.seekg(0);
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
    if (!input) throw std::runtime_error("unable to read exact DKDN input");
    return bytes;
}
}
} // namespace inputleap

int main(int argc, char** argv) {
    if (argc != 6) {
        std::cerr << "usage: rust-r2-dkdn-interop <emit-frame|fixture-frame|decode-frame> "
                     "<key-id> <modifier-mask> <button> <path>\n";
        return 2;
    }
    try {
        inputleap::Log log;
        const auto keyId = inputleap::parseU16(argv[2]);
        const auto modifierMask = inputleap::parseU16(argv[3]);
        const auto button = inputleap::parseU16(argv[4]);
        const std::filesystem::path path(argv[5]);
        const std::string_view mode(argv[1]);
        const auto expected = inputleap::frame(keyId, modifierMask, button);
        if (mode == "emit-frame") inputleap::writeFile(path, expected, false);
        else if (mode == "fixture-frame") inputleap::writeFile(path, expected, true);
        else if (mode == "decode-frame") {
            if (inputleap::readExact(path, expected.size()) != expected)
                throw std::runtime_error("bytes differ from C++ DKDN frame oracle");
        }
        else {
            std::cerr << "rust-r2-dkdn-interop: unknown mode\n";
            return 2;
        }
        std::cout << "DKDN_CPP_" << (mode == "decode-frame" ? "DECODE" : "EMIT")
                  << "_PASS key_id=" << keyId << " modifier_mask=" << modifierMask
                  << " button=" << button << " frame_bytes=" << expected.size() << "\n";
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "rust-r2-dkdn-interop: " << error.what() << '\n';
        return 1;
    }
}
