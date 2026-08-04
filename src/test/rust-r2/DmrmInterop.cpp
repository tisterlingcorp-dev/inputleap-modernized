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
constexpr std::size_t kPayloadSize = 8;
constexpr std::size_t kFrameSize = 12;

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

std::int16_t parseI16(std::string_view value) {
    int parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (value.empty() || result.ec != std::errc{} || result.ptr != value.data() + value.size() ||
        parsed < (std::numeric_limits<std::int16_t>::min)() || parsed > (std::numeric_limits<std::int16_t>::max)())
        throw std::invalid_argument("coordinate must be a decimal i16");
    return static_cast<std::int16_t>(parsed);
}

std::vector<std::uint8_t> payload(std::int16_t x, std::int16_t y) {
    Capture capture;
    ProtocolUtil::writef(&capture, kMsgDMouseRelMove, static_cast<int>(x), static_cast<int>(y));
    if (capture.bytes().size() != kPayloadSize ||
        !std::equal(capture.bytes().begin(), capture.bytes().begin() + 4, "DMRM"))
        throw std::logic_error("ProtocolUtil DMRM writer emitted unexpected payload");
    return capture.bytes();
}

std::vector<std::uint8_t> frame(std::int16_t x, std::int16_t y) {
    const auto bytes = payload(x, y);
    Events events;
    auto stream = std::make_unique<Capture>();
    auto* capture = stream.get();
    PacketStreamFilter packetizer(&events, std::move(stream));
    packetizer.write(bytes.data(), static_cast<std::uint32_t>(bytes.size()));
    if (capture->bytes().size() != kFrameSize) throw std::logic_error("PacketStreamFilter DMRM frame size mismatch");
    return capture->bytes();
}

void writeFile(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes, bool exclusive) {
    if (exclusive) {
#ifdef _WIN32
        const auto handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE) throw std::runtime_error("refusing to overwrite existing output");
        DWORD written = 0;
        const bool ok = WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) != 0 && written == bytes.size() && FlushFileBuffers(handle) != 0 && CloseHandle(handle) != 0;
        if (!ok) throw std::runtime_error("exclusive output write failed");
#else
        const auto descriptor = ::open(path.string().c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (descriptor < 0) throw std::runtime_error("refusing to overwrite existing output");
        const auto written = ::write(descriptor, bytes.data(), bytes.size());
        const bool ok = written == static_cast<ssize_t>(bytes.size()) && ::fsync(descriptor) == 0 && ::close(descriptor) == 0;
        if (!ok) throw std::runtime_error("exclusive output write failed");
#endif
        return;
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("unable to open output");
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!output) throw std::runtime_error("unable to write output");
}

std::vector<std::uint8_t> readExact(const std::filesystem::path& path, std::size_t size) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input || input.tellg() != static_cast<std::streamoff>(size)) throw std::runtime_error("input is not an exact DMRM file");
    std::vector<std::uint8_t> bytes(size);
    input.seekg(0);
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
    if (!input) throw std::runtime_error("unable to read exact DMRM input");
    return bytes;
}
}

} // namespace inputleap

int main(int argc, char** argv) {
    if (argc != 5) {
        std::cerr << "usage: rust-r2-dmrm-interop <emit-frame|fixture-frame|decode-frame> <x> <y> <path>\n";
        return 2;
    }
    try {
        inputleap::Log log;
        const auto x = inputleap::parseI16(argv[2]);
        const auto y = inputleap::parseI16(argv[3]);
        const std::filesystem::path path(argv[4]);
        const std::string_view mode(argv[1]);
        const auto expected = inputleap::frame(x, y);
        if (mode == "emit-frame") inputleap::writeFile(path, expected, false);
        else if (mode == "fixture-frame") inputleap::writeFile(path, expected, true);
        else if (mode == "decode-frame") {
            if (inputleap::readExact(path, expected.size()) != expected) throw std::runtime_error("bytes differ from C++ DMRM frame oracle");
        }
        else { std::cerr << "rust-r2-dmrm-interop: unknown mode\n"; return 2; }
        std::cout << "DMRM_CPP_" << (mode == "decode-frame" ? "DECODE" : "EMIT") << "_PASS x=" << x << " y=" << y << " frame_bytes=" << expected.size() << "\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "rust-r2-dmrm-interop: " << error.what() << '\n';
        return 1;
    }
}