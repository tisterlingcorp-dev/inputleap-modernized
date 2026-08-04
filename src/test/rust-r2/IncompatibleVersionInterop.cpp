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

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace inputleap::rust_r2 {
namespace {

constexpr std::size_t kPayloadSize = 8;
constexpr std::size_t kFrameSize = 12;

class FrameEventQueue final : public IEventQueue
{
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
    const EventTarget* getSystemTarget() override { return &system_target_; }

private:
    EventTarget system_target_;
};

class CaptureStream final : public IStream
{
public:
    void close() override {}
    std::uint32_t read(void*, std::uint32_t) override { return 0; }

    void write(const void* data, std::uint32_t size) override
    {
        if (size == 0) {
            return;
        }
        if (data == nullptr) {
            throw std::invalid_argument("capture stream received null data");
        }
        const auto writeSize = static_cast<std::size_t>(size);
        if (writeSize > bytes_.max_size() - bytes_.size()) {
            throw std::length_error("capture stream size overflow");
        }
        const auto* begin = static_cast<const std::uint8_t*>(data);
        bytes_.insert(bytes_.end(), begin, begin + writeSize);
    }

    void flush() override {}
    void shutdownInput() override {}
    void shutdownOutput() override {}
    const EventTarget* get_event_target() const override { return nullptr; }
    bool isReady() const override { return false; }
    std::uint32_t getSize() const override
    {
        if (bytes_.size() > (std::numeric_limits<std::uint32_t>::max)()) {
            throw std::length_error("capture stream size exceeds u32");
        }
        return static_cast<std::uint32_t>(bytes_.size());
    }

    const std::vector<std::uint8_t>& bytes() const { return bytes_; }

private:
    std::vector<std::uint8_t> bytes_;
};

std::vector<std::uint8_t> oraclePayload()
{
    CaptureStream stream;
    ProtocolUtil::writef(&stream, kMsgEIncompatible,
                         kProtocolMajorVersion, kProtocolMinorVersion);
    if (stream.bytes().size() != kPayloadSize) {
        throw std::length_error("EICV ProtocolUtil oracle did not emit eight bytes");
    }
    return stream.bytes();
}

std::vector<std::uint8_t> oracleFrame()
{
    const auto payload = oraclePayload();
    FrameEventQueue events;
    auto capture = std::make_unique<CaptureStream>();
    auto* capturePtr = capture.get();
    PacketStreamFilter packetizer(&events, std::move(capture));
    packetizer.write(payload.data(), static_cast<std::uint32_t>(payload.size()));
    const auto frame = capturePtr->bytes();
    if (frame.size() != kFrameSize) {
        throw std::logic_error("EICV PacketStreamFilter oracle has unexpected size");
    }
    return frame;
}

void writeBytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes,
                bool refuseExisting)
{
    if (refuseExisting && std::filesystem::exists(path)) {
        throw std::runtime_error("refusing to overwrite existing fixture candidate");
    }
    if (bytes.size() > static_cast<std::size_t>((std::numeric_limits<std::streamsize>::max)())) {
        throw std::length_error("output size exceeds streamsize");
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("unable to open output file");
    }
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!output) {
        throw std::runtime_error("unable to write output file");
    }
}

std::vector<std::uint8_t> readExactBytes(const std::filesystem::path& path,
                                         std::size_t expectedSize)
{
    if (expectedSize > static_cast<std::size_t>((std::numeric_limits<std::streamsize>::max)())) {
        throw std::length_error("expected input size exceeds streamsize");
    }
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        throw std::runtime_error("unable to open input file");
    }
    const auto end = input.tellg();
    if (end < 0 || static_cast<std::uintmax_t>(end) != expectedSize) {
        throw std::length_error("input file size does not match expected EICV size");
    }
    std::vector<std::uint8_t> bytes(expectedSize);
    input.seekg(0);
    if (!input) {
        throw std::runtime_error("unable to seek input file");
    }
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
    }
    if (!input) {
        throw std::runtime_error("unable to read exact input bytes");
    }
    char trailing = 0;
    input.read(&trailing, 1);
    if (input.gcount() != 0) {
        throw std::length_error("input file grew beyond expected EICV size");
    }
    if (!input.eof()) {
        throw std::runtime_error("unable to confirm input end-of-file");
    }
    return bytes;
}

void emit(const std::filesystem::path& path, bool fixtureMode, bool framed)
{
    const auto bytes = framed ? oracleFrame() : oraclePayload();
    writeBytes(path, bytes, fixtureMode);
    std::cout << (framed ? "EICV_CPP_FRAME_EMIT_PASS" : "EICV_CPP_EMIT_PASS")
              << " bytes=" << bytes.size()
              << " numeric_fields=NOT_ORACLED_CPP_CONSUMER_BUG path=" << path << '\n';
}

void decode(const std::filesystem::path& path, bool framed)
{
    const auto expected = framed ? oracleFrame() : oraclePayload();
    const auto bytes = readExactBytes(path, expected.size());
    if (!std::equal(bytes.begin(), bytes.end(), expected.begin(), expected.end())) {
        throw std::runtime_error("bytes do not match the real kMsgEIncompatible writer oracle");
    }
    std::cout << (framed ? "EICV_CPP_FRAME_DECODE_PASS" : "EICV_CPP_DECODE_PASS")
              << " consumed=" << bytes.size()
              << " coverage=RAW_BYTE_EQUALITY_ONLY"
              << " numeric_fields=NOT_ORACLED_CPP_CONSUMER_BUG path=" << path << '\n';
}

} // namespace
} // namespace inputleap::rust_r2

int main(int argc, char** argv)
{
    if (argc != 3) {
        std::cerr << "usage: rust-r2-incompatible-version-interop "
                     "<emit|fixture|decode|emit-frame|decode-frame> <path>\n";
        return 2;
    }

    try {
        inputleap::Log log;
        const std::string_view mode{argv[1]};
        if (mode == "emit") {
            inputleap::rust_r2::emit(argv[2], false, false);
        }
        else if (mode == "fixture") {
            inputleap::rust_r2::emit(argv[2], true, false);
        }
        else if (mode == "decode") {
            inputleap::rust_r2::decode(argv[2], false);
        }
        else if (mode == "emit-frame") {
            inputleap::rust_r2::emit(argv[2], false, true);
        }
        else if (mode == "decode-frame") {
            inputleap::rust_r2::decode(argv[2], true);
        }
        else {
            std::cerr << "rust-r2-incompatible-version-interop: unknown mode\n";
            return 2;
        }
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "rust-r2-incompatible-version-interop: " << error.what() << '\n';
        return 1;
    }
}
