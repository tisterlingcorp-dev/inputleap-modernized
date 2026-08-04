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
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cerrno>
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

constexpr std::size_t kPayloadSize = 5;
constexpr std::size_t kFrameSize = 9;

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
        const auto write_size = static_cast<std::size_t>(size);
        if (write_size > bytes_.max_size() - bytes_.size()) {
            throw std::length_error("capture stream size overflow");
        }
        const auto* begin = static_cast<const std::uint8_t*>(data);
        bytes_.insert(bytes_.end(), begin, begin + write_size);
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

std::uint8_t parseRaw(std::string_view value)
{
    if (value == "0") {
        return 0;
    }
    if (value == "1") {
        return 1;
    }
    throw std::invalid_argument("screen-saver raw value must be 0 or 1");
}

std::vector<std::uint8_t> oraclePayload(std::uint8_t raw)
{
    CaptureStream stream;
    ProtocolUtil::writef(&stream, kMsgCScreenSaver, static_cast<int>(raw));
    if (stream.bytes().size() != kPayloadSize || stream.bytes().back() != raw) {
        throw std::logic_error("CSEC ProtocolUtil writer oracle emitted unexpected bytes");
    }
    return stream.bytes();
}

std::vector<std::uint8_t> oracleFrame(std::uint8_t raw)
{
    const auto payload = oraclePayload(raw);
    FrameEventQueue events;
    auto capture = std::make_unique<CaptureStream>();
    auto* capture_ptr = capture.get();
    PacketStreamFilter packetizer(&events, std::move(capture));
    packetizer.write(payload.data(), static_cast<std::uint32_t>(payload.size()));
    const auto frame = capture_ptr->bytes();
    if (frame.size() != kFrameSize) {
        throw std::logic_error("CSEC PacketStreamFilter writer oracle emitted unexpected size");
    }
    return frame;
}

void writeNewBytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes)
{
#ifdef _WIN32
    if (bytes.size() > static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())) {
        throw std::length_error("exclusive output size exceeds DWORD");
    }
    const auto handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const auto error = GetLastError();
        if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS) {
            throw std::runtime_error("refusing to overwrite existing fixture candidate");
        }
        throw std::runtime_error("unable to create exclusive output file");
    }
    DWORD written = 0;
    const auto write_ok = WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()),
                                    &written, nullptr);
    const auto flush_ok = write_ok != 0 && FlushFileBuffers(handle) != 0;
    const auto close_ok = CloseHandle(handle) != 0;
    if (write_ok == 0 || static_cast<std::size_t>(written) != bytes.size() || !flush_ok ||
        !close_ok) {
        throw std::runtime_error("unable to write exclusive output file");
    }
#else
    const auto descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor < 0) {
        if (errno == EEXIST) {
            throw std::runtime_error("refusing to overwrite existing fixture candidate");
        }
        throw std::runtime_error("unable to create exclusive output file");
    }
    std::size_t offset = 0;
    bool failed = false;
    while (offset < bytes.size()) {
        const auto written = ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            failed = true;
            break;
        }
        offset += static_cast<std::size_t>(written);
    }
    const auto sync_result = ::fsync(descriptor);
    const auto close_result = ::close(descriptor);
    if (sync_result != 0 || close_result != 0) {
        failed = true;
    }
    if (failed) {
        throw std::runtime_error("unable to write exclusive output file");
    }
#endif
}

void writeBytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes,
                bool refuse_existing)
{
    if (refuse_existing) {
        writeNewBytes(path, bytes);
        return;
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
                                         std::size_t expected_size)
{
    if (expected_size >
        static_cast<std::size_t>((std::numeric_limits<std::streamsize>::max)())) {
        throw std::length_error("expected input size exceeds streamsize");
    }
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        throw std::runtime_error("unable to open input file");
    }
    const auto end = input.tellg();
    if (end < 0 || static_cast<std::uintmax_t>(end) != expected_size) {
        throw std::length_error("input file size does not match expected CSEC size");
    }
    std::vector<std::uint8_t> bytes(expected_size);
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
        throw std::length_error("input file grew beyond expected CSEC size");
    }
    if (!input.eof()) {
        throw std::runtime_error("unable to confirm input end-of-file");
    }
    return bytes;
}

void emit(std::uint8_t raw, const std::filesystem::path& path, bool fixture_mode, bool framed)
{
    const auto bytes = framed ? oracleFrame(raw) : oraclePayload(raw);
    writeBytes(path, bytes, fixture_mode);
    std::cout << (framed ? "CSEC_CPP_FRAME_EMIT_PASS" : "CSEC_CPP_EMIT_PASS")
              << " raw=" << static_cast<unsigned int>(raw) << " bytes=" << bytes.size()
              << " path=" << path << '\n';
}

void decode(std::uint8_t raw, const std::filesystem::path& path, bool framed)
{
    const auto expected = framed ? oracleFrame(raw) : oraclePayload(raw);
    const auto bytes = readExactBytes(path, expected.size());
    if (!std::equal(bytes.begin(), bytes.end(), expected.begin(), expected.end())) {
        throw std::runtime_error("bytes do not match the real kMsgCScreenSaver writer oracle");
    }
    std::cout << (framed ? "CSEC_CPP_FRAME_DECODE_PASS" : "CSEC_CPP_DECODE_PASS")
              << " raw=" << static_cast<unsigned int>(raw) << " consumed=" << bytes.size()
              << " coverage=RAW_BYTE_EQUALITY_ONLY path=" << path << '\n';
}

} // namespace
} // namespace inputleap::rust_r2

int main(int argc, char** argv)
{
    if (argc != 4) {
        std::cerr << "usage: rust-r2-screensaver-interop "
                     "<emit|fixture|decode|emit-frame|decode-frame> <0|1> <path>\n";
        return 2;
    }

    try {
        inputleap::Log log;
        const std::string_view mode{argv[1]};
        const auto raw = inputleap::rust_r2::parseRaw(argv[2]);
        if (mode == "emit") {
            inputleap::rust_r2::emit(raw, argv[3], false, false);
        }
        else if (mode == "fixture") {
            inputleap::rust_r2::emit(raw, argv[3], true, false);
        }
        else if (mode == "decode") {
            inputleap::rust_r2::decode(raw, argv[3], false);
        }
        else if (mode == "emit-frame") {
            inputleap::rust_r2::emit(raw, argv[3], false, true);
        }
        else if (mode == "decode-frame") {
            inputleap::rust_r2::decode(raw, argv[3], true);
        }
        else {
            std::cerr << "rust-r2-screensaver-interop: unknown mode\n";
            return 2;
        }
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "rust-r2-screensaver-interop: " << error.what() << '\n';
        return 1;
    }
}
