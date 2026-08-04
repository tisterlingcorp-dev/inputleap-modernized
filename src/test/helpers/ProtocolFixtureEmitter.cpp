#include "test/helpers/ProtocolFixtureEmitter.h"

#include "base/Log.h"
#include "inputleap/ProtocolUtil.h"
#include "inputleap/protocol_types.h"
#include "ipc/Ipc.h"
#include "io/IStream.h"
#include <openssl/evp.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace inputleap::protocol_fixture {
namespace {

#ifndef PROTOCOL_FIXTURE_SOURCE_REVISION
#define PROTOCOL_FIXTURE_SOURCE_REVISION "unavailable"
#endif
#ifndef PROTOCOL_FIXTURE_PLATFORM
#define PROTOCOL_FIXTURE_PLATFORM "unavailable"
#endif
#ifndef PROTOCOL_FIXTURE_ARCHITECTURE
#define PROTOCOL_FIXTURE_ARCHITECTURE "unavailable"
#endif
#ifndef PROTOCOL_FIXTURE_COMPILER
#define PROTOCOL_FIXTURE_COMPILER "unavailable"
#endif
#ifndef PROTOCOL_FIXTURE_ENDIANNESS
#define PROTOCOL_FIXTURE_ENDIANNESS "unavailable"
#endif

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

        const auto maximumSize = (std::min)(
            bytes_.max_size(),
            static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()));
        const auto writeSize = static_cast<std::size_t>(size);
        if (bytes_.size() > maximumSize || writeSize > maximumSize - bytes_.size()) {
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
        return static_cast<std::uint32_t>(bytes_.size());
    }

    std::vector<std::uint8_t> takeBytes() { return std::move(bytes_); }

private:
    std::vector<std::uint8_t> bytes_;
};

void appendBigEndian32(std::vector<std::uint8_t>& bytes, std::uint32_t value)
{
    bytes.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
    bytes.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xff));
}

std::vector<std::uint8_t> remoteFrame(std::vector<std::uint8_t> payload)
{
    if (payload.size() > (std::numeric_limits<std::uint32_t>::max)()) {
        throw std::length_error("remote fixture payload size overflow");
    }

    std::vector<std::uint8_t> frame;
    if (payload.size() > frame.max_size() - 4u) {
        throw std::length_error("remote fixture frame size overflow");
    }
    frame.reserve(4u + payload.size());
    appendBigEndian32(frame, static_cast<std::uint32_t>(payload.size()));
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

std::vector<std::uint8_t> messageCode(const char* format)
{
    if (format == nullptr) {
        throw std::invalid_argument("fixture message format is null");
    }
    return {format, format + 4};
}

bool isSafeFixtureName(std::string_view name)
{
    if (name.empty()) {
        return false;
    }
    return std::all_of(name.begin(), name.end(), [](unsigned char character) {
        return (character >= 'a' && character <= 'z') ||
               (character >= '0' && character <= '9') || character == '-';
    });
}

void writeJsonString(std::ostream& output, std::string_view value)
{
    output.put('"');
    for (const unsigned char character : value) {
        switch (character) {
        case '"':
            output << "\\\"";
            break;
        case '\\':
            output << "\\\\";
            break;
        case '\b':
            output << "\\b";
            break;
        case '\f':
            output << "\\f";
            break;
        case '\n':
            output << "\\n";
            break;
        case '\r':
            output << "\\r";
            break;
        case '\t':
            output << "\\t";
            break;
        default:
            if (character < 0x20) {
                constexpr char hex[] = "0123456789abcdef";
                output << "\\u00" << hex[character >> 4] << hex[character & 0x0f];
            }
            else {
                output.put(static_cast<char>(character));
            }
            break;
        }
    }
    output.put('"');
}

std::string sha256Hex(const std::vector<std::uint8_t>& bytes)
{
    std::uint8_t digest[EVP_MAX_MD_SIZE]{};
    unsigned int digestSize = 0;
    const void* data = bytes.empty() ? static_cast<const void*>("") : bytes.data();
    if (EVP_Digest(data, bytes.size(), digest, &digestSize, EVP_sha256(), nullptr) != 1 ||
        digestSize != 32) {
        throw std::runtime_error("fixture digest failed");
    }
    constexpr char hex[] = "0123456789abcdef";
    std::string encoded;
    encoded.reserve(digestSize * 2u);
    for (unsigned int index = 0; index < digestSize; ++index) {
        encoded.push_back(hex[digest[index] >> 4]);
        encoded.push_back(hex[digest[index] & 0x0f]);
    }
    return encoded;
}

const char* categoryName(Category category)
{
    switch (category) {
    case Category::Accepted:
        return "Accepted";
    case Category::NeedMore:
        return "NeedMore";
    case Category::Malformed:
        return "Malformed";
    case Category::Oversized:
        return "Oversized";
    case Category::UnsupportedVersion:
        return "UnsupportedVersion";
    }
    throw std::invalid_argument("unknown fixture category");
}

void writeFixture(const std::filesystem::path& outputDirectory, const Fixture& fixture)
{
    if (fixture.bytes.size() >
        static_cast<std::size_t>((std::numeric_limits<std::streamsize>::max)())) {
        throw std::length_error("fixture output size overflow");
    }

    const std::string relativePath = fixture.name + ".bin";
    std::ofstream bytesFile(outputDirectory / relativePath, std::ios::binary | std::ios::trunc);
    if (!bytesFile) {
        throw std::runtime_error("unable to open fixture output");
    }
    bytesFile.write(
        reinterpret_cast<const char*>(fixture.bytes.data()),
        static_cast<std::streamsize>(fixture.bytes.size()));
    if (!bytesFile) {
        throw std::runtime_error("unable to write fixture output");
    }
    bytesFile.close();
    if (!bytesFile) {
        throw std::runtime_error("unable to close fixture output");
    }
}

void emitImpl(const std::filesystem::path& outputDirectory, const std::vector<Fixture>& fixtures)
{
    if (fixtures.empty()) {
        throw std::invalid_argument("fixture corpus is empty");
    }

    std::set<std::string> names;
    for (const auto& fixture : fixtures) {
        if (!isSafeFixtureName(fixture.name) || fixture.oracle.empty() || fixture.kind.empty() ||
            fixture.sourceSymbol.empty() ||
            !names.insert(fixture.name).second) {
            throw std::invalid_argument("fixture metadata is invalid");
        }
    }

    const auto outputStatus = std::filesystem::symlink_status(outputDirectory);
    if (std::filesystem::exists(outputStatus)) {
        throw std::runtime_error("fixture output directory already exists");
    }
    const auto stagingDirectory = outputDirectory.string() + ".staging";
    const auto stagingStatus = std::filesystem::symlink_status(stagingDirectory);
    if (std::filesystem::exists(stagingStatus)) {
        throw std::runtime_error("fixture staging directory already exists");
    }
    if (!outputDirectory.parent_path().empty()) {
        std::filesystem::create_directories(outputDirectory.parent_path());
    }
    std::filesystem::create_directory(stagingDirectory);
    for (const auto& fixture : fixtures) {
        writeFixture(stagingDirectory, fixture);
    }

    std::ofstream manifestFile(
        std::filesystem::path(stagingDirectory) / "manifest.json", std::ios::binary | std::ios::trunc);
    if (!manifestFile) {
        throw std::runtime_error("unable to open fixture manifest");
    }
    manifestFile
        << "{\n"
        << "  \"schema\": 1,\n"
        << "  \"oracle\": \"C++ InputLeap wire oracle\",\n"
        << "  \"sourceRevision\": ";
    writeJsonString(manifestFile, PROTOCOL_FIXTURE_SOURCE_REVISION);
    manifestFile << ",\n  \"sourceManifest\": "
                 << "\"docs/architecture/rust-rewrite/r0-source-manifest.json\",\n"
                 << "  \"platform\": ";
    writeJsonString(manifestFile, PROTOCOL_FIXTURE_PLATFORM);
    manifestFile << ",\n  \"architecture\": ";
    writeJsonString(manifestFile, PROTOCOL_FIXTURE_ARCHITECTURE);
    manifestFile << ",\n  \"compiler\": ";
    writeJsonString(manifestFile, PROTOCOL_FIXTURE_COMPILER);
    manifestFile << ",\n  \"endianness\": ";
    writeJsonString(manifestFile, PROTOCOL_FIXTURE_ENDIANNESS);
    manifestFile << ",\n  \"fixtures\": [\n";
    for (std::size_t index = 0; index < fixtures.size(); ++index) {
        const auto& fixture = fixtures[index];
        const std::string relativePath = fixture.name + ".bin";
        manifestFile << "    {\n      \"name\": ";
        writeJsonString(manifestFile, fixture.name);
        manifestFile << ",\n      \"category\": ";
        writeJsonString(manifestFile, categoryName(fixture.category));
        manifestFile << ",\n      \"oracle\": ";
        writeJsonString(manifestFile, fixture.oracle);
        manifestFile << ",\n      \"kind\": ";
        writeJsonString(manifestFile, fixture.kind);
        manifestFile << ",\n      \"sourceSymbol\": ";
        writeJsonString(manifestFile, fixture.sourceSymbol);
        manifestFile << ",\n      \"sha256\": ";
        writeJsonString(manifestFile, sha256Hex(fixture.bytes));
        manifestFile << ",\n      \"path\": ";
        writeJsonString(manifestFile, relativePath);
        manifestFile << ",\n      \"size\": " << fixture.bytes.size() << "\n    }";
        if (index + 1u != fixtures.size()) {
            manifestFile << ',';
        }
        manifestFile << '\n';
    }
    manifestFile << "  ]\n}\n";
    if (!manifestFile) {
        throw std::runtime_error("unable to write fixture manifest");
    }
    manifestFile.close();
    if (!manifestFile) {
        throw std::runtime_error("unable to close fixture manifest");
    }
    std::filesystem::rename(stagingDirectory, outputDirectory);
}

} // namespace

void emit(const std::filesystem::path& outputDirectory, const std::vector<Fixture>& fixtures)
{
    emitImpl(outputDirectory, fixtures);
}

Fixture consecutiveStrings()
{
    CaptureStream stream;
    std::string alpha = "alpha";
    std::string beta = "beta";
    ProtocolUtil::writef(&stream, "TEST%s%s", &alpha, &beta);
    return {"writef-consecutive-strings", Category::Accepted, stream.takeBytes(),
            "ProtocolUtil::writef", "payload", "ProtocolUtil::writef"};
}

std::vector<Fixture> initialCorpus()
{
    CaptureStream hello;
    ProtocolUtil::writef(&hello, kMsgHello, kProtocolMajorVersion, kProtocolMinorVersion);

    CaptureStream helloBack;
    std::string clientName = "kat-client";
    ProtocolUtil::writef(&helloBack, kMsgHelloBack, kProtocolMajorVersion, 7, &clientName);

    std::vector<std::uint8_t> oversizedRemoteLength;
    appendBigEndian32(oversizedRemoteLength, PROTOCOL_MAX_MESSAGE_LENGTH + 1u);

    CaptureStream ipcHello;
    ProtocolUtil::writef(&ipcHello, kIpcMsgHello, kIpcClientGui);

    auto oversizedIpcLog = messageCode(kIpcMsgLogLine);
    appendBigEndian32(oversizedIpcLog, PROTOCOL_MAX_STRING_LENGTH + 1u);

    return {
        {"remote-hello-1-6", Category::Accepted, remoteFrame(hello.takeBytes()),
         "ProtocolUtil::writef + PacketStreamFilter::write framing", "remote-frame",
         "kMsgHello; ProtocolUtil::writef; PacketStreamFilter::write"},
        {"remote-hello-back-1-7", Category::UnsupportedVersion,
         remoteFrame(helloBack.takeBytes()),
         "ProtocolUtil::writef + PacketStreamFilter::write framing", "remote-frame",
         "kMsgHelloBack; ProtocolUtil::writef; PacketStreamFilter::write"},
        {"remote-truncated-prefix", Category::NeedMore, {0, 0, 0},
         "PacketStreamFilter wire contract", "remote-frame",
         "PacketStreamFilter::readPacketSize"},
        {"remote-oversized-length", Category::Oversized, std::move(oversizedRemoteLength),
         "PacketStreamFilter wire contract", "remote-frame",
         "PacketStreamFilter::readPacketSize"},
        {"remote-unknown-code", Category::Malformed,
         remoteFrame({'Z', 'Z', 'Z', 'Z'}),
         "PacketStreamFilter framing + protocol message-code contract", "remote-frame",
         "PacketStreamFilter::write; message dispatch"},
        {"ipc-ihel-gui", Category::Accepted, ipcHello.takeBytes(),
         "ProtocolUtil::writef + IPC constants", "ipc-stream",
         "kIpcMsgHello; ProtocolUtil::writef; IpcFrameReader"},
        {"ipc-ihel-missing-type", Category::NeedMore, messageCode(kIpcMsgHello),
         "IPC message-code contract", "ipc-stream", "kIpcMsgHello; IpcFrameReader"},
        {"ipc-unknown-code", Category::Malformed, {'Z', 'Z', 'Z', 'Z'},
         "IPC message-code contract", "ipc-stream", "IpcFrameReader"},
        {"ipc-ilog-oversized-string", Category::Oversized, std::move(oversizedIpcLog),
         "IPC constants + ProtocolUtil string-length contract", "ipc-stream",
         "kIpcMsgLogLine; IpcFrameReader"},
    };
}

} // namespace inputleap::protocol_fixture

#ifndef INPUTLEAP_PROTOCOL_FIXTURE_EMITTER_NO_MAIN
int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "protocol-fixture-emitter: expected one output directory\n";
        return 2;
    }

    try {
        inputleap::Log log;
        auto fixtures = inputleap::protocol_fixture::initialCorpus();
        fixtures.insert(
            fixtures.begin(), inputleap::protocol_fixture::consecutiveStrings());
        inputleap::protocol_fixture::emit(
            std::filesystem::path(argv[1]), fixtures);
        return 0;
    }
    catch (...) {
        std::cerr << "protocol-fixture-emitter: emission failed\n";
        return 1;
    }
}
#endif
