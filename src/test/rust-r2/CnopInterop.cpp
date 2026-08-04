#include "base/Log.h"
#include "inputleap/ProtocolUtil.h"
#include "inputleap/protocol_types.h"
#include "io/IStream.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace inputleap::rust_r2 {
namespace {

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

void writeBytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("unable to open output file");
    }
    output.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    if (!output) {
        throw std::runtime_error("unable to write output file");
    }
}

std::vector<std::uint8_t> readExactBytes(
    const std::filesystem::path& path,
    std::size_t expectedSize)
{
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        throw std::runtime_error("unable to open input file");
    }
    const auto end = input.tellg();
    if (end < 0 || static_cast<std::uintmax_t>(end) != expectedSize) {
        throw std::length_error("input file size does not match the expected message size");
    }
    std::vector<std::uint8_t> bytes(expectedSize);
    input.seekg(0);
    if (!bytes.empty()) {
        input.read(
            reinterpret_cast<char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    }
    if (!input) {
        throw std::runtime_error("unable to read input file");
    }
    return bytes;
}

void emit(const std::filesystem::path& path)
{
    CaptureStream stream;
    ProtocolUtil::writef(&stream, kMsgCNoop);
    writeBytes(path, stream.bytes());
    std::cout << "CNOP_CPP_EMIT_PASS bytes=" << stream.bytes().size() << " path=" << path << '\n';
}

void decode(const std::filesystem::path& path)
{
    const std::string_view expected{kMsgCNoop};
    const auto bytes = readExactBytes(path, expected.size());
    if (!std::equal(bytes.begin(), bytes.end(), expected.begin(), expected.end())) {
        throw std::runtime_error("payload bytes do not match kMsgCNoop");
    }
    std::cout << "CNOP_CPP_DECODE_PASS consumed=" << bytes.size() << " path=" << path << '\n';
}

} // namespace
} // namespace inputleap::rust_r2

int main(int argc, char** argv)
{
    if (argc != 3) {
        std::cerr << "usage: rust-r2-cnop-interop <emit|decode> <path>\n";
        return 2;
    }

    try {
        inputleap::Log log;
        const std::string_view mode{argv[1]};
        if (mode == "emit") {
            inputleap::rust_r2::emit(argv[2]);
        }
        else if (mode == "decode") {
            inputleap::rust_r2::decode(argv[2]);
        }
        else {
            std::cerr << "rust-r2-cnop-interop: unknown mode\n";
            return 2;
        }
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "rust-r2-cnop-interop: " << error.what() << '\n';
        return 1;
    }
}
