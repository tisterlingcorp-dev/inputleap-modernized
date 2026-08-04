#include "inputleap/ProtocolUtil.h"
#include "inputleap/protocol_types.h"
#include "io/IStream.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace inputleap {
namespace {

class CaptureStream final : public IStream
{
public:
    explicit CaptureStream(std::vector<std::uint8_t> input = {}) : input_(std::move(input)) {}

    void close() override {}
    std::uint32_t read(void* data, std::uint32_t size) override
    {
        const auto count = std::min<std::size_t>(size, input_.size() - input_offset_);
        if (count != 0) {
            std::memcpy(data, input_.data() + input_offset_, count);
            input_offset_ += count;
        }
        return static_cast<std::uint32_t>(count);
    }
    void write(const void* data, std::uint32_t size) override
    {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        written.assign(bytes, bytes + size);
    }
    void flush() override {}
    void shutdownInput() override {}
    void shutdownOutput() override {}
    const EventTarget* get_event_target() const override { return nullptr; }
    bool isReady() const override { return false; }
    std::uint32_t getSize() const override
    {
        return static_cast<std::uint32_t>(input_.size() - input_offset_);
    }

    std::vector<std::uint8_t> written;

private:
    std::vector<std::uint8_t> input_;
    std::size_t input_offset_ = 0;
};

TEST(ProtocolUtilTests, WritefSerializesConsecutiveStringsWithoutConsumingExtraArgument)
{
    CaptureStream stream;
    std::string first = "alpha";
    std::string second = "beta";

    ProtocolUtil::writef(&stream, "TEST%s%s", &first, &second);

    const std::vector<std::uint8_t> expected{
        'T', 'E', 'S', 'T',
        0, 0, 0, 5, 'a', 'l', 'p', 'h', 'a',
        0, 0, 0, 4, 'b', 'e', 't', 'a'};
    EXPECT_EQ(stream.written, expected);
}

TEST(ProtocolUtilTests, WritefAcceptsStringAtProtocolLimit)
{
    CaptureStream stream;
    std::string value(PROTOCOL_MAX_STRING_LENGTH, 'x');

    EXPECT_NO_THROW(ProtocolUtil::writef(&stream, "%s", &value));
    EXPECT_EQ(stream.written.size(), value.size() + 4u);
}

TEST(ProtocolUtilTests, WritefRejectsStringAboveProtocolLimitBeforeWriting)
{
    CaptureStream stream;
    std::string value(static_cast<std::size_t>(PROTOCOL_MAX_STRING_LENGTH) + 1u, 'x');

    EXPECT_THROW(ProtocolUtil::writef(&stream, "%s", &value), std::length_error);
    EXPECT_TRUE(stream.written.empty());
}

TEST(ProtocolUtilTests, WritefRejectsListAboveProtocolLimitBeforeWriting)
{
    CaptureStream stream;
    std::vector<std::uint8_t> value(
        static_cast<std::size_t>(PROTOCOL_MAX_LIST_LENGTH) + 1u, 1);

    EXPECT_THROW(ProtocolUtil::writef(&stream, "%1I", &value), std::length_error);
    EXPECT_TRUE(stream.written.empty());
}

TEST(ProtocolUtilTests, WritefRejectsTotalMessageAboveProtocolLimitBeforeWriting)
{
    CaptureStream stream;
    std::string value(PROTOCOL_MAX_STRING_LENGTH, 'x');

    EXPECT_THROW(
        ProtocolUtil::writef(&stream, "%s%s%s%s", &value, &value, &value, &value),
        std::length_error);
    EXPECT_TRUE(stream.written.empty());
}

TEST(ProtocolUtilTests, ReadfUsesTypedUint32ListOverload)
{
    using ListReader = bool (*)(IStream*, const char*, std::vector<std::uint32_t>*);
    const ListReader reader = &ProtocolUtil::readf;
    CaptureStream stream({0, 0, 0, 2,
                          0x01, 0x02, 0x03, 0x04,
                          0xa0, 0xb0, 0xc0, 0xd0});
    std::vector<std::uint32_t> values;

    EXPECT_TRUE(reader(&stream, "%4I", &values));
    EXPECT_EQ(values, (std::vector<std::uint32_t>{0x01020304u, 0xa0b0c0d0u}));
}

TEST(ProtocolUtilTests, TypedUint32ListReadRejectsTruncationWithoutPartialMutation)
{
    using ListReader = bool (*)(IStream*, const char*, std::vector<std::uint32_t>*);
    const ListReader reader = &ProtocolUtil::readf;
    CaptureStream stream({0, 0, 0, 2, 0x01, 0x02, 0x03, 0x04});
    std::vector<std::uint32_t> values{0xfeedfaceu};

    EXPECT_FALSE(reader(&stream, "%4I", &values));
    EXPECT_EQ(values, (std::vector<std::uint32_t>{0xfeedfaceu}));
}

} // namespace
} // namespace inputleap
