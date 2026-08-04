#include "test/helpers/ProtocolFixtureEmitter.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace {

class ScopedFixtureDirectory final
{
public:
    ScopedFixtureDirectory()
        : path_(std::filesystem::temp_directory_path() / "inputleap-fixture-emitter-red")
    {
        std::filesystem::remove_all(path_);
        std::filesystem::create_directories(path_);
    }

    ~ScopedFixtureDirectory() { std::filesystem::remove_all(path_); }

    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

} // namespace

namespace inputleap {
namespace {

TEST(ProtocolFixtureEmitterTests, ExistingOutputDirectoryIsRejectedBeforePublication)
{
    ScopedFixtureDirectory directory;

    EXPECT_THROW(
        protocol_fixture::emit(directory.path(), protocol_fixture::initialCorpus()),
        std::runtime_error);
    EXPECT_EQ(std::filesystem::directory_iterator(directory.path()),
              std::filesystem::directory_iterator());
}
TEST(ProtocolFixtureEmitterTests, ConsecutiveStringsFixtureIsDeterministicAndClassified)
{
    const auto fixture = protocol_fixture::consecutiveStrings();

    EXPECT_EQ(fixture.name, "writef-consecutive-strings");
    EXPECT_EQ(fixture.category, protocol_fixture::Category::Accepted);
    const std::vector<std::uint8_t> expected{
        'T', 'E', 'S', 'T',
        0, 0, 0, 5, 'a', 'l', 'p', 'h', 'a',
        0, 0, 0, 4, 'b', 'e', 't', 'a'};
    EXPECT_EQ(fixture.bytes, expected);
}

TEST(ProtocolFixtureEmitterTests, InitialCorpusMatchesFrozenContractMatrix)
{
    const auto fixtures = protocol_fixture::initialCorpus();
    ASSERT_EQ(fixtures.size(), 9u);

    struct Expected {
        const char* name;
        protocol_fixture::Category category;
        std::vector<std::uint8_t> bytes;
    };
    const std::vector<Expected> expected{
        {"remote-hello-1-6", protocol_fixture::Category::Accepted,
         {0, 0, 0, 11, 'B', 'a', 'r', 'r', 'i', 'e', 'r', 0, 1, 0, 6}},
        {"remote-hello-back-1-7", protocol_fixture::Category::UnsupportedVersion,
         {0, 0, 0, 25, 'B', 'a', 'r', 'r', 'i', 'e', 'r', 0, 1, 0, 7,
          0, 0, 0, 10, 'k', 'a', 't', '-', 'c', 'l', 'i', 'e', 'n', 't'}},
        {"remote-truncated-prefix", protocol_fixture::Category::NeedMore, {0, 0, 0}},
        {"remote-oversized-length", protocol_fixture::Category::Oversized, {0, 64, 0, 1}},
        {"remote-unknown-code", protocol_fixture::Category::Malformed,
         {0, 0, 0, 4, 'Z', 'Z', 'Z', 'Z'}},
        {"ipc-ihel-gui", protocol_fixture::Category::Accepted, {'I', 'H', 'E', 'L', 1}},
        {"ipc-ihel-missing-type", protocol_fixture::Category::NeedMore, {'I', 'H', 'E', 'L'}},
        {"ipc-unknown-code", protocol_fixture::Category::Malformed, {'Z', 'Z', 'Z', 'Z'}},
        {"ipc-ilog-oversized-string", protocol_fixture::Category::Oversized,
         {'I', 'L', 'O', 'G', 0, 16, 0, 1}},
    };

    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(fixtures[i].name, expected[i].name) << i;
        EXPECT_EQ(fixtures[i].category, expected[i].category) << i;
        EXPECT_EQ(fixtures[i].bytes, expected[i].bytes) << i;
    }
}

} // namespace
} // namespace inputleap
