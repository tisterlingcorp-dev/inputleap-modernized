#include "server/TopologyConfigCandidate.h"

#include <gtest/gtest.h>

#include <sstream>

namespace inputleap {
namespace {

TEST(TopologyConfigCandidateTests, ParsesCandidateWithoutMutatingActiveConfig)
{
    Config active;
    ASSERT_TRUE(active.addScreen("primary"));

    Config serializedCandidate;
    ASSERT_TRUE(serializedCandidate.addScreen("primary"));
    ASSERT_TRUE(serializedCandidate.addScreen("peer"));
    std::ostringstream payload;
    payload << serializedCandidate;

    const auto result = TopologyConfigCandidate::parse(payload.str(), "primary");

    ASSERT_TRUE(result.config.has_value()) << result.error;
    EXPECT_TRUE(result.config->isScreen("primary"));
    EXPECT_TRUE(result.config->isScreen("peer"));
    EXPECT_TRUE(active.isScreen("primary"));
    EXPECT_FALSE(active.isScreen("peer"));
}

TEST(TopologyConfigCandidateTests, RejectsMalformedPayloadWithoutMutatingActiveConfig)
{
    Config active;
    ASSERT_TRUE(active.addScreen("primary"));

    const auto result = TopologyConfigCandidate::parse(
        "not a topology section\n", "primary");

    EXPECT_FALSE(result.config.has_value());
    EXPECT_FALSE(result.error.empty());
    EXPECT_TRUE(active.isScreen("primary"));
}

TEST(TopologyConfigCandidateTests, RejectsCandidateWithoutPrimaryScreen)
{
    Config serializedCandidate;
    ASSERT_TRUE(serializedCandidate.addScreen("peer"));
    std::ostringstream payload;
    payload << serializedCandidate;

    const auto result = TopologyConfigCandidate::parse(payload.str(), "primary");

    EXPECT_FALSE(result.config.has_value());
    EXPECT_EQ(result.error, "primary screen is missing from topology");
}

TEST(TopologyConfigCandidateTests, AcceptsTopologyPayloadProducedByTauriEditor)
{
    const std::string payload =
        "section: screens\n"
        "\tprimary:\n"
        "\tpeer:\n"
        "end\n"
        "\n"
        "section: links\n"
        "\tprimary:\n"
        "\t\tright = peer\n"
        "\tpeer:\n"
        "\t\tleft = primary\n"
        "end\n";

    const auto result = TopologyConfigCandidate::parse(payload, "primary");

    ASSERT_TRUE(result.config.has_value()) << result.error;
    EXPECT_TRUE(result.config->isScreen("primary"));
    EXPECT_TRUE(result.config->isScreen("peer"));
}

} // namespace
} // namespace inputleap
