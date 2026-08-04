#include "server/ServerConnectionEventPolicy.h"

#include <gtest/gtest.h>

namespace inputleap {
namespace {

TEST(ServerConnectionEventPolicyTests, spontaneousRemovalEmitsOneNamedDisconnect)
{
    const auto first = ServerConnectionEventPolicy::activeClientRemoved("alpha", true, false, 1, 0);
    const auto duplicate = ServerConnectionEventPolicy::activeClientRemoved("alpha", false, true, 1, 0);

    ASSERT_TRUE(first.screenDisconnected.has_value());
    EXPECT_EQ(*first.screenDisconnected, "alpha");
    EXPECT_FALSE(first.serverDisconnected);
    EXPECT_FALSE(duplicate.screenDisconnected.has_value());
}

TEST(ServerConnectionEventPolicyTests, serverInitiatedRemovalIsNotDuplicatedByLaterClose)
{
    const auto initiated = ServerConnectionEventPolicy::activeClientRemoved("alpha", true, false, 1, 0);
    const auto closed = ServerConnectionEventPolicy::activeClientRemoved("alpha", false, true, 1, 1);

    ASSERT_TRUE(initiated.screenDisconnected.has_value());
    EXPECT_EQ(*initiated.screenDisconnected, "alpha");
    EXPECT_FALSE(closed.screenDisconnected.has_value());
}

TEST(ServerConnectionEventPolicyTests, removingOneOfTwoPeersPreservesOtherWithoutAggregateDisconnect)
{
    const auto decision = ServerConnectionEventPolicy::activeClientRemoved("alpha", true, true, 2, 0);

    ASSERT_TRUE(decision.screenDisconnected.has_value());
    EXPECT_EQ(*decision.screenDisconnected, "alpha");
    EXPECT_FALSE(decision.serverDisconnected);
}

} // namespace
} // namespace inputleap
