#include "ipc/IpcConnectionStateStore.h"

#include <gtest/gtest.h>

#include <cstdint>

namespace inputleap {
namespace {

IpcConnectionStateMessage ownershipState(IpcConnectionState value,
                                         std::string detail = {})
{
    return {value, IpcConnectionRole::ServerPeer, IpcIdentityPresence::Known,
            "peer", std::move(detail)};
}

TEST(IpcConnectionStateOwnershipTests, LateStateAndDisconnectFromReplacedNodeAreIgnored)
{
    IpcConnectionStateStore store;
    constexpr std::uint64_t first = 101;
    constexpr std::uint64_t replacement = 202;

    EXPECT_TRUE(store.clientConnected(kIpcClientNode, first).empty());
    ASSERT_EQ(store.receive(kIpcClientNode, first,
                            ownershipState(IpcConnectionState::Connected, "first")).size(), 1u);

    EXPECT_TRUE(store.clientConnected(kIpcClientNode, replacement).empty());
    ASSERT_EQ(store.receive(kIpcClientNode, replacement,
                            ownershipState(IpcConnectionState::Connected, "replacement")).size(), 1u);

    EXPECT_TRUE(store.receive(kIpcClientNode, first,
                              ownershipState(IpcConnectionState::Disconnected, "late state")).empty());
    EXPECT_TRUE(store.clientDisconnected(kIpcClientNode, first).empty());

    const auto snapshot = store.snapshot();
    ASSERT_EQ(snapshot.size(), 1u);
    EXPECT_EQ(snapshot.begin()->second.state(), IpcConnectionState::Connected);
    EXPECT_EQ(snapshot.begin()->second.detail(), "replacement");
}

TEST(IpcConnectionStateOwnershipTests, CurrentNodeDisconnectMarksConnectedPeers)
{
    IpcConnectionStateStore store;
    constexpr std::uint64_t owner = 303;

    store.clientConnected(kIpcClientNode, owner);
    store.receive(kIpcClientNode, owner,
                  ownershipState(IpcConnectionState::Connected));

    const auto relays = store.clientDisconnected(kIpcClientNode, owner);
    ASSERT_EQ(relays.size(), 1u);
    EXPECT_EQ(relays[0].message.state(), IpcConnectionState::Disconnected);
}

} // namespace
} // namespace inputleap
