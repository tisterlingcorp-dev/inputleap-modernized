#include "DashboardPeerStatePolicy.h"

#include <gtest/gtest.h>

namespace {
DeviceConnectionModel::Snapshot peer(const QUuid& uuid, DeviceConnectionModel::State state)
{
    DeviceConnectionModel::Snapshot result;
    result.uuid = uuid;
    result.state = state;
    return result;
}
}

TEST(DashboardPeerStatePolicyTests, OfflineEventDoesNotReplaceOrDropAnotherConnectedPeer)
{
    const auto a = QUuid::createUuid();
    const auto b = QUuid::createUuid();
    const auto result = DashboardPeerStatePolicy::evaluate(
        {peer(a, DeviceConnectionModel::State::Connected), peer(b, DeviceConnectionModel::State::Offline)},
        a, b);

    EXPECT_EQ(result.aggregate, DeviceConnectionModel::State::Connected);
    EXPECT_EQ(result.selected, a);
}

TEST(DashboardPeerStatePolicyTests, SelectsAnotherConnectedPeerWhenSelectedDisconnects)
{
    const auto a = QUuid::createUuid();
    const auto b = QUuid::createUuid();
    const auto result = DashboardPeerStatePolicy::evaluate(
        {peer(a, DeviceConnectionModel::State::Offline), peer(b, DeviceConnectionModel::State::Connected)},
        a, a);

    EXPECT_EQ(result.aggregate, DeviceConnectionModel::State::Connected);
    EXPECT_EQ(result.selected, b);
}

TEST(DashboardPeerStatePolicyTests, TransferringPeerHasPriority)
{
    const auto connected = QUuid::createUuid();
    const auto transferring = QUuid::createUuid();
    const auto result = DashboardPeerStatePolicy::evaluate(
        {peer(connected, DeviceConnectionModel::State::Connected),
         peer(transferring, DeviceConnectionModel::State::Transferring)},
        connected, transferring);

    EXPECT_EQ(result.aggregate, DeviceConnectionModel::State::Transferring);
    EXPECT_EQ(result.selected, transferring);
}

TEST(DashboardPeerStatePolicyTests, LastDisconnectProducesOfflineAndNoOfflineSelection)
{
    const auto a = QUuid::createUuid();
    const auto result = DashboardPeerStatePolicy::evaluate(
        {peer(a, DeviceConnectionModel::State::Offline)}, a, a);

    EXPECT_EQ(result.aggregate, DeviceConnectionModel::State::Offline);
    EXPECT_TRUE(result.selected.isNull());
}

TEST(DashboardPeerStatePolicyTests, AvailableEventMayBeSelectedWhenThereIsNoActivePeer)
{
    const auto a = QUuid::createUuid();
    const auto b = QUuid::createUuid();
    const auto result = DashboardPeerStatePolicy::evaluate(
        {peer(a, DeviceConnectionModel::State::Offline), peer(b, DeviceConnectionModel::State::Available)},
        a, b);

    EXPECT_EQ(result.aggregate, DeviceConnectionModel::State::Available);
    EXPECT_EQ(result.selected, b);
}

TEST(DashboardPeerStatePolicyTests, RemovalOfSelectedPeerChoosesRemainingActivePeer)
{
    const auto removed = QUuid::createUuid();
    const auto active = QUuid::createUuid();
    const auto result = DashboardPeerStatePolicy::evaluate(
        {peer(active, DeviceConnectionModel::State::Connected)}, removed, {});

    EXPECT_EQ(result.aggregate, DeviceConnectionModel::State::Connected);
    EXPECT_EQ(result.selected, active);
}

TEST(DashboardPeerStatePolicyTests, LegacyConnectedDrivesAggregateWithoutCreatingASelection)
{
    const auto result = DashboardPeerStatePolicy::evaluate(
        {}, {}, {}, DeviceConnectionModel::State::Connected);

    EXPECT_EQ(result.aggregate, DeviceConnectionModel::State::Connected);
    EXPECT_TRUE(result.selected.isNull());
}

TEST(DashboardPeerStatePolicyTests, LegacyDisconnectDoesNotDropKnownConnectedPeer)
{
    const QUuid known = QUuid::createUuid();
    const auto result = DashboardPeerStatePolicy::evaluate(
        {peer(known, DeviceConnectionModel::State::Connected)}, known, {},
        DeviceConnectionModel::State::Offline);

    EXPECT_EQ(result.aggregate, DeviceConnectionModel::State::Connected);
    EXPECT_EQ(result.selected, known);
}
