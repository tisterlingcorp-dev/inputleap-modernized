#include "CoreConnectionStateController.h"
#include <QSettings>
#include <QTemporaryDir>
#include <gtest/gtest.h>

namespace { QString file(QTemporaryDir& dir) { return dir.filePath("registry.ini"); } }

TEST(CoreConnectionStateControllerTests, KnownIdentityCreatesReusesAndUpdatesModel)
{
    QTemporaryDir dir; QSettings settings(file(dir), QSettings::IniFormat); DeviceRegistry registry(settings); DeviceConnectionModel model;
    CoreConnectionStateController controller(registry, model);
    const auto connected = controller.apply(IpcConnectionState::Connected, "peer-A", "ok");
    ASSERT_EQ(connected.status, CoreConnectionStateController::Status::Applied); ASSERT_FALSE(connected.uuid.isNull());
    EXPECT_EQ(model.snapshot(connected.uuid)->state, DeviceConnectionModel::State::Connected);
    const auto available = controller.apply(IpcConnectionState::Available, "peer-A", "seen");
    EXPECT_EQ(available.uuid, connected.uuid); EXPECT_EQ(model.snapshot(connected.uuid)->state, DeviceConnectionModel::State::Available);
}

TEST(CoreConnectionStateControllerTests, LegacyIdentityNeverCreatesUuid)
{
    QTemporaryDir dir; QSettings settings(file(dir), QSettings::IniFormat); DeviceRegistry registry(settings); DeviceConnectionModel model;
    CoreConnectionStateController controller(registry, model); const auto result = controller.applyLegacy(IpcConnectionState::Connected, "legacy");
    EXPECT_EQ(result.status, CoreConnectionStateController::Status::LegacyUnavailable); EXPECT_TRUE(result.uuid.isNull());
    EXPECT_TRUE(registry.devices().isEmpty()); EXPECT_TRUE(model.snapshots().isEmpty());
}

TEST(CoreConnectionStateControllerTests, KeepsTwoPeersAndDisconnectedUsesDiscovery)
{
    QTemporaryDir dir; QSettings settings(file(dir), QSettings::IniFormat); DeviceRegistry registry(settings); DeviceConnectionModel model;
    CoreConnectionStateController controller(registry, model); const auto a = controller.apply(IpcConnectionState::Connected, "peer-A", {});
    const auto b = controller.apply(IpcConnectionState::Connected, "peer-B", {}); EXPECT_NE(a.uuid, b.uuid); EXPECT_EQ(model.snapshots().size(), 2);
    controller.setDiscovered("peer-A", true); controller.apply(IpcConnectionState::Disconnected, "peer-A", {});
    controller.apply(IpcConnectionState::Disconnected, "peer-B", {});
    EXPECT_EQ(model.snapshot(a.uuid)->state, DeviceConnectionModel::State::Available);
    EXPECT_EQ(model.snapshot(b.uuid)->state, DeviceConnectionModel::State::Offline);
}

TEST(CoreConnectionStateControllerTests, RegistryFailureDoesNotCreateEphemeralModelIdentity)
{
    QTemporaryDir dir; QSettings settings(file(dir), QSettings::IniFormat); DeviceRegistry registry(settings, [](QSettings&) { return false; });
    DeviceConnectionModel model; CoreConnectionStateController controller(registry, model);
    EXPECT_EQ(controller.apply(IpcConnectionState::Connected, "peer-A", {}).status, CoreConnectionStateController::Status::RegistryError);
    EXPECT_TRUE(model.snapshots().isEmpty());
}

TEST(CoreConnectionStateControllerTests, ConnectionLookingLogLineCannotChangeState)
{
    EXPECT_FALSE(CoreConnectionStateController::logLineCanChangeState("connected to server"));
    EXPECT_FALSE(CoreConnectionStateController::logLineCanChangeState("started server"));
}

TEST(CoreConnectionStateControllerTests, MapsCoreRoleToHonestControlDirection)
{
    QTemporaryDir dir; QSettings settings(file(dir),QSettings::IniFormat); DeviceRegistry registry(settings); DeviceConnectionModel model; CoreConnectionStateController controller(registry,model);
    const auto server=controller.apply(IpcConnectionState::Connected,IpcConnectionRole::ServerPeer,"client-a",{}); ASSERT_TRUE(model.snapshot(server.uuid)); EXPECT_EQ(model.snapshot(server.uuid)->state,DeviceConnectionModel::State::Connected); EXPECT_EQ(model.snapshot(server.uuid)->direction,DeviceConnectionModel::Direction::LocalControlsRemote);
    const auto client=controller.apply(IpcConnectionState::Connected,IpcConnectionRole::ClientPeer,"server-a",{}); ASSERT_TRUE(model.snapshot(client.uuid)); EXPECT_EQ(model.snapshot(client.uuid)->state,DeviceConnectionModel::State::Connected); EXPECT_EQ(model.snapshot(client.uuid)->direction,DeviceConnectionModel::Direction::RemoteControlsLocal);
}