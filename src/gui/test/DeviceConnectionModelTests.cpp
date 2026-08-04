/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#include "DeviceConnectionModel.h"

#include <gtest/gtest.h>

#include <QSignalSpy>

TEST(DeviceConnectionModelTests, NewDeviceStartsOffline)
{
    DeviceConnectionModel model;
    const QUuid id = QUuid::createUuid();

    EXPECT_EQ(model.setState(id, DeviceConnectionModel::State::Offline),
              DeviceConnectionModel::TransitionResult::Unchanged);
    const auto snapshot = model.snapshot(id);
    ASSERT_TRUE(snapshot.has_value());
    EXPECT_EQ(snapshot->state, DeviceConnectionModel::State::Offline);
}

TEST(DeviceConnectionModelTests, AcceptsDefinedTransitions)
{
    DeviceConnectionModel model;
    const QUuid id = QUuid::createUuid();

    EXPECT_EQ(model.setState(id, DeviceConnectionModel::State::Available), DeviceConnectionModel::TransitionResult::Accepted);
    EXPECT_EQ(model.setState(id, DeviceConnectionModel::State::Connecting), DeviceConnectionModel::TransitionResult::Accepted);
    EXPECT_EQ(model.setState(id, DeviceConnectionModel::State::Connected), DeviceConnectionModel::TransitionResult::Accepted);
    EXPECT_EQ(model.setState(id, DeviceConnectionModel::State::Transferring), DeviceConnectionModel::TransitionResult::Accepted);
    EXPECT_EQ(model.setState(id, DeviceConnectionModel::State::Connected), DeviceConnectionModel::TransitionResult::Accepted);
    EXPECT_EQ(model.setState(id, DeviceConnectionModel::State::Offline), DeviceConnectionModel::TransitionResult::Accepted);
}

TEST(DeviceConnectionModelTests, RejectsInvalidTransitionWithoutChangingSnapshot)
{
    DeviceConnectionModel model;
    const QUuid id = QUuid::createUuid();

    ASSERT_EQ(model.setState(id, DeviceConnectionModel::State::Connected), DeviceConnectionModel::TransitionResult::Rejected);
    ASSERT_TRUE(model.snapshot(id).has_value());
    EXPECT_EQ(model.snapshot(id)->state, DeviceConnectionModel::State::Offline);
}

TEST(DeviceConnectionModelTests, RejectsNullUuid)
{
    DeviceConnectionModel model;
    EXPECT_EQ(model.setState({}, DeviceConnectionModel::State::Available), DeviceConnectionModel::TransitionResult::Rejected);
    EXPECT_FALSE(model.snapshot({}).has_value());
    EXPECT_FALSE(model.remove({}));
}

TEST(DeviceConnectionModelTests, SnapshotsAreIndependentValues)
{
    DeviceConnectionModel model;
    const QUuid id = QUuid::createUuid();
    model.setState(id, DeviceConnectionModel::State::Available, "Disponível", "discovery ok");
    auto oldSnapshot = model.snapshot(id);
    model.setState(id, DeviceConnectionModel::State::Connecting, "Conectando", "socket pending");

    ASSERT_TRUE(oldSnapshot.has_value());
    EXPECT_EQ(oldSnapshot->state, DeviceConnectionModel::State::Available);
    EXPECT_EQ(oldSnapshot->friendlyDetail, "Disponível");
}

TEST(DeviceConnectionModelTests, RecordsTimestampAndSeparateDetails)
{
    DeviceConnectionModel model;
    const QUuid id = QUuid::createUuid();
    const QDateTime before = QDateTime::currentDateTimeUtc();
    model.setState(id, DeviceConnectionModel::State::Available, "Computador encontrado", "mdns ttl=120");
    const auto snapshot = model.snapshot(id);

    ASSERT_TRUE(snapshot.has_value());
    EXPECT_GE(snapshot->lastChanged, before);
    EXPECT_TRUE(snapshot->lastChanged.isValid());
    EXPECT_EQ(snapshot->friendlyDetail, "Computador encontrado");
    EXPECT_EQ(snapshot->technicalDetail, "mdns ttl=120");
}

TEST(DeviceConnectionModelTests, EmitsSignalOnlyWhenDataChanges)
{
    DeviceConnectionModel model;
    const QUuid id = QUuid::createUuid();
    QSignalSpy spy(&model, &DeviceConnectionModel::deviceChanged);

    EXPECT_EQ(model.setState(id, DeviceConnectionModel::State::Offline), DeviceConnectionModel::TransitionResult::Unchanged);
    EXPECT_EQ(spy.count(), 0);
    EXPECT_EQ(model.setState(id, DeviceConnectionModel::State::Available, "Pronto"), DeviceConnectionModel::TransitionResult::Accepted);
    ASSERT_EQ(spy.count(), 1);
    EXPECT_EQ(spy.at(0).at(0).toUuid(), id);
    EXPECT_EQ(model.setState(id, DeviceConnectionModel::State::Available, "Pronto"), DeviceConnectionModel::TransitionResult::Unchanged);
    EXPECT_EQ(spy.count(), 1);
    EXPECT_EQ(model.setState(id, DeviceConnectionModel::State::Available, "Novo detalhe"), DeviceConnectionModel::TransitionResult::Accepted);
    EXPECT_EQ(spy.count(), 2);
}

TEST(DeviceConnectionModelTests, RemovesOnlyExpiredDevicesAndEmitsRemovalOnce)
{
    DeviceConnectionModel model;
    const QUuid expired = QUuid::createUuid();
    const QUuid recent = QUuid::createUuid();
    const QDateTime now = QDateTime::fromMSecsSinceEpoch(20000, Qt::UTC);
    model.setState(expired, DeviceConnectionModel::State::Available, {}, {}, now.addSecs(-10));
    model.setState(recent, DeviceConnectionModel::State::Available, {}, {}, now.addSecs(-2));
    QSignalSpy removed(&model, &DeviceConnectionModel::deviceRemoved);

    EXPECT_EQ(model.removeExpired(now.addSecs(-5)), 1);
    EXPECT_FALSE(model.snapshot(expired).has_value());
    EXPECT_TRUE(model.snapshot(recent).has_value());
    ASSERT_EQ(removed.count(), 1);
    EXPECT_EQ(removed.at(0).at(0).toUuid(), expired);
    EXPECT_EQ(model.removeExpired(now), 1);
    EXPECT_EQ(model.removeExpired(now), 0);
    EXPECT_EQ(removed.count(), 2);
}

TEST(DeviceConnectionModelTests, IdenticalObservationRenewsExpiryWithoutChangingData)
{
    DeviceConnectionModel model;
    const QUuid id = QUuid::createUuid();
    const QDateTime first = QDateTime::fromMSecsSinceEpoch(10000, Qt::UTC);
    const QDateTime renewed = first.addSecs(8);
    QSignalSpy changed(&model, &DeviceConnectionModel::deviceChanged);

    ASSERT_EQ(model.setState(id, DeviceConnectionModel::State::Available, "Pronto", {}, first),
              DeviceConnectionModel::TransitionResult::Accepted);
    const QDateTime lastChanged = model.snapshot(id)->lastChanged;
    ASSERT_EQ(model.setState(id, DeviceConnectionModel::State::Available, "Pronto", {}, renewed),
              DeviceConnectionModel::TransitionResult::Unchanged);

    ASSERT_TRUE(model.snapshot(id).has_value());
    EXPECT_EQ(model.snapshot(id)->lastChanged, lastChanged);
    EXPECT_EQ(model.snapshot(id)->lastObserved, renewed);
    EXPECT_EQ(changed.count(), 1);
    EXPECT_EQ(model.removeExpired(first.addSecs(5)), 0);
}

TEST(DeviceConnectionModelTests, ActiveConnectionDoesNotExpire)
{
    DeviceConnectionModel model;
    const QUuid id = QUuid::createUuid();
    const QDateTime old = QDateTime::fromMSecsSinceEpoch(1000, Qt::UTC);
    ASSERT_EQ(model.synchronizeState(id, DeviceConnectionModel::State::Connected, {}, {}, old),
              DeviceConnectionModel::TransitionResult::Accepted);
    EXPECT_EQ(model.removeExpired(old.addDays(1)), 0);
    EXPECT_TRUE(model.snapshot(id).has_value());
}

TEST(DeviceConnectionModelTests, AuthoritativeStateAcceptsCoreJumpButNormalRulesRemainStrict)
{
    DeviceConnectionModel model;
    const QUuid id = QUuid::createUuid();
    QSignalSpy changed(&model, &DeviceConnectionModel::deviceChanged);

    EXPECT_EQ(model.setState(id, DeviceConnectionModel::State::Connected),
              DeviceConnectionModel::TransitionResult::Rejected);
    EXPECT_EQ(model.synchronizeState(id, DeviceConnectionModel::State::Connected),
              DeviceConnectionModel::TransitionResult::Accepted);
    EXPECT_EQ(model.snapshot(id)->state, DeviceConnectionModel::State::Connected);
    EXPECT_EQ(changed.count(), 1);

    EXPECT_EQ(model.setState(id, DeviceConnectionModel::State::Incompatible),
              DeviceConnectionModel::TransitionResult::Rejected);
    EXPECT_EQ(model.snapshot(id)->state, DeviceConnectionModel::State::Connected);
}

TEST(DeviceConnectionModelTests, ErrorAndIncompatibleCanRecoverThroughAvailable)
{
    DeviceConnectionModel model;
    const QUuid errorId = QUuid::createUuid();
    const QUuid incompatibleId = QUuid::createUuid();

    EXPECT_EQ(model.setState(errorId, DeviceConnectionModel::State::Error), DeviceConnectionModel::TransitionResult::Accepted);
    EXPECT_EQ(model.setState(errorId, DeviceConnectionModel::State::Available), DeviceConnectionModel::TransitionResult::Accepted);
    EXPECT_EQ(model.setState(incompatibleId, DeviceConnectionModel::State::Incompatible), DeviceConnectionModel::TransitionResult::Accepted);
    EXPECT_EQ(model.setState(incompatibleId, DeviceConnectionModel::State::Available), DeviceConnectionModel::TransitionResult::Accepted);
}

TEST(DeviceConnectionModelTests, KeepsAuthoritativeDirectionIsolatedPerPeer)
{
    DeviceConnectionModel model; const QUuid local=QUuid::createUuid(),remote=QUuid::createUuid();
    model.synchronizeState(local,DeviceConnectionModel::State::Controlling,{},{},{},DeviceConnectionModel::Direction::LocalControlsRemote);
    model.synchronizeState(remote,DeviceConnectionModel::State::Connected,{},{},{},DeviceConnectionModel::Direction::RemoteControlsLocal);
    EXPECT_EQ(model.snapshot(local)->direction,DeviceConnectionModel::Direction::LocalControlsRemote);
    EXPECT_EQ(model.snapshot(remote)->direction,DeviceConnectionModel::Direction::RemoteControlsLocal);
}
