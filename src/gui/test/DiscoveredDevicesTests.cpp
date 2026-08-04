#include "DiscoveredDevicesModel.h"
#include "DeviceDiscoveryPanel.h"
#include "DeviceRegistry.h"

#include <gtest/gtest.h>
#include <QSettings>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QLabel>
#include <QPushButton>
#include "DeviceDisplayNameResolver.h"

namespace {
DiscoveredDeviceAdvertisement ad(const QUuid& id, const QString& name, qint64 seen = 100,
                                 ZeroconfCapability capability = ZeroconfCapability::Keyboard)
{
    DiscoveredDeviceAdvertisement value;
    value.uuid = id; value.metadata.uuid = id; value.metadata.technicalName = name;
    value.metadata.friendlyName = name + " amigável"; value.metadata.inputLeapVersion = "3.0";
    value.metadata.controlPort = 24800; value.metadata.capabilities.insert(capability);
    value.addresses.insert("192.168.1.20"); value.lastSeenMs = seen;
    return value;
}
struct Fixture {
    QTemporaryDir dir;
    QSettings settings{dir.filePath("registry.ini"), QSettings::IniFormat};
    DeviceRegistry registry{settings};
    DeviceConnectionModel connections;
    QUuid local = QUuid::createUuid();
    DiscoveredDevicesModel model{registry, connections, local};
};
}

TEST(DiscoveredDevicesModel, HandlesCountsUuidIdentitySelfAndDuplicateWithoutChurn)
{
    Fixture f; QSignalSpy changed(&f.model, &DiscoveredDevicesModel::devicesChanged);
    f.model.upsert(ad(f.local, "eu")); EXPECT_EQ(f.model.count(), 0);
    const QUuid a = QUuid::createUuid(), b = QUuid::createUuid();
    f.model.upsert(ad(a, "igual")); f.model.upsert(ad(b, "igual"));
    EXPECT_EQ(f.model.count(), 2); EXPECT_EQ(changed.count(), 2);
    const QString generation = f.settings.value("deviceRegistry/activeGeneration").toString();
    f.model.upsert(ad(a, "igual")); EXPECT_EQ(changed.count(), 2);
    EXPECT_EQ(f.settings.value("deviceRegistry/activeGeneration").toString(), generation);
    EXPECT_EQ(f.model.visibleDevices().size(), 2);
}

TEST(DiscoveredDevicesModel, MarksPeersBehindLocallyCheckedReleaseWithoutRemoteAction)
{
    Fixture f;
    f.model.setUpdateTargetVersion(QStringLiteral("3.1.0"));
    const QUuid behind = QUuid::createUuid();
    auto older = ad(behind, "older");
    older.metadata.inputLeapVersion = QStringLiteral("3.0.0");
    ASSERT_TRUE(f.model.upsert(older));
    ASSERT_TRUE(f.model.find(behind));
    EXPECT_TRUE(f.model.find(behind)->updateAvailable);
    f.model.setUpdateTargetVersion(QStringLiteral("3.0.0"));
    EXPECT_FALSE(f.model.find(behind)->updateAvailable);
}

TEST(DiscoveredDevicesModel, LimitsVisibleToFourAndOrdersByStateThenSeenNameUuid)
{
    Fixture f; QList<QUuid> ids;
    for (int i=0;i<5;++i) { ids << QUuid::createUuid(); f.model.upsert(ad(ids.last(), QString("pc%1").arg(i), 100+i)); }
    f.connections.synchronizeState(ids[0], DeviceConnectionModel::State::Connected);
    f.connections.synchronizeState(ids[1], DeviceConnectionModel::State::Connecting);
    EXPECT_EQ(f.model.count(), 5); EXPECT_EQ(f.model.visibleDevices().size(), 4); EXPECT_EQ(f.model.hiddenCount(), 1);
    EXPECT_EQ(f.model.visibleDevices().at(0).uuid, ids[0]);
    EXPECT_EQ(f.model.visibleDevices().at(1).uuid, ids[1]);
    EXPECT_EQ(f.model.visibleDevices().at(2).uuid, ids[4]);
}

TEST(DiscoveredDevicesModel, LostAvailableRemovedButConnectedRetainedOfflineObservation)
{
    Fixture f; const QUuid available=QUuid::createUuid(), connected=QUuid::createUuid();
    f.model.upsert(ad(available,"a")); f.model.upsert(ad(connected,"c"));
    f.connections.synchronizeState(connected, DeviceConnectionModel::State::Connected);
    f.model.remove(available); EXPECT_FALSE(f.model.find(available).has_value());
    f.model.remove(connected); ASSERT_TRUE(f.model.find(connected).has_value());
    EXPECT_FALSE(f.model.find(connected)->discoveryAvailable);
    EXPECT_EQ(f.model.find(connected)->state, DeviceConnectionModel::State::Connected);
    f.connections.synchronizeState(connected, DeviceConnectionModel::State::Offline);
    EXPECT_FALSE(f.model.find(connected).has_value());
}

TEST(DiscoveredDevicesModel, RegistryMergePreservesAliasTrustAndFailureIsAtomic)
{
    Fixture f; const QUuid id=QUuid::createUuid(); DeviceInfo old(id);
    old.setTechnicalName("old"); old.setLocalAlias("Meu notebook"); old.setTrustState(DeviceInfo::TrustState::Trusted);
    ASSERT_EQ(f.registry.add(old), DeviceRegistry::AddResult::Added); ASSERT_EQ(f.registry.save(), DeviceRegistry::SaveResult::Success);
    auto value=ad(id,"new"); value.metadata.osFamily=ZeroconfOsFamily::Linux; value.metadata.capabilities.insert(ZeroconfCapability::FileTransfer);
    ASSERT_TRUE(f.model.upsert(value)); auto saved=f.registry.find(id); ASSERT_TRUE(saved);
    EXPECT_EQ(saved->localAlias(), "Meu notebook"); EXPECT_EQ(saved->trustState(), DeviceInfo::TrustState::Trusted);
    EXPECT_EQ(saved->technicalName(), "new"); EXPECT_EQ(f.model.find(id)->displayName, "Meu notebook");

    QTemporaryDir dir; QSettings settings(dir.filePath("bad.ini"), QSettings::IniFormat);
    DeviceRegistry broken(settings, [](QSettings&){ return false; }); DeviceConnectionModel states;
    DiscoveredDevicesModel failed(broken, states, {}); const QUuid failedId=QUuid::createUuid();
    EXPECT_FALSE(failed.upsert(ad(failedId,"nope"))); EXPECT_EQ(failed.count(),0); EXPECT_FALSE(broken.find(failedId));
}

TEST(DeviceDiscoveryPanel, HiddenAtZeroShowsRealCardsAndMoreCount)
{
    Fixture f; DeviceDiscoveryPanel panel(&f.model); EXPECT_FALSE(panel.isVisible());
    for(int i=0;i<5;++i) f.model.upsert(ad(QUuid::createUuid(), QString("pc%1").arg(i)));
    panel.show(); EXPECT_TRUE(panel.isVisible());
    EXPECT_EQ(panel.findChildren<DeviceCard*>(QString(), Qt::FindDirectChildrenOnly).size(), 4);
    auto* more=panel.findChild<QPushButton*>("discoveryMoreButton"); ASSERT_NE(more,nullptr); EXPECT_EQ(more->text(), "Ver mais (1)");
    more->click();
    EXPECT_EQ(panel.findChildren<DeviceCard*>(QString(), Qt::FindDirectChildrenOnly).size(), 5);
    EXPECT_EQ(more->text(), "Mostrar menos");
    more->click();
    EXPECT_EQ(panel.findChildren<DeviceCard*>(QString(), Qt::FindDirectChildrenOnly).size(), 4);
    EXPECT_EQ(panel.accessibleName(), "Computadores encontrados");
}

TEST(DeviceDiscoveryPanel, ShowsExactlyOneTwoAndFourRealCards)
{
    for (const int count : {1, 2, 4}) {
        Fixture f; DeviceDiscoveryPanel panel(&f.model);
        for (int i = 0; i < count; ++i)
            f.model.upsert(ad(QUuid::createUuid(), QString("pc%1").arg(i)));
        panel.show();
        EXPECT_EQ(panel.findChildren<DeviceCard*>(QString(), Qt::FindDirectChildrenOnly).size(), count);
        EXPECT_FALSE(panel.findChild<QPushButton*>("discoveryMoreButton")->isVisible());
    }
}

TEST(DeviceDiscoveryPanel, CollapsesAgainAfterCountDropsToFour)
{
    Fixture f; DeviceDiscoveryPanel panel(&f.model); QList<QUuid> ids;
    for (int i = 0; i < 5; ++i) {
        ids.append(QUuid::createUuid());
        f.model.upsert(ad(ids.last(), QString("pc%1").arg(i)));
    }
    panel.show();
    auto* more = panel.findChild<QPushButton*>("discoveryMoreButton");
    ASSERT_NE(more, nullptr); more->click();
    EXPECT_EQ(panel.findChildren<DeviceCard*>(QString(), Qt::FindDirectChildrenOnly).size(), 5);

    f.model.remove(ids.last());
    EXPECT_EQ(panel.findChildren<DeviceCard*>(QString(), Qt::FindDirectChildrenOnly).size(), 4);
    EXPECT_FALSE(more->isVisible());

    f.model.upsert(ad(QUuid::createUuid(), "novo"));
    EXPECT_EQ(panel.findChildren<DeviceCard*>(QString(), Qt::FindDirectChildrenOnly).size(), 4);
    EXPECT_EQ(more->text(), "Ver mais (1)");
}

TEST(DeviceCard, PortugueseAccessibleActionsReflectStateAndCapabilities)
{
    DiscoveredDeviceView value; value.uuid=QUuid::createUuid(); value.displayName="Sala"; value.operatingSystem="Linux";
    value.compatible=true; value.discoveryAvailable=true; value.state=DeviceConnectionModel::State::Available;
    DeviceCard card; card.setDevice(value);
    EXPECT_TRUE(card.findChild<QLabel*>("deviceStatusLabel")->text().contains("Disponível"));
    EXPECT_TRUE(card.findChild<QPushButton*>("deviceConnectButton")->isVisibleTo(&card));
    EXPECT_EQ(card.findChild<QPushButton*>("devicePairButton")->text(), "Parear");
    EXPECT_FALSE(card.findChild<QPushButton*>("deviceSendFileButton")->isVisibleTo(&card));
    value.state=DeviceConnectionModel::State::Connected; value.capabilities.insert(ZeroconfCapability::FileTransfer); value.addresses.insert("192.0.2.2"); value.transferPort=24801; card.setDevice(value);
    EXPECT_TRUE(card.findChild<QPushButton*>("deviceSendFileButton")->isVisibleTo(&card));
    value.compatible=false; value.state=DeviceConnectionModel::State::Incompatible; card.setDevice(value);
    EXPECT_FALSE(card.findChild<QPushButton*>("deviceConnectButton")->isEnabled());
    EXPECT_FALSE(card.accessibleName().isEmpty());
}

TEST(DeviceCard, ShowsLocalUpdateNoticeWithoutAddingRemoteUpdateAction)
{
    DeviceCard card;
    DiscoveredDeviceView value;
    value.uuid = QUuid::createUuid();
    value.displayName = QStringLiteral("Sala");
    value.updateAvailable = true;
    card.setDevice(value);
    auto* notice = card.findChild<QLabel*>("deviceUpdateLabel");
    ASSERT_NE(notice, nullptr);
    EXPECT_TRUE(notice->isVisibleTo(&card));
    EXPECT_EQ(notice->text(), QStringLiteral("Atualização disponível neste computador"));
    EXPECT_TRUE(card.findChildren<QPushButton*>("deviceUpdateButton").isEmpty());
}

TEST(DiscoveredDevicesModel, AliasChangeUpdatesDisplayExactlyOnceWithoutChurn)
{
    Fixture f; const QUuid id=QUuid::createUuid(); ASSERT_TRUE(f.model.upsert(ad(id,"peer")));
    QSignalSpy changed(&f.model,&DiscoveredDevicesModel::devicesChanged);
    EXPECT_EQ(f.model.setLocalAlias(id,"  Sala  "),DeviceRegistry::AliasResult::Changed);
    EXPECT_EQ(changed.count(),1); EXPECT_EQ(f.model.find(id)->displayName,"Sala");
    EXPECT_EQ(f.model.setLocalAlias(id,"Sala"),DeviceRegistry::AliasResult::Unchanged); EXPECT_EQ(changed.count(),1);
}

TEST(DeviceCard, RenameActionEmitsStableDeviceAndIsAccessible)
{
    DiscoveredDeviceView value; value.uuid=QUuid::createUuid(); value.displayName="Sala"; value.technicalName="peer";
    DeviceCard card; card.setDevice(value); QSignalSpy spy(&card,&DeviceCard::renameRequested);
    auto* rename=card.findChild<QPushButton*>("deviceRenameButton"); ASSERT_NE(rename,nullptr);
    EXPECT_EQ(rename->text(),"Renomear"); EXPECT_FALSE(rename->accessibleName().isEmpty()); rename->click();
    ASSERT_EQ(spy.count(),1); EXPECT_EQ(qvariant_cast<DiscoveredDeviceView>(spy.at(0).at(0)).uuid,value.uuid);
}

TEST(DeviceDisplayNameResolver, UsesAliasForKnownUuidAndTechnicalFallback)
{
    Fixture f; const QUuid id=QUuid::createUuid(); DeviceInfo device(id); device.setTechnicalName("peer-tech");
    ASSERT_EQ(f.registry.add(device),DeviceRegistry::AddResult::Added); ASSERT_EQ(f.registry.save(),DeviceRegistry::SaveResult::Success);
    ASSERT_EQ(f.registry.setLocalAlias(id,"Sala"),DeviceRegistry::AliasResult::Changed); DeviceDisplayNameResolver resolver(f.registry);
    EXPECT_EQ(resolver.resolve(id,"fallback"),"Sala"); EXPECT_EQ(resolver.resolve(QUuid::createUuid(),"endpoint.local"),"endpoint.local");
    EXPECT_EQ(resolver.resolve({},"192.0.2.9"),"192.0.2.9");
}

TEST(DeviceCard, ShowsAuthoritativeStatesWithTextIconToneAndAccessibility)
{
    const QList<QPair<DeviceConnectionModel::State,QString>> states={{DeviceConnectionModel::State::Offline,"Offline"},{DeviceConnectionModel::State::Available,"Disponível"},{DeviceConnectionModel::State::Connecting,"Conectando…"},{DeviceConnectionModel::State::Connected,"Conectado"},{DeviceConnectionModel::State::Controlling,"Você controla este computador"},{DeviceConnectionModel::State::Transferring,"Transferindo arquivos"},{DeviceConnectionModel::State::Error,"Não foi possível conectar"},{DeviceConnectionModel::State::Incompatible,"Versão incompatível"}};
    DeviceCard card; DiscoveredDeviceView value; value.uuid=QUuid::createUuid(); value.displayName="Sala";
    for(const auto& expected:states){value.state=expected.first;value.direction=DeviceConnectionModel::Direction::Unknown;card.setDevice(value);auto* label=card.findChild<QLabel*>("deviceStatusLabel");ASSERT_NE(label,nullptr);EXPECT_TRUE(label->text().contains(expected.second));EXPECT_FALSE(label->accessibleName().isEmpty());EXPECT_FALSE(label->accessibleDescription().isEmpty());EXPECT_FALSE(label->property("stateTone").toString().isEmpty());}
    value.state=DeviceConnectionModel::State::Connected;value.direction=DeviceConnectionModel::Direction::LocalControlsRemote;card.setDevice(value);EXPECT_TRUE(card.findChild<QLabel*>("deviceStatusLabel")->text().contains("você controla este computador"));
    value.direction=DeviceConnectionModel::Direction::RemoteControlsLocal;card.setDevice(value);EXPECT_TRUE(card.findChild<QLabel*>("deviceStatusLabel")->text().contains("este computador controla o seu"));
}

TEST(DeviceCard, RelativeContactIsDeterministicAndFalseActionsAreAbsent)
{
    DeviceCard card; DiscoveredDeviceView value; value.uuid=QUuid::createUuid(); value.displayName="Sala"; value.state=DeviceConnectionModel::State::Connected;
    const QDateTime now=QDateTime::fromMSecsSinceEpoch(120000,Qt::UTC); value.lastObserved=now.addSecs(-125); card.setDevice(value); card.setNow(now);
    ASSERT_NE(card.findChild<QLabel*>("deviceLastContactLabel"),nullptr); EXPECT_EQ(card.findChild<QLabel*>("deviceLastContactLabel")->text(),"Último contato: há 2 min");
    EXPECT_TRUE(card.findChildren<QPushButton*>("deviceLocateButton").isEmpty()); EXPECT_FALSE(card.findChildren<QPushButton*>("devicePermissionsButton").isEmpty()); EXPECT_TRUE(card.findChildren<QPushButton*>("deviceDisconnectButton").isEmpty());
}

TEST(DiscoveredDevicesModel, NewDiscoveryObservationAdvancesContactWithoutOverwritingCoreState)
{
    Fixture f;const QUuid id=QUuid::createUuid();ASSERT_TRUE(f.model.upsert(ad(id,"peer",1000)));
    f.connections.synchronizeState(id,DeviceConnectionModel::State::Connected,{}, {},QDateTime::fromMSecsSinceEpoch(2000,Qt::UTC),DeviceConnectionModel::Direction::LocalControlsRemote);
    ASSERT_TRUE(f.model.upsert(ad(id,"peer",3000)));const auto view=f.model.find(id);ASSERT_TRUE(view);EXPECT_EQ(view->state,DeviceConnectionModel::State::Connected);EXPECT_EQ(view->direction,DeviceConnectionModel::Direction::LocalControlsRemote);EXPECT_EQ(view->lastObserved.toMSecsSinceEpoch(),3000);
}

TEST(DeviceCard, EnablesOnlyActionsBackedByUsableEndpoints)
{
    DeviceCard card; DiscoveredDeviceView value; value.uuid=QUuid::createUuid(); value.displayName="Sala"; value.state=DeviceConnectionModel::State::Available; value.compatible=true; value.discoveryAvailable=true;
    card.setConnectionInitiationAllowed(true); value.role=ZeroconfRole::Server;
    card.setDevice(value); EXPECT_FALSE(card.findChild<QPushButton*>("deviceConnectButton")->isEnabled()); value.addresses.insert("192.0.2.1"); value.controlPort=24800; card.setDevice(value); EXPECT_TRUE(card.findChild<QPushButton*>("deviceConnectButton")->isEnabled());
    value.role=ZeroconfRole::Client; card.setDevice(value); EXPECT_FALSE(card.findChild<QPushButton*>("deviceConnectButton")->isEnabled()); value.role=ZeroconfRole::Server; card.setConnectionInitiationAllowed(false); EXPECT_FALSE(card.findChild<QPushButton*>("deviceConnectButton")->isEnabled());
    value.state=DeviceConnectionModel::State::Connected; value.capabilities.insert(ZeroconfCapability::FileTransfer); card.setDevice(value); EXPECT_FALSE(card.findChild<QPushButton*>("deviceSendFileButton")->isVisibleTo(&card)); value.transferPort=24801; card.setDevice(value); EXPECT_TRUE(card.findChild<QPushButton*>("deviceSendFileButton")->isVisibleTo(&card));
}
