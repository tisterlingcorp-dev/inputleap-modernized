#include "TrayMenuPolicy.h"
#include <gtest/gtest.h>

namespace {
DiscoveredDeviceView peer(const QString& uuid, const QString& name,
                          DeviceConnectionModel::State state = DeviceConnectionModel::State::Connected,
                          const QString& address = "192.0.2.10")
{
    DiscoveredDeviceView device;
    device.uuid = QUuid(uuid);
    device.displayName = name;
    device.state = state;
    device.discoveryAvailable = true;
    device.compatible = true;
    device.transferPort = 24801;
    device.addresses.insert(address);
    device.capabilities.insert(ZeroconfCapability::FileTransfer);
    CapabilityAdvertisement advertised; advertised.uuid=device.uuid;
    advertised.versions={{CapabilityId::Control,{1,0}},{CapabilityId::FileTransfer,{1,1}}};
    advertised.claimed.insert(CapabilityId::FileTransfer);
    device.negotiation=CapabilityNegotiationPolicy().negotiate(advertised);
    return device;
}
}

TEST(TrayMenuPolicy, BuildsConcisePortugueseMenuForZeroOneAndFourPeers)
{
    EXPECT_TRUE(TrayMenuPolicy::build({}).peers.isEmpty());

    const auto one = TrayMenuPolicy::build({peer("{00000000-0000-0000-0000-000000000001}", "Sala")});
    ASSERT_EQ(one.peers.size(), 1);
    EXPECT_EQ(one.peers.first().displayName, "Sala");
    EXPECT_EQ(one.openText, "&Abrir InputLeap");
    EXPECT_EQ(one.peersText, "Computadores ativos");
    EXPECT_EQ(one.sendText, "Enviar &arquivo…");
    EXPECT_EQ(one.transfersText, "&Transferências");
    EXPECT_EQ(one.quitText, "&Sair");
    EXPECT_FALSE(one.showPause);

    QList<DiscoveredDeviceView> four;
    for (int i = 4; i >= 1; --i)
        four.append(peer(QString("{00000000-0000-0000-0000-00000000000%1}").arg(i), QString("Peer %1").arg(i)));
    const auto result = TrayMenuPolicy::build(four);
    ASSERT_EQ(result.peers.size(), 4);
    EXPECT_EQ(result.peers.first().displayName, "Peer 1");
    EXPECT_EQ(result.peers.last().displayName, "Peer 4");
}

TEST(TrayMenuPolicy, LimitsFivePeersAndIncludesOnlyAuthoritativeActiveStates)
{
    QList<DiscoveredDeviceView> devices;
    devices << peer("{00000000-0000-0000-0000-000000000001}", "A", DeviceConnectionModel::State::Connected)
            << peer("{00000000-0000-0000-0000-000000000002}", "B", DeviceConnectionModel::State::Controlling)
            << peer("{00000000-0000-0000-0000-000000000003}", "C", DeviceConnectionModel::State::Transferring)
            << peer("{00000000-0000-0000-0000-000000000004}", "D", DeviceConnectionModel::State::Available)
            << peer("{00000000-0000-0000-0000-000000000005}", "E", DeviceConnectionModel::State::Offline)
            << peer("{00000000-0000-0000-0000-000000000006}", "F", DeviceConnectionModel::State::Connected)
            << peer("{00000000-0000-0000-0000-000000000007}", "G", DeviceConnectionModel::State::Connected);
    const auto result = TrayMenuPolicy::build(devices);
    ASSERT_EQ(result.peers.size(), 4);
    EXPECT_EQ(result.peers.at(0).displayName, "A");
    EXPECT_EQ(result.peers.at(1).displayName, "B");
    EXPECT_EQ(result.peers.at(2).displayName, "C");
    EXPECT_FALSE(result.peers.at(2).sendEnabled);
    EXPECT_EQ(result.peers.at(3).displayName, "F");
}

TEST(TrayMenuPolicy, DuplicateAliasesRemainUuidIsolated)
{
    const auto result = TrayMenuPolicy::build({
        peer("{00000000-0000-0000-0000-000000000002}", "Escritório", DeviceConnectionModel::State::Connected, "192.0.2.2"),
        peer("{00000000-0000-0000-0000-000000000001}", "Escritório", DeviceConnectionModel::State::Connected, "192.0.2.1")});
    ASSERT_EQ(result.peers.size(), 2);
    EXPECT_NE(result.peers.at(0).target.uuid, result.peers.at(1).target.uuid);
    EXPECT_NE(result.peers.at(0).target.address, result.peers.at(1).target.address);
    EXPECT_EQ(result.peers.at(0).target.uuid, QUuid("{00000000-0000-0000-0000-000000000001}"));
    EXPECT_EQ(result.peers.at(0).displayName,"Escritório (1)");
    EXPECT_EQ(result.peers.at(1).displayName,"Escritório (2)");
}

TEST(TrayMenuPolicy, ResolvesCapturedTargetOnlyWhileSamePeerAndEndpointRemainEligible)
{
    const auto original = peer("{00000000-0000-0000-0000-000000000001}", "Sala");
    const auto target = TrayMenuPolicy::build({original}).peers.first().target;
    EXPECT_TRUE(TrayMenuPolicy::resolveTarget(target, original).has_value());

    auto disconnected = original;
    disconnected.state = DeviceConnectionModel::State::Offline;
    EXPECT_FALSE(TrayMenuPolicy::resolveTarget(target, disconnected).has_value());

    auto changed = original;
    changed.addresses = {"192.0.2.99"};
    EXPECT_FALSE(TrayMenuPolicy::resolveTarget(target, changed).has_value());

    auto wrongUuid = original;
    wrongUuid.uuid = QUuid("{00000000-0000-0000-0000-000000000002}");
    EXPECT_FALSE(TrayMenuPolicy::resolveTarget(target, wrongUuid).has_value());
}

TEST(TrayMenuPolicy, RejectsMissingTransferPrerequisitesAndNeverInventsPause)
{
    auto noCapability = peer("{00000000-0000-0000-0000-000000000001}", "Sem recurso");
    noCapability.capabilities.clear();
    auto noPort = peer("{00000000-0000-0000-0000-000000000002}", "Sem porta");
    noPort.transferPort = 0;
    auto invalidAddress = peer("{00000000-0000-0000-0000-000000000003}", "Sem endereço", DeviceConnectionModel::State::Connected, "não-é-ip");
    const auto result = TrayMenuPolicy::build({noCapability, noPort, invalidAddress});
    ASSERT_EQ(result.peers.size(), 3);
    for (const auto& entry : result.peers)
        EXPECT_FALSE(entry.sendEnabled);
    EXPECT_FALSE(result.showPause);

    const auto rebuilt = TrayMenuPolicy::build({noCapability, noPort, invalidAddress});
    EXPECT_EQ(rebuilt.peers.size(), result.peers.size());
    for (int i = 0; i < rebuilt.peers.size(); ++i)
        EXPECT_EQ(rebuilt.peers.at(i).target.uuid, result.peers.at(i).target.uuid);
}

TEST(TrayMenuPolicy, RejectsUnusableIpv6AndSpecialAddresses)
{
    auto linkLocal=peer("{00000000-0000-0000-0000-000000000001}","Link",DeviceConnectionModel::State::Connected,"fe80::1");
    auto unspecified=peer("{00000000-0000-0000-0000-000000000002}","Any",DeviceConnectionModel::State::Connected,"0.0.0.0");
    auto multicast=peer("{00000000-0000-0000-0000-000000000003}","Grupo",DeviceConnectionModel::State::Connected,"ff02::1");
    const auto rejected=TrayMenuPolicy::build({linkLocal,unspecified,multicast});ASSERT_EQ(rejected.peers.size(),3);for(const auto& entry:rejected.peers)EXPECT_FALSE(entry.sendEnabled);
    auto scoped=linkLocal;scoped.addresses={"fe80::1%12"};const auto accepted=TrayMenuPolicy::build({scoped});ASSERT_EQ(accepted.peers.size(),1);EXPECT_TRUE(accepted.peers.first().sendEnabled);
}

TEST(TrayMenuPolicy, KeepsMainWindowAndTrayIconMutuallyExclusive)
{
    const auto open = TrayMenuPolicy::visibility(true);
    EXPECT_TRUE(open.mainWindowVisible);
    EXPECT_FALSE(open.trayIconVisible);
    EXPECT_NE(open.mainWindowVisible, open.trayIconVisible);

    const auto hidden = TrayMenuPolicy::visibility(false);
    EXPECT_FALSE(hidden.mainWindowVisible);
    EXPECT_TRUE(hidden.trayIconVisible);
    EXPECT_NE(hidden.mainWindowVisible, hidden.trayIconVisible);
}
