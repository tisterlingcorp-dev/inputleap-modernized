#include "LocalDeviceIdentity.h"
#include "ZeroconfMetadata.h"
#include "ZeroconfDiscoveryCoordinator.h"
#include "ZeroconfRegistrationState.h"

#include <gtest/gtest.h>
#include <QSettings>
#include <QTemporaryDir>

namespace {
ZeroconfMetadata metadata(const QString& uuid = "123e4567-e89b-42d3-a456-426614174000")
{
    ZeroconfMetadata value;
    value.uuid = QUuid(uuid);
    value.technicalName = QString::fromUtf8("máquina-α");
    value.friendlyName = QString::fromUtf8("Notebook da sala 🖥");
    value.osFamily = ZeroconfOsFamily::Windows;
    value.inputLeapVersion = "3.1.0-modernized";
    value.role = ZeroconfRole::Server;
    value.capabilities = {ZeroconfCapability::Keyboard, ZeroconfCapability::Clipboard, ZeroconfCapability::FileTransfer};
    value.controlPort = 24800;
    value.transferPort = 24801;
    value.pairingPort = 24802;
    value.features = {"tls-psk", "folder-transfer", "pairing-srp6a-v1"};
    return value;
}
QString file(QTemporaryDir& dir) { return dir.filePath("identity.ini"); }
}

TEST(ZeroconfMetadataTests, RoundTripsAllFieldsAndUnicodeDeterministically)
{
    const auto first = ZeroconfMetadataCodec::serialize(metadata());
    const auto second = ZeroconfMetadataCodec::serialize(metadata());
    ASSERT_TRUE(first.ok) << first.detail.toStdString();
    EXPECT_EQ(first.txt, second.txt);
    const auto parsed = ZeroconfMetadataCodec::parse(first.txt);
    ASSERT_EQ(parsed.status, ZeroconfParseStatus::Compatible) << parsed.detail.toStdString();
    ASSERT_TRUE(parsed.metadata.has_value());
    EXPECT_EQ(*parsed.metadata, metadata());
}

TEST(ZeroconfMetadataTests, NeverSerializesSecrets)
{
    const auto result = ZeroconfMetadataCodec::serialize(metadata());
    ASSERT_TRUE(result.ok);
    const auto lower = result.txt.toLower();
    for (const QByteArray secret : {"pairing=", "pairing-code=", "psk=", "fingerprint=", "username=", "path=", "clipboard-data="})
        EXPECT_FALSE(lower.contains(secret));
}

TEST(ZeroconfMetadataTests, RejectsMalformedAndNeverReturnsPartialIdentity)
{
    const QList<QByteArray> invalid = {
        "sv=1\npv=1\nuuid=nope\nname=x\nos=windows\nver=1\nrole=server\ncap=keyboard\ncp=1\ntp=2\nfeat=",
        "sv=x\npv=1\nuuid=123e4567-e89b-42d3-a456-426614174000",
        "sv=1\npv=1\nuuid=123e4567-e89b-42d3-a456-426614174000\nname=x\nos=windows\nver=1\nrole=server\ncap=bogus\ncp=1\ntp=2\nfeat=",
        "sv=1\npv=1\nuuid=123e4567-e89b-42d3-a456-426614174000\nname=x\nos=windows\nver=1\nrole=server\ncap=keyboard\ncp=0\ntp=2\nfeat=",
        QByteArray("sv=1\npv=1\nuuid=123e4567-e89b-42d3-a456-426614174000\nname=\xff\nos=windows\nver=1\nrole=server\ncap=keyboard\ncp=1\ntp=2\nfeat=", 123),
        QByteArray(1400, 'x')
    };
    for (const auto& txt : invalid) {
        const auto parsed = ZeroconfMetadataCodec::parse(txt);
        EXPECT_EQ(parsed.status, ZeroconfParseStatus::Malformed);
        EXPECT_FALSE(parsed.metadata.has_value());
        EXPECT_FALSE(parsed.detail.isEmpty());
    }
}

TEST(ZeroconfMetadataTests, UnknownKeysAreForwardCompatibleAndVersionsExplicit)
{
    auto encoded = ZeroconfMetadataCodec::serialize(metadata()).txt;
    encoded += "\nfuture=value";
    EXPECT_EQ(ZeroconfMetadataCodec::parse(encoded).status, ZeroconfParseStatus::Compatible);
    encoded.replace("pv=1", "pv=99");
    EXPECT_EQ(ZeroconfMetadataCodec::parse(encoded).status, ZeroconfParseStatus::Incompatible);
}

TEST(ZeroconfMetadataTests, LegacyAdvertisementIsExplicit)
{
    const auto parsed = ZeroconfMetadataCodec::parse({});
    EXPECT_EQ(parsed.status, ZeroconfParseStatus::Legacy);
    EXPECT_FALSE(parsed.metadata.has_value());
}

TEST(ZeroconfMetadataTests, PairingPortIsOptionalAndStrict)
{
    const auto modern=ZeroconfMetadataCodec::serialize(metadata()); ASSERT_TRUE(modern.ok);
    ASSERT_EQ(ZeroconfMetadataCodec::parse(modern.txt).metadata->pairingPort,24802);
    QByteArray old=modern.txt; old.replace("\npp=24802","");
    const auto oldParsed=ZeroconfMetadataCodec::parse(old); ASSERT_EQ(oldParsed.status,ZeroconfParseStatus::Compatible);
    EXPECT_EQ(oldParsed.metadata->pairingPort,0);
    for(const QByteArray invalid:{"","0","01","65536","-1","abc"}){QByteArray bad=modern.txt;bad.replace("pp=24802","pp="+invalid);EXPECT_EQ(ZeroconfMetadataCodec::parse(bad).status,ZeroconfParseStatus::Malformed);}
}

TEST(ZeroconfMetadataTests, DeduplicatesUuidAcrossInterfacesAndKeepsSameNameDifferentUuid)
{
    qint64 now = 1000;
    ZeroconfDiscoveryCache cache([&] { return now; }, 5000);
    auto a = metadata();
    auto b = metadata("123e4567-e89b-42d3-a456-426614174001");
    EXPECT_EQ(cache.observe(a, "192.0.2.1", 1), ZeroconfDiscoveryEvent::Found);
    EXPECT_EQ(cache.observe(a, "fe80::1", 2), ZeroconfDiscoveryEvent::Updated);
    EXPECT_EQ(cache.observe(b, "192.0.2.2", 1), ZeroconfDiscoveryEvent::Found);
    ASSERT_EQ(cache.devices().size(), 2);
    EXPECT_EQ(cache.devices().first().addresses.size() + cache.devices().last().addresses.size(), 3);
}

TEST(ZeroconfMetadataTests, UpdatesExpiresAndEmitsLostOnlyOnce)
{
    qint64 now = 1000;
    ZeroconfDiscoveryCache cache([&] { return now; }, 100);
    auto value = metadata();
    EXPECT_EQ(cache.observe(value, "192.0.2.1", 1), ZeroconfDiscoveryEvent::Found);
    now = 1050;
    value.friendlyName = "Updated";
    EXPECT_EQ(cache.observe(value, "192.0.2.1", 1), ZeroconfDiscoveryEvent::Updated);
    now = 1200;
    const auto lost = cache.expire();
    ASSERT_EQ(lost.size(), 1);
    EXPECT_EQ(lost.first().uuid, value.uuid);
    EXPECT_TRUE(cache.expire().isEmpty());
}

TEST(ZeroconfMetadataTests, ExplicitRemovalWaitsForLastInterface)
{
    qint64 now = 0;
    ZeroconfDiscoveryCache cache([&] { return now; }, 100);
    const auto value = metadata();
    cache.observe(value, "192.0.2.1", 1);
    cache.observe(value, "fe80::1", 2);
    EXPECT_FALSE(cache.remove(value.uuid, 1).has_value());
    EXPECT_TRUE(cache.remove(value.uuid, 2).has_value());
    EXPECT_FALSE(cache.remove(value.uuid, 2).has_value());
}

TEST(DnsSdTxtRecordCodecTests, RejectsTruncatedZeroLengthDuplicateAndOversizedEntries)
{
    QByteArray truncated;
    truncated.append(char(5));
    truncated.append("abc");
    EXPECT_EQ(DnsSdTxtRecordCodec::decode(truncated).status, ZeroconfParseStatus::Malformed);
    EXPECT_EQ(DnsSdTxtRecordCodec::decode(QByteArray(1, '\0')).status, ZeroconfParseStatus::Malformed);
    QByteArray duplicate; duplicate += char(3); duplicate += "a=1"; duplicate += char(3); duplicate += "a=2";
    EXPECT_EQ(DnsSdTxtRecordCodec::decode(duplicate).status, ZeroconfParseStatus::Malformed);
    EXPECT_FALSE(DnsSdTxtRecordCodec::encode({QByteArray(256, 'x')}).ok);
}

TEST(DnsSdTxtRecordCodecTests, WireRoundTripFeedsMetadataParser)
{
    const auto canonical = ZeroconfMetadataCodec::serialize(metadata());
    ASSERT_TRUE(canonical.ok);
    const auto wire = DnsSdTxtRecordCodec::fromCanonical(canonical.txt);
    ASSERT_TRUE(wire.ok);
    const auto decoded = DnsSdTxtRecordCodec::decode(wire.wire);
    ASSERT_EQ(decoded.status, ZeroconfParseStatus::Compatible);
    ASSERT_TRUE(decoded.metadata.has_value());
    EXPECT_EQ(*decoded.metadata, metadata());
}

TEST(ZeroconfMetadataTests, RefreshDoesNotSpamAndInterfacesExpireIndependently)
{
    qint64 now = 0;
    ZeroconfDiscoveryCache cache([&] { return now; }, 100);
    const auto value = metadata();
    EXPECT_EQ(cache.observe(value, "192.0.2.1", 1), ZeroconfDiscoveryEvent::Found);
    EXPECT_EQ(cache.observe(value, "192.0.2.2", 2), ZeroconfDiscoveryEvent::Updated);
    now = 50;
    EXPECT_EQ(cache.observe(value, "192.0.2.1", 1), ZeroconfDiscoveryEvent::Refreshed);
    now = 120;
    EXPECT_TRUE(cache.expire().isEmpty());
    const auto devices = cache.devices();
    ASSERT_EQ(devices.size(), 1);
    EXPECT_EQ(devices.first().interfaces, QSet<quint32>({1}));
    EXPECT_EQ(devices.first().addresses, QSet<QString>({"192.0.2.1"}));
}

TEST(ZeroconfMetadataTests, InvalidObservationHasNoPartialMutation)
{
    qint64 now = 1;
    ZeroconfDiscoveryCache cache([&] { return now; }, 100);
    auto value = metadata(); value.uuid = {};
    EXPECT_EQ(cache.observe(value, "192.0.2.1", 1), ZeroconfDiscoveryEvent::Rejected);
    EXPECT_TRUE(cache.devices().isEmpty());
    value = metadata();
    EXPECT_EQ(cache.observe(value, {}, 1), ZeroconfDiscoveryEvent::Rejected);
    EXPECT_EQ(cache.observe(value, "192.0.2.1", 0), ZeroconfDiscoveryEvent::Rejected);
}

TEST(LocalDeviceIdentityTests, PersistsAndReloadsCanonicalUuid)
{
    QTemporaryDir dir;
    QSettings settings(file(dir), QSettings::IniFormat);
    const auto created = LocalDeviceIdentity::loadOrCreate(settings);
    ASSERT_TRUE(created.ok);
    ASSERT_FALSE(created.uuid.isNull());
    QSettings reload(file(dir), QSettings::IniFormat);
    const auto loaded = LocalDeviceIdentity::loadOrCreate(reload);
    EXPECT_TRUE(loaded.ok);
    EXPECT_EQ(loaded.uuid, created.uuid);
}

TEST(LocalDeviceIdentityTests, LoadExistingIsReadOnlyAndReturnsPersistedIdentity)
{
    QTemporaryDir dir;
    QSettings empty(file(dir), QSettings::IniFormat);
    const auto missing = LocalDeviceIdentity::loadExisting(empty);
    EXPECT_FALSE(missing.ok);
    EXPECT_TRUE(missing.uuid.isNull());
    EXPECT_TRUE(empty.allKeys().isEmpty());

    const auto created = LocalDeviceIdentity::loadOrCreate(empty);
    ASSERT_TRUE(created.ok);
    const QStringList keysBefore = empty.allKeys();
    const auto loaded = LocalDeviceIdentity::loadExisting(empty);
    ASSERT_TRUE(loaded.ok);
    EXPECT_EQ(loaded.uuid, created.uuid);
    EXPECT_EQ(empty.allKeys(), keysBefore);
}

TEST(LocalDeviceIdentityTests, ReportsAtomicSaveFailure)
{
    QTemporaryDir dir;
    QSettings settings(dir.path(), QSettings::IniFormat);
    const auto result = LocalDeviceIdentity::loadOrCreate(settings);
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(result.uuid.isNull());
    EXPECT_FALSE(result.detail.isEmpty());
}

TEST(LocalDeviceIdentityTests, SyncFailuresPublishNoNewIdentity)
{
    QTemporaryDir dir; QSettings first(file(dir), QSettings::IniFormat);
    int calls = 0;
    auto result = LocalDeviceIdentity::loadOrCreate(first, [&](QSettings&) { ++calls; return false; });
    EXPECT_FALSE(result.ok); EXPECT_TRUE(result.uuid.isNull()); EXPECT_EQ(calls, 1);

    QSettings second(dir.filePath("second.ini"), QSettings::IniFormat); calls = 0;
    result = LocalDeviceIdentity::loadOrCreate(second, [&](QSettings& s) { ++calls; s.sync(); return calls != 2; });
    EXPECT_FALSE(result.ok); EXPECT_TRUE(result.uuid.isNull()); EXPECT_GE(calls, 2);
    EXPECT_TRUE(second.value("localDeviceIdentity/activeGeneration").toString().isEmpty());
}

TEST(LocalDeviceIdentityTests, PreservesLegacyAndInvalidStoredValuesDeterministically)
{
    QTemporaryDir dir; QSettings legacy(file(dir), QSettings::IniFormat);
    const QString oldUuid = "123e4567-e89b-42d3-a456-426614174012";
    legacy.setValue("localDeviceIdentity/uuid", oldUuid); legacy.sync();
    const auto first = LocalDeviceIdentity::loadOrCreate(legacy);
    const auto second = LocalDeviceIdentity::loadOrCreate(legacy);
    ASSERT_TRUE(first.ok); EXPECT_EQ(first.uuid, QUuid(oldUuid)); EXPECT_EQ(second.uuid, first.uuid);

    QSettings invalid(dir.filePath("invalid.ini"), QSettings::IniFormat);
    invalid.setValue("localDeviceIdentity/activeGeneration", "generation");
    invalid.setValue("localDeviceIdentity/generations/generation/uuid", "invalid");
    EXPECT_FALSE(LocalDeviceIdentity::loadOrCreate(invalid).ok);
    EXPECT_EQ(invalid.value("localDeviceIdentity/generations/generation/uuid"), "invalid");
}

TEST(ZeroconfDiscoveryCoordinatorTests, CancellationAndDuplicateAddRejectLateCallbacks)
{
    ZeroconfDiscoveryCoordinator c; const auto old = c.begin("k", "old", 7);
    const auto fresh = c.begin("k", "new", 7);
    EXPECT_FALSE(c.active("k", old)); EXPECT_TRUE(c.active("k", fresh)); EXPECT_EQ(c.pendingCount(), 1);
    EXPECT_FALSE(c.setResolved("k", old, {}, 24800));
    EXPECT_FALSE(c.cancel("k").has_value());
    EXPECT_EQ(c.address("k", fresh, true, "192.0.2.1", 10).route, ZeroconfDiscoveryCoordinator::Route::Ignored);
}

TEST(ZeroconfDiscoveryCoordinatorTests, RoutesCompatibleAddressesAndReturnsUuidOnCancel)
{
    ZeroconfDiscoveryCoordinator c; const auto token = c.begin("k", "name", 1);
    const auto wire = DnsSdTxtRecordCodec::fromCanonical(ZeroconfMetadataCodec::serialize(metadata()).txt).wire;
    ASSERT_TRUE(c.setResolved("k", token, wire, 24800));
    const auto add = c.address("k", token, true, "192.0.2.1", 10);
    ASSERT_EQ(add.route, ZeroconfDiscoveryCoordinator::Route::CompatibleAdd); ASSERT_TRUE(add.metadata);
    EXPECT_EQ(c.address("k", token, false, "192.0.2.1", 10).route, ZeroconfDiscoveryCoordinator::Route::CompatibleRemove);
    const auto removed = c.cancel("k"); ASSERT_TRUE(removed); EXPECT_EQ(*removed, metadata().uuid);
    EXPECT_FALSE(c.cancel("k"));
}

TEST(ZeroconfDiscoveryCoordinatorTests, RoutesLegacyMalformedIncompatibleAndInvalidAddress)
{
    ZeroconfDiscoveryCoordinator c;
    auto token = c.begin("legacy", "n", 1); ASSERT_TRUE(c.setResolved("legacy", token, {}, 1));
    EXPECT_EQ(c.address("legacy", token, true, "a", 1).route, ZeroconfDiscoveryCoordinator::Route::Legacy);
    token = c.begin("bad", "n", 1); ASSERT_TRUE(c.setResolved("bad", token, QByteArray(1, char(5)), 1));
    EXPECT_EQ(c.address("bad", token, true, "a", 1).route, ZeroconfDiscoveryCoordinator::Route::Malformed);
    auto incompatible = ZeroconfMetadataCodec::serialize(metadata()).txt; incompatible.replace("pv=1", "pv=99");
    token = c.begin("future", "n", 1); ASSERT_TRUE(c.setResolved("future", token, DnsSdTxtRecordCodec::fromCanonical(incompatible).wire, 24800));
    EXPECT_EQ(c.address("future", token, true, "a", 1).route, ZeroconfDiscoveryCoordinator::Route::Incompatible);
    token = c.begin("invalid", "n", 1); ASSERT_TRUE(c.setResolved("invalid", token, DnsSdTxtRecordCodec::fromCanonical(ZeroconfMetadataCodec::serialize(metadata()).txt).wire, 24800));
    EXPECT_EQ(c.address("invalid", token, true, {}, 1).route, ZeroconfDiscoveryCoordinator::Route::InvalidAddress);
}

TEST(ZeroconfRegistrationStateTests, ConfirmationAndFailureDriveRetryableState)
{
    ZeroconfRegistrationState state; EXPECT_TRUE(state.begin()); EXPECT_FALSE(state.isRegistered());
    EXPECT_TRUE(state.confirm()); EXPECT_TRUE(state.isRegistered()); EXPECT_FALSE(state.begin());
    state.fail(); EXPECT_TRUE(state.begin()); EXPECT_FALSE(state.isRegistered());
}

TEST(ZeroconfMetadataTests, ClientUsesZeroControlPortButServersRequireControlPort)
{
    auto value = metadata(); value.role = ZeroconfRole::Client; value.controlPort = 0;
    const auto encoded = ZeroconfMetadataCodec::serialize(value);
    ASSERT_TRUE(encoded.ok) << encoded.detail.toStdString();
    EXPECT_EQ(ZeroconfMetadataCodec::parse(encoded.txt).status, ZeroconfParseStatus::Compatible);
    value.role = ZeroconfRole::Server;
    EXPECT_FALSE(ZeroconfMetadataCodec::serialize(value).ok);
}

TEST(ZeroconfMetadataTests, FutureProtocolRetainsCanonicalIdentityForIncompatibleCard)
{
    auto canonical = ZeroconfMetadataCodec::serialize(metadata()).txt;
    canonical.replace("pv=1", "pv=99");
    const auto parsed = ZeroconfMetadataCodec::parse(canonical);
    ASSERT_EQ(parsed.status, ZeroconfParseStatus::Incompatible);
    ASSERT_TRUE(parsed.metadata.has_value());
    EXPECT_EQ(parsed.metadata->uuid, metadata().uuid);
    EXPECT_EQ(parsed.metadata->technicalName, metadata().technicalName);

    ZeroconfDiscoveryCoordinator coordinator;
    const auto token = coordinator.begin("future", "fallback", 1);
    const auto wire = DnsSdTxtRecordCodec::fromCanonical(canonical);
    ASSERT_TRUE(wire.ok);
    ASSERT_TRUE(coordinator.setResolved("future", token, wire.wire, 24800));
    const auto decision = coordinator.address("future", token, true, "192.0.2.1", 10);
    EXPECT_EQ(decision.route, ZeroconfDiscoveryCoordinator::Route::Incompatible);
    ASSERT_TRUE(decision.metadata.has_value());
    EXPECT_EQ(decision.metadata->uuid, metadata().uuid);
}

TEST(ZeroconfMetadataTests, RejectsInvalidEnumCastsAndDuplicateCapabilities)
{
    auto value = metadata(); value.osFamily = static_cast<ZeroconfOsFamily>(99);
    EXPECT_FALSE(ZeroconfMetadataCodec::serialize(value).ok);
    value = metadata(); value.role = static_cast<ZeroconfRole>(99);
    EXPECT_FALSE(ZeroconfMetadataCodec::serialize(value).ok);
    value = metadata(); value.capabilities = {static_cast<ZeroconfCapability>(99)};
    EXPECT_FALSE(ZeroconfMetadataCodec::serialize(value).ok);
    auto txt = ZeroconfMetadataCodec::serialize(metadata()).txt;
    txt.replace("cap=clipboard,file-transfer,keyboard", "cap=keyboard,keyboard");
    EXPECT_EQ(ZeroconfMetadataCodec::parse(txt).status, ZeroconfParseStatus::Malformed);
    txt.replace("cap=keyboard,keyboard", "cap=keyboard,");
    EXPECT_EQ(ZeroconfMetadataCodec::parse(txt).status, ZeroconfParseStatus::Malformed);
}

TEST(ZeroconfDiscoveryCacheTests, AddressRemovalAndExpiryArePerAddress)
{
    qint64 now = 0; ZeroconfDiscoveryCache cache([&]{ return now; }, 100); const auto value = metadata();
    cache.observe(value, "192.0.2.1", 1); cache.observe(value, "fe80::1", 1);
    EXPECT_FALSE(cache.removeAddress(value.uuid, "192.0.2.1", 1));
    ASSERT_EQ(cache.devices().size(), 1); EXPECT_EQ(cache.devices().first().addresses, QSet<QString>({"fe80::1"}));
    now = 50; cache.observe(value, "192.0.2.2", 1); now = 110;
    EXPECT_TRUE(cache.expire().isEmpty());
    ASSERT_EQ(cache.devices().size(), 1); EXPECT_EQ(cache.devices().first().addresses, QSet<QString>({"192.0.2.2"}));
    EXPECT_TRUE(cache.removeAddress(value.uuid, "192.0.2.2", 1));
}

TEST(ZeroconfDiscoveryCoordinatorTests, EnforcesRoleSpecificSrvPortAndOneShotResolve)
{
    ZeroconfDiscoveryCoordinator c; auto value = metadata();
    auto token = c.begin("server", "n", 1); auto wire = DnsSdTxtRecordCodec::fromCanonical(ZeroconfMetadataCodec::serialize(value).txt).wire;
    EXPECT_TRUE(c.setResolved("server", token, wire, value.controlPort));
    EXPECT_FALSE(c.setResolved("server", token, wire, value.controlPort));
    EXPECT_EQ(c.address("server", token, true, "192.0.2.1", 1).route, ZeroconfDiscoveryCoordinator::Route::CompatibleAdd);
    EXPECT_EQ(c.address("server", token, false, "192.0.2.1", 0).route, ZeroconfDiscoveryCoordinator::Route::CompatibleRemove);
    value.role=ZeroconfRole::Client; value.controlPort=0; token=c.begin("client","n",1);
    wire=DnsSdTxtRecordCodec::fromCanonical(ZeroconfMetadataCodec::serialize(value).txt).wire;
    ASSERT_TRUE(c.setResolved("client",token,wire,54321));
    EXPECT_EQ(c.address("client",token,true,"192.0.2.2",1).route,ZeroconfDiscoveryCoordinator::Route::CompatibleAdd);
    token=c.begin("badclient","n",1); ASSERT_TRUE(c.setResolved("badclient",token,wire,0));
    EXPECT_EQ(c.address("badclient",token,true,"192.0.2.2",1).route,ZeroconfDiscoveryCoordinator::Route::InvalidAddress);
}

TEST(ZeroconfRetryPolicyTests, FailureBacksOffWithoutDuplicateAndConfirmationCancels)
{
    ZeroconfRetryPolicy policy(2000, 30000);
    EXPECT_EQ(policy.fail(), 2000); EXPECT_FALSE(policy.fail().has_value());
    policy.retryStarted(); EXPECT_EQ(policy.fail(), 4000);
    policy.retryStarted(); policy.confirm(); EXPECT_FALSE(policy.pending()); EXPECT_EQ(policy.nextDelayMs(), 2000);
}
