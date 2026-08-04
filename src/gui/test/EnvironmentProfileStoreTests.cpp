/* InputLeap -- atomic environment profile store tests. */
#include "EnvironmentProfileStore.h"
#include "ConfigurationTransactionLock.h"

#include <gtest/gtest.h>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLockFile>
#include <QMap>
#include <QProcess>
#include <QSettings>
#include <QTemporaryDir>

#include <filesystem>

namespace {
const QUuid firstUuid(QStringLiteral("{11111111-1111-1111-1111-111111111111}"));
const QUuid secondUuid(QStringLiteral("{22222222-2222-2222-2222-222222222222}"));

ScreenLayout::Device layoutDevice(const QUuid& uuid, const QString& name, const QRect& geometry)
{
    ScreenLayout::Device result;
    result.uuid = uuid;
    result.technicalName = name;
    result.geometry = geometry;
    result.monitors.push_back({QStringLiteral("monitor-1"), QRect(0, 0, 100, 100), 1.25,
                               Qt::LandscapeOrientation, true});
    return result;
}

EnvironmentProfile validProfile(EnvironmentProfile::Kind kind = EnvironmentProfile::Kind::Home)
{
    EnvironmentProfile profile;
    profile.kind = kind;
    profile.layout.columns = 2;
    profile.layout.rows = 1;
    profile.layout.gridTechnicalNames = {QStringLiteral("desktop"), QStringLiteral("notebook")};
    profile.layout.extension = ScreenLayout({
        layoutDevice(firstUuid, QStringLiteral("desktop"), QRect(0, 0, 100, 100)),
        layoutDevice(secondUuid, QStringLiteral("notebook"), QRect(100, 0, 100, 100)),
    });
    profile.devices = {
        {firstUuid, QStringLiteral("desktop"), DevicePermissions::ControlMouseKeyboard | DevicePermissions::ShareClipboard},
        {secondUuid, QStringLiteral("notebook"), DevicePermissions::SendFiles | DevicePermissions::ReceiveFiles | DevicePermissions::AutoConnect},
    };
    return profile;
}

QString seedLiteralSchemaOneFixture(QSettings& settings)
{
    const QString generation = QStringLiteral("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    const QString root = QStringLiteral("environmentProfiles");
    const QString group = root + QStringLiteral("/generations/") + generation;
    settings.setValue(root + QStringLiteral("/schemaVersion"), 1);
    settings.setValue(root + QStringLiteral("/activeGeneration"), generation);
    settings.setValue(group + QStringLiteral("/schemaVersion"), 1);
    settings.setValue(group + QStringLiteral("/activeKind"), QStringLiteral("home"));
    settings.setValue(group + QStringLiteral("/profiles/size"), 4);
    const QStringList literalKinds{
        QStringLiteral("home"),
        QStringLiteral("office"),
        QStringLiteral("travel"),
        QStringLiteral("presentation")
    };
    for (qsizetype index = 0; index < literalKinds.size(); ++index) {
        const QString profile = group + QStringLiteral("/profiles/") +
                                QString::number(index + 1);
        settings.setValue(profile + QStringLiteral("/kind"), literalKinds.at(index));
        settings.setValue(profile + QStringLiteral("/columns"), 1);
        settings.setValue(profile + QStringLiteral("/rows"), 1);
        settings.setValue(profile + QStringLiteral("/gridTechnicalNames"),
                          QStringList{QString()});
        settings.setValue(profile + QStringLiteral("/devices/size"), 0);
        settings.setValue(profile + QStringLiteral("/layout/extension/schemaVersion"), 2);
        settings.setValue(profile + QStringLiteral("/layout/extension/devices/size"), 0);
    }
    settings.sync();
    return generation;
}

QString settingsFile(QTemporaryDir& directory) { return directory.filePath(QStringLiteral("profiles.ini")); }
QByteArray bytes(const QString& path)
{
    QFile file(path);
    EXPECT_TRUE(file.open(QIODevice::ReadOnly));
    return file.readAll();
}

struct SettingsSnapshot {
    QStringList keys;
    QMap<QString, QVariant> values;
    QByteArray fileBytes;
};

SettingsSnapshot snapshot(QSettings& settings, const QString& path)
{
    settings.sync();
    SettingsSnapshot result;
    result.keys = settings.allKeys();
    for (const QString& key : result.keys) result.values.insert(key, settings.value(key));
    result.fileBytes = bytes(path);
    return result;
}

void expectUnchanged(QSettings& settings, const QString& path, const SettingsSnapshot& expected)
{
    settings.sync();
    EXPECT_EQ(settings.allKeys(), expected.keys);
    for (const QString& key : expected.keys) {
        const QVariant actual = settings.value(key);
        ASSERT_TRUE(expected.values.contains(key));
        EXPECT_EQ(actual.metaType().id(), expected.values.value(key).metaType().id()) << key.toStdString();
        EXPECT_TRUE(actual == expected.values.value(key)) << key.toStdString();
    }
    EXPECT_EQ(bytes(path), expected.fileBytes);
}

void expectSameProfile(const EnvironmentProfile& actual, const EnvironmentProfile& expected)
{
    EXPECT_EQ(actual.kind, expected.kind);
    EXPECT_EQ(actual.layout.columns, expected.layout.columns);
    EXPECT_EQ(actual.layout.rows, expected.layout.rows);
    EXPECT_EQ(actual.layout.gridTechnicalNames, expected.layout.gridTechnicalNames);
    EXPECT_EQ(actual.devices, expected.devices);
    const auto& a = actual.layout.extension.devices();
    const auto& e = expected.layout.extension.devices();
    ASSERT_EQ(a.size(), e.size());
    for (size_t i = 0; i < e.size(); ++i) {
        EXPECT_EQ(a[i].uuid, e[i].uuid);
        EXPECT_EQ(a[i].technicalName, e[i].technicalName);
        EXPECT_EQ(a[i].geometry, e[i].geometry);
        ASSERT_EQ(a[i].monitors.size(), e[i].monitors.size());
        for (size_t j = 0; j < e[i].monitors.size(); ++j) {
            EXPECT_EQ(a[i].monitors[j].id, e[i].monitors[j].id);
            EXPECT_EQ(a[i].monitors[j].geometry, e[i].monitors[j].geometry);
            EXPECT_DOUBLE_EQ(a[i].monitors[j].devicePixelRatio, e[i].monitors[j].devicePixelRatio);
            EXPECT_EQ(a[i].monitors[j].orientation, e[i].monitors[j].orientation);
            EXPECT_EQ(a[i].monitors[j].stableIdentity, e[i].monitors[j].stableIdentity);
        }
    }
}
}

TEST(EnvironmentProfileStoreTests, MissingConstructorDoesNotWrite)
{
    QTemporaryDir directory;
    QSettings settings(settingsFile(directory), QSettings::IniFormat);
    EnvironmentProfileStore store(settings);
    EXPECT_EQ(store.loadStatus(), EnvironmentProfileStore::LoadStatus::Missing);
    EXPECT_FALSE(settings.contains(QStringLiteral("environmentProfiles/schemaVersion")));
    EXPECT_TRUE(settings.allKeys().isEmpty());
}

#ifdef Q_OS_WIN
TEST(EnvironmentProfileStoreTests, EmptyNativeGenerationsKeyIsStructurallyMissing)
{
    const QString application = QStringLiteral("EnvironmentProfileStoreTests-") +
        QUuid::createUuid().toString(QUuid::WithoutBraces);
    QSettings settings(QSettings::NativeFormat, QSettings::UserScope,
                       QStringLiteral("InputLeapTests"), application);
    settings.clear();
    settings.setValue(QStringLiteral("environmentProfiles/generations/_seed"), 1);
    settings.sync();
    settings.remove(QStringLiteral("environmentProfiles/generations/_seed"));
    settings.sync();

    settings.beginGroup(QStringLiteral("environmentProfiles"));
    ASSERT_EQ(settings.childGroups(),
              QStringList{QStringLiteral("generations")});
    settings.endGroup();

    EnvironmentProfileStore store(settings);
    EXPECT_EQ(store.loadStatus(), EnvironmentProfileStore::LoadStatus::Missing);
    EXPECT_TRUE(settings.allKeys().isEmpty());

    settings.clear();
    settings.sync();
}
#endif

TEST(EnvironmentProfileStoreTests, InitializesExactlyFourClonesAndRoundTripsEveryField)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    const auto home = validProfile();
    {
        QSettings settings(path, QSettings::IniFormat);
        EnvironmentProfileStore store(settings);
        ASSERT_EQ(store.initializeFromLegacy(home), EnvironmentProfileStore::SaveResult::Success);
        EXPECT_EQ(store.profiles().size(), 4);
        EXPECT_EQ(store.activeKind(), EnvironmentProfile::Kind::Home);
        EXPECT_EQ(settings.value(QStringLiteral("environmentProfiles/schemaVersion")).toInt(),
              EnvironmentProfileStore::SchemaVersion);
        const QString activeGeneration = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
        EXPECT_FALSE(activeGeneration.isEmpty());
        settings.beginGroup(QStringLiteral("environmentProfiles/generations"));
        const QStringList generations = settings.childGroups();
        settings.endGroup();
        ASSERT_EQ(generations.size(), 1);
        EXPECT_EQ(generations.front(), activeGeneration);
        for (const auto kind : EnvironmentProfile::canonicalKinds()) {
            auto profile = store.profile(kind);
            ASSERT_TRUE(profile.has_value());
            auto expected = home; expected.kind = kind;
            expectSameProfile(*profile, expected);
        }
    }
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(settings);
    ASSERT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);
    ASSERT_EQ(reopened.profiles().size(), 4);
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        auto profile = reopened.profile(kind); ASSERT_TRUE(profile);
        auto expected = home; expected.kind = kind;
        expectSameProfile(*profile, expected);
    }
}

TEST(EnvironmentProfileStoreTests, PersistsOnlyAllowlistedProfileData)
{
    QTemporaryDir directory;
    QSettings settings(settingsFile(directory), QSettings::IniFormat);
    const QStringList forbiddenKeys = {QStringLiteral("pairing"), QStringLiteral("psk"), QStringLiteral("secret"),
        QStringLiteral("password"), QStringLiteral("token"), QStringLiteral("certificate"), QStringLiteral("privatekey"),
        QStringLiteral("ipaddresses"), QStringLiteral("capabilities"), QStringLiteral("truststate"), QStringLiteral("ssid"), QStringLiteral("bssid")};
    const QStringList sentinels = {QStringLiteral("DO_NOT_COPY_PAIRING"), QStringLiteral("DO_NOT_COPY_PSK"),
        QStringLiteral("DO_NOT_COPY_SECRET"), QStringLiteral("DO_NOT_COPY_NETWORK")};
    settings.setValue(QStringLiteral("fileTransferPairingCode"), sentinels[0]);
    settings.setValue(QStringLiteral("trustedFileTransferPeers/peer/psk"), sentinels[1]);
    settings.setValue(QStringLiteral("credentials/privateKey"), sentinels[2]);
    settings.setValue(QStringLiteral("deviceRegistry/generations/x/devices/1/ipAddresses"), sentinels[3]);
    EnvironmentProfileStore store(settings);
    ASSERT_EQ(store.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    for (const QString& key : settings.allKeys()) {
        if (!key.startsWith(QStringLiteral("environmentProfiles/"))) continue;
        const QString lower = key.toLower();
        for (const QString& forbidden : forbiddenKeys) EXPECT_FALSE(lower.contains(forbidden)) << key.toStdString();
        const QString rendered = settings.value(key).toString();
        for (const QString& sentinel : sentinels) EXPECT_FALSE(rendered.contains(sentinel)) << key.toStdString();
    }
}

TEST(EnvironmentProfileStoreTests, FutureSchemaIsBytePreservingReadOnly)
{
    QTemporaryDir directory; const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    settings.setValue(QStringLiteral("environmentProfiles/schemaVersion"), EnvironmentProfileStore::SchemaVersion + 1);
    settings.setValue(QStringLiteral("environmentProfiles/futurePayload"), QStringLiteral("untouched"));
    const SettingsSnapshot before = snapshot(settings, path);
    EnvironmentProfileStore store(settings);
    EXPECT_EQ(store.loadStatus(), EnvironmentProfileStore::LoadStatus::FutureSchema);
    expectUnchanged(settings, path, before);
    EXPECT_EQ(store.replaceProfile(validProfile()), EnvironmentProfileStore::SaveResult::ReadOnlyFutureSchema);
    EXPECT_EQ(store.setActive(EnvironmentProfile::Kind::Office), EnvironmentProfileStore::SaveResult::ReadOnlyFutureSchema);
    EXPECT_EQ(store.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::ReadOnlyFutureSchema);
    expectUnchanged(settings, path, before);
}

TEST(EnvironmentProfileStoreTests, AuthenticatedManifestCannotMaskFuturePhysicalRootSchema)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings);
    ASSERT_EQ(initial.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);

    settings.setValue(QStringLiteral("environmentProfiles/schemaVersion"),
                      EnvironmentProfileStore::SchemaVersion + 1);
    settings.sync();
    const SettingsSnapshot before = snapshot(settings, path);

    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(reopenedSettings);
    EXPECT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::FutureSchema);
    EXPECT_EQ(reopened.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::ReadOnlyFutureSchema);
    expectUnchanged(reopenedSettings, path, before);
}

TEST(EnvironmentProfileStoreTests, AuthenticatedManifestMustMatchPhysicalActiveGeneration)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings);
    ASSERT_EQ(initial.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);

    settings.setValue(QStringLiteral("environmentProfiles/activeGeneration"),
                      QStringLiteral("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"));
    settings.sync();
    const SettingsSnapshot before = snapshot(settings, path);

    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(reopenedSettings);
    EXPECT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_EQ(reopened.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::SettingsError);
    expectUnchanged(reopenedSettings, path, before);
}

TEST(EnvironmentProfileStoreTests, AuthenticatedManifestMustMatchPhysicalRecoveryGeneration)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings);
    ASSERT_EQ(initial.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    ASSERT_EQ(initial.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::Success);

    settings.setValue(QStringLiteral("environmentProfiles/recoveryGeneration"),
                      QStringLiteral("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"));
    settings.sync();
    const SettingsSnapshot before = snapshot(settings, path);

    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(reopenedSettings);
    EXPECT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_EQ(reopened.setActive(EnvironmentProfile::Kind::Travel),
              EnvironmentProfileStore::SaveResult::SettingsError);
    expectUnchanged(reopenedSettings, path, before);
}

TEST(EnvironmentProfileStoreTests, RecoveryRollsBackRootTornBeforeManifestCommit)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings);
    ASSERT_EQ(initial.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    const QString committedActive = settings.value(
        QStringLiteral("environmentProfiles/activeGeneration")).toString();
    const QString committedRecovery = settings.value(
        QStringLiteral("environmentProfiles/recoveryGeneration")).toString();
    const QVariant committedManifest = settings.value(
        QStringLiteral("environmentProfiles/manifest"));

    ASSERT_EQ(initial.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::Success);
    const QString uncommittedActive = settings.value(
        QStringLiteral("environmentProfiles/activeGeneration")).toString();
    ASSERT_NE(uncommittedActive, committedActive);
    ASSERT_EQ(settings.value(QStringLiteral("environmentProfiles/recoveryGeneration")).toString(),
              committedActive);

    // Recreate a process death after the physical root pointers were synced but
    // before the authenticated manifest for that promotion was committed.
    settings.setValue(QStringLiteral("environmentProfiles/manifest"), committedManifest);
    settings.sync();

    QSettings tornSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore torn(tornSettings);
    ASSERT_EQ(torn.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_EQ(torn.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::NotNeeded);

    QSettings recoveredSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore recovered(recoveredSettings);
    EXPECT_EQ(recovered.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(recovered.activeKind(), EnvironmentProfile::Kind::Home);
    EXPECT_EQ(recoveredSettings.value(
                  QStringLiteral("environmentProfiles/activeGeneration")).toString(),
              committedActive);
    EXPECT_EQ(recoveredSettings.value(
                  QStringLiteral("environmentProfiles/recoveryGeneration")).toString(),
              committedRecovery);
    EXPECT_EQ(recoveredSettings.value(QStringLiteral("environmentProfiles/manifest")),
              committedManifest);
}

TEST(EnvironmentProfileStoreTests, RecoveryCompletesRootTornBeforeRecoveryManifestCommit)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings);
    ASSERT_EQ(initial.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    ASSERT_EQ(initial.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::Success);
    const QString failedActive = settings.value(
        QStringLiteral("environmentProfiles/activeGeneration")).toString();
    const QString committedRecovery = settings.value(
        QStringLiteral("environmentProfiles/recoveryGeneration")).toString();
    ASSERT_FALSE(committedRecovery.isEmpty());
    settings.setValue(
        QStringLiteral("environmentProfiles/generations/%1/profiles/1/columns")
            .arg(failedActive),
        0);

    // Recreate a process death after recovery synced its physical pointers but
    // before publishing the authenticated recovery manifest.
    settings.setValue(QStringLiteral("environmentProfiles/activeGeneration"),
                      committedRecovery);
    settings.setValue(QStringLiteral("environmentProfiles/recoveryGeneration"), QString());
    settings.sync();

    QSettings tornSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore torn(tornSettings);
    ASSERT_EQ(torn.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_EQ(torn.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::Recovered);

    QSettings recoveredSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore recovered(recoveredSettings);
    EXPECT_EQ(recovered.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(recovered.activeKind(), EnvironmentProfile::Kind::Home);
    EXPECT_EQ(recoveredSettings.value(
                  QStringLiteral("environmentProfiles/activeGeneration")).toString(),
              committedRecovery);
    EXPECT_TRUE(recoveredSettings.value(
                    QStringLiteral("environmentProfiles/recoveryGeneration")).toString().isEmpty());
}

TEST(EnvironmentProfileStoreTests, TornRecoveryNeverDowngradesFutureActiveGeneration)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings);
    ASSERT_EQ(initial.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    ASSERT_EQ(initial.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::Success);
    const QString futureActive = settings.value(
        QStringLiteral("environmentProfiles/activeGeneration")).toString();
    const QString committedRecovery = settings.value(
        QStringLiteral("environmentProfiles/recoveryGeneration")).toString();
    settings.setValue(
        QStringLiteral("environmentProfiles/generations/%1/schemaVersion").arg(futureActive),
        EnvironmentProfileStore::SchemaVersion + 1);
    settings.setValue(QStringLiteral("environmentProfiles/activeGeneration"),
                      committedRecovery);
    settings.setValue(QStringLiteral("environmentProfiles/recoveryGeneration"), QString());
    settings.sync();
    const SettingsSnapshot before = snapshot(settings, path);

    QSettings tornSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore torn(tornSettings);
    ASSERT_EQ(torn.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_EQ(torn.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::ReadOnlyFutureSchema);
    expectUnchanged(tornSettings, path, before);
}

TEST(EnvironmentProfileStoreTests, FutureActiveGenerationSchemaIsBytePreservingAndNeverRecovered)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings);
    ASSERT_EQ(initial.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    ASSERT_EQ(initial.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::Success);
    const QString active = initial.currentGeneration().value();
    settings.setValue(
        QStringLiteral("environmentProfiles/generations/%1/schemaVersion").arg(active),
        EnvironmentProfileStore::SchemaVersion + 1);
    settings.sync();
    const SettingsSnapshot before = snapshot(settings, path);

    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(reopenedSettings);
    EXPECT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::FutureSchema);
    EXPECT_EQ(reopened.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::ReadOnlyFutureSchema);
    expectUnchanged(reopenedSettings, path, before);
}

TEST(EnvironmentProfileStoreTests, FutureRecoveryGenerationSchemaIsBytePreservingAndNeverPromoted)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings);
    ASSERT_EQ(initial.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    ASSERT_EQ(initial.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::Success);
    const QString active = settings.value(
        QStringLiteral("environmentProfiles/activeGeneration")).toString();
    const QString fallback = settings.value(
        QStringLiteral("environmentProfiles/recoveryGeneration")).toString();
    settings.setValue(
        QStringLiteral("environmentProfiles/generations/%1/profiles/1/columns").arg(active), 0);
    settings.setValue(
        QStringLiteral("environmentProfiles/generations/%1/schemaVersion").arg(fallback),
        EnvironmentProfileStore::SchemaVersion + 1);
    settings.sync();
    const SettingsSnapshot before = snapshot(settings, path);

    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(reopenedSettings);
    EXPECT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_EQ(reopened.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::ReadOnlyFutureSchema);
    expectUnchanged(reopenedSettings, path, before);
}

TEST(EnvironmentProfileStoreTests, RejectsStrictRootAndGenerationShapesWithoutMutation)
{
    const QList<QVariant> badSchemas = {QStringLiteral("1"), 1.5, 0, -1};
    for (const QVariant& schema : badSchemas) {
        QTemporaryDir directory; const QString path = settingsFile(directory); QSettings settings(path, QSettings::IniFormat);
        settings.setValue(QStringLiteral("environmentProfiles/schemaVersion"), schema);
        settings.setValue(QStringLiteral("environmentProfiles/payload"), QStringLiteral("keep"));
        const SettingsSnapshot before = snapshot(settings, path);
        EnvironmentProfileStore store(settings);
        EXPECT_EQ(store.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
        expectUnchanged(settings, path, before);
        EXPECT_EQ(store.replaceProfile(validProfile()), EnvironmentProfileStore::SaveResult::SettingsError);
        EXPECT_EQ(store.setActive(EnvironmentProfile::Kind::Office), EnvironmentProfileStore::SaveResult::SettingsError);
        EXPECT_EQ(store.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::SettingsError);
        expectUnchanged(settings, path, before);
    }

    struct Corruption { QString suffix; QVariant value; bool remove = false; };
    const QList<Corruption> corruptions = {
        {QStringLiteral("profiles/size"), 3},
        {QStringLiteral("profiles/size"), 5},
        {QStringLiteral("profiles/4"), {}, true},
        {QStringLiteral("profiles/1/columns"), {}, true},
        {QStringLiteral("profiles/2/kind"), QStringLiteral("home")},
        {QStringLiteral("profiles/1/devices/size"), QStringLiteral("2")},
        {QStringLiteral("profiles/1/devices/1/requestedResources"), qulonglong(1) << 31},
        {QStringLiteral("profiles/1/columns"), 0},
        {QStringLiteral("profiles/1/layout/extension/schemaVersion"), QStringLiteral("2")},
        {QStringLiteral("profiles/1/layout/extension/devices/size"), 3},
        {QStringLiteral("profiles/1/layout/extension/devices/1/technicalName"), {}, true},
    };
    for (const auto& corruption : corruptions) {
        QTemporaryDir directory; const QString path = settingsFile(directory);
        QString active;
        { QSettings settings(path, QSettings::IniFormat); EnvironmentProfileStore store(settings);
          ASSERT_EQ(store.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
          active = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
          const QString key = QStringLiteral("environmentProfiles/generations/") + active + QLatin1Char('/') + corruption.suffix;
          if (corruption.remove) settings.remove(key); else settings.setValue(key, corruption.value);
          settings.sync(); }
        QSettings settings(path, QSettings::IniFormat);
        const SettingsSnapshot before = snapshot(settings, path);
        EnvironmentProfileStore reopened(settings);
        EXPECT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema) << corruption.suffix.toStdString();
        EXPECT_TRUE(reopened.profiles().isEmpty());
        expectUnchanged(settings, path, before);
        EXPECT_EQ(reopened.replaceProfile(validProfile()), EnvironmentProfileStore::SaveResult::SettingsError);
        EXPECT_EQ(reopened.setActive(EnvironmentProfile::Kind::Office), EnvironmentProfileStore::SaveResult::SettingsError);
        EXPECT_EQ(reopened.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::SettingsError);
        expectUnchanged(settings, path, before);
    }
}

TEST(EnvironmentProfileStoreTests, CompleteUnpromotedGenerationIsIgnoredAndPointerTamperFailsClosed)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings);
    ASSERT_EQ(initial.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    const QString original = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
    const QString orphan = QStringLiteral("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    const QString originalPrefix = QStringLiteral("environmentProfiles/generations/") + original + QLatin1Char('/');
    const QString orphanPrefix = QStringLiteral("environmentProfiles/generations/") + orphan + QLatin1Char('/');
    const QStringList keys = settings.allKeys();
    for (const QString& key : keys) {
        if (key.startsWith(originalPrefix))
            settings.setValue(orphanPrefix + key.mid(originalPrefix.size()), settings.value(key));
    }
    settings.setValue(orphanPrefix + QStringLiteral("activeKind"), QStringLiteral("office"));
    settings.sync();

    QSettings ignoredSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore ignored(ignoredSettings);
    ASSERT_EQ(ignored.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(ignored.currentGeneration(), original);
    EXPECT_EQ(ignored.activeKind(), EnvironmentProfile::Kind::Home);

    settings.setValue(QStringLiteral("environmentProfiles/activeGeneration"), orphan);
    settings.sync();
    QSettings promotedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore promoted(promotedSettings);
    EXPECT_EQ(promoted.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_TRUE(promoted.profiles().isEmpty());
}

TEST(EnvironmentProfileStoreTests, FailedGenerationSyncPreservesPreviousDataAfterReopen)
{
    QTemporaryDir directory; const QString path = settingsFile(directory); QString previous;
    { QSettings settings(path, QSettings::IniFormat); EnvironmentProfileStore store(settings);
      ASSERT_EQ(store.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
      previous = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString(); }
    { QSettings settings(path, QSettings::IniFormat); EnvironmentProfileStore failing(settings, [](QSettings&) { return false; });
      auto changed = validProfile(EnvironmentProfile::Kind::Office); changed.devices[0].requestedResources = DevicePermissions::AutoConnect;
      EXPECT_EQ(failing.replaceProfile(changed), EnvironmentProfileStore::SaveResult::SettingsError);
      EXPECT_EQ(settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString(), previous); }
    QSettings settings(path, QSettings::IniFormat); EnvironmentProfileStore reopened(settings);
    EXPECT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(reopened.profile(EnvironmentProfile::Kind::Office)->devices[0].requestedResources,
              validProfile().devices[0].requestedResources);
}

TEST(EnvironmentProfileStoreTests, FailedPromotionSyncRollsBackDurably)
{
    QTemporaryDir directory; const QString path = settingsFile(directory); QString previous;
    { QSettings settings(path, QSettings::IniFormat); EnvironmentProfileStore store(settings);
      ASSERT_EQ(store.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
      previous = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString(); }
    { QSettings settings(path, QSettings::IniFormat); int syncCount = 0;
      EnvironmentProfileStore failing(settings, [&](QSettings& value) {
          ++syncCount; value.sync(); if (syncCount == 3) return false; return value.status() == QSettings::NoError;
      });
      EXPECT_EQ(failing.setActive(EnvironmentProfile::Kind::Travel), EnvironmentProfileStore::SaveResult::SettingsError);
      EXPECT_EQ(syncCount, 4);
      EXPECT_EQ(settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString(), previous); }
    QSettings settings(path, QSettings::IniFormat); EnvironmentProfileStore reopened(settings);
    EXPECT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(reopened.activeKind(), EnvironmentProfile::Kind::Home);
}

TEST(EnvironmentProfileStoreTests, CorruptNewGenerationIsRejectedBeforePromotion)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
    EnvironmentProfileStore initial(settings); ASSERT_EQ(initial.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    const QString previous = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
    bool corrupted = false;
    EnvironmentProfileStore failing(settings, [&](QSettings& value) {
        value.sync();
        if (!corrupted) {
            value.beginGroup(QStringLiteral("environmentProfiles/generations"));
            const QStringList groups = value.childGroups(); value.endGroup();
            for (const QString& group : groups) if (group != previous) {
                value.setValue(QStringLiteral("environmentProfiles/generations/") + group + QStringLiteral("/profiles/size"), QStringLiteral("4"));
                corrupted = true;
            }
            if (corrupted) value.sync();
        }
        return value.status() == QSettings::NoError;
    });
    EXPECT_EQ(failing.setActive(EnvironmentProfile::Kind::Office), EnvironmentProfileStore::SaveResult::SettingsError);
    EXPECT_EQ(settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString(), previous);
}

TEST(EnvironmentProfileStoreTests, RecoversUniquePreviousGenerationWhenActiveIsCorrupted)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore store(settings);
    ASSERT_EQ(store.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    const QString previous = store.currentGeneration().value();
    ASSERT_EQ(store.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::Success);
    const QString corrupted = store.currentGeneration().value();
    ASSERT_NE(corrupted, previous);

    settings.setValue(
        QStringLiteral("environmentProfiles/generations/%1/profiles/size").arg(corrupted),
        QStringLiteral("4"));
    settings.sync();

    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(reopenedSettings);
    ASSERT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_EQ(reopened.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::Recovered);
    EXPECT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(reopened.currentGeneration(), previous);
    EXPECT_EQ(reopened.activeKind(), EnvironmentProfile::Kind::Home);
    EXPECT_EQ(reopenedSettings.value(
                  QStringLiteral("environmentProfiles/activeGeneration")).toString(),
              previous);
}

TEST(EnvironmentProfileStoreTests, RecoversStructurallyValidActiveGenerationWithInvalidAuthenticatedTag)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore store(settings);
    ASSERT_EQ(store.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    const QString previous = store.currentGeneration().value();
    ASSERT_EQ(store.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::Success);
    const QString corrupted = store.currentGeneration().value();

    settings.setValue(
        QStringLiteral("environmentProfiles/generations/%1/activeKind").arg(corrupted),
        EnvironmentProfile::key(EnvironmentProfile::Kind::Travel));
    settings.sync();

    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(reopenedSettings);
    ASSERT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_EQ(reopened.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::Recovered);
    EXPECT_EQ(reopened.currentGeneration(), previous);
    EXPECT_EQ(reopened.activeKind(), EnvironmentProfile::Kind::Home);
}

TEST(EnvironmentProfileStoreTests, RecoveryRejectsPhysicalRootPointerMismatch)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore store(settings);
    ASSERT_EQ(store.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    const QString previous = store.currentGeneration().value();
    ASSERT_EQ(store.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::Success);
    const QString corrupted = store.currentGeneration().value();

    settings.setValue(
        QStringLiteral("environmentProfiles/generations/%1/profiles/size").arg(corrupted),
        QStringLiteral("4"));
    settings.setValue(QStringLiteral("environmentProfiles/activeGeneration"), previous);
    settings.sync();
    const SettingsSnapshot before = snapshot(settings, path);

    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(reopenedSettings);
    ASSERT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_EQ(reopened.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::Unavailable);
    expectUnchanged(reopenedSettings, path, before);
}

TEST(EnvironmentProfileStoreTests,
     AuthenticatedRecoveryRejectsCraftedGenerationContent)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore store(settings);
    ASSERT_EQ(store.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    const QString previous = store.currentGeneration().value();
    ASSERT_EQ(store.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::Success);
    const QString active = store.currentGeneration().value();

    settings.setValue(
        QStringLiteral("environmentProfiles/generations/%1/activeKind").arg(previous),
        EnvironmentProfile::key(EnvironmentProfile::Kind::Travel));
    settings.setValue(
        QStringLiteral("environmentProfiles/generations/%1/profiles/size").arg(active),
        QStringLiteral("4"));
    settings.sync();
    const QVariant manifestBefore = settings.value(
        QStringLiteral("environmentProfiles/manifest"));

    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(reopenedSettings);
    ASSERT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_EQ(reopened.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::Unavailable);
    EXPECT_EQ(reopenedSettings.value(
                  QStringLiteral("environmentProfiles/activeGeneration")).toString(),
              active);
    EXPECT_EQ(reopenedSettings.value(QStringLiteral("environmentProfiles/manifest")),
              manifestBefore);
}

TEST(EnvironmentProfileStoreTests, SchemaTwoWithoutAuthenticatedManifestIsRejected)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore store(settings);
    ASSERT_EQ(store.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    const QString active = store.currentGeneration().value();
    settings.remove(QStringLiteral("environmentProfiles/manifest"));
    settings.sync();

    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(reopenedSettings);
    EXPECT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_EQ(reopened.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::Unavailable);
    EXPECT_EQ(reopenedSettings.value(
                  QStringLiteral("environmentProfiles/activeGeneration")).toString(),
              active);
    EXPECT_FALSE(reopenedSettings.contains(
        QStringLiteral("environmentProfiles/manifest")));
}

TEST(EnvironmentProfileStoreTests, CompensationPreservesKnownGoodRecoveryAndDiscardsAbortedGeneration)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore store(settings);
    ASSERT_EQ(store.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    const QString knownGood = store.currentGeneration().value();

    const auto attempted = store.setActiveIfGeneration(
        EnvironmentProfile::Kind::Office, knownGood);
    ASSERT_EQ(attempted.result, EnvironmentProfileStore::SaveResult::Success);
    const QString aborted = attempted.resultingGeneration;
    ASSERT_NE(aborted, knownGood);

    const auto compensated = store.setActiveIfGeneration(
        EnvironmentProfile::Kind::Home, aborted, knownGood);
    ASSERT_EQ(compensated.result, EnvironmentProfileStore::SaveResult::Success);
    const QString compensation = compensated.resultingGeneration;
    ASSERT_NE(compensation, aborted);
    EXPECT_EQ(settings.value(
                  QStringLiteral("environmentProfiles/recoveryGeneration")).toString(),
              knownGood);

    settings.beginGroup(QStringLiteral("environmentProfiles/generations"));
    const QStringList generations = settings.childGroups();
    settings.endGroup();
    EXPECT_TRUE(generations.contains(knownGood));
    EXPECT_TRUE(generations.contains(compensation));
    EXPECT_FALSE(generations.contains(aborted));

    settings.setValue(
        QStringLiteral("environmentProfiles/generations/%1/profiles/size")
            .arg(compensation),
        QStringLiteral("4"));
    settings.sync();

    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(reopenedSettings);
    ASSERT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_EQ(reopened.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::Recovered);
    EXPECT_EQ(reopened.currentGeneration(), knownGood);
    EXPECT_EQ(reopened.activeKind(), EnvironmentProfile::Kind::Home);
}

TEST(EnvironmentProfileStoreTests, RecoveryNeverPromotesAnUncommittedOrphan)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings);
    ASSERT_EQ(initial.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    const QString active = initial.currentGeneration().value();
    const QString orphan = QStringLiteral("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    const QString activePrefix =
        QStringLiteral("environmentProfiles/generations/%1/").arg(active);
    const QString orphanPrefix =
        QStringLiteral("environmentProfiles/generations/%1/").arg(orphan);
    for (const QString& key : settings.allKeys()) {
        if (key.startsWith(activePrefix))
            settings.setValue(orphanPrefix + key.mid(activePrefix.size()),
                              settings.value(key));
    }
    settings.setValue(activePrefix + QStringLiteral("profiles/size"),
                      QStringLiteral("4"));
    settings.sync();

    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(reopenedSettings);
    ASSERT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_EQ(reopened.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::Unavailable);
    EXPECT_EQ(reopenedSettings.value(
                  QStringLiteral("environmentProfiles/activeGeneration")).toString(),
              active);
}

TEST(EnvironmentProfileStoreTests, RecoveryIsFailClosedForUntrustedStateAndIgnoresOrphans)
{
    {
        QTemporaryDir directory;
        const QString path = settingsFile(directory);
        QSettings settings(path, QSettings::IniFormat);
        EnvironmentProfileStore store(settings);
        ASSERT_EQ(store.initializeFromLegacy(validProfile()),
                  EnvironmentProfileStore::SaveResult::Success);
        EXPECT_EQ(store.recoverLastValidGeneration(),
                  EnvironmentProfileStore::RecoveryResult::NotNeeded);
    }

    {
        QTemporaryDir directory;
        const QString path = settingsFile(directory);
        QSettings settings(path, QSettings::IniFormat);
        EnvironmentProfileStore store(settings);
        ASSERT_EQ(store.initializeFromLegacy(validProfile()),
                  EnvironmentProfileStore::SaveResult::Success);
        settings.setValue(QStringLiteral("environmentProfiles/activeGeneration"),
                          QStringLiteral("../../not-trusted"));
        settings.sync();
        const SettingsSnapshot before = snapshot(settings, path);
        QSettings reopenedSettings(path, QSettings::IniFormat);
        EnvironmentProfileStore reopened(reopenedSettings);
        EXPECT_EQ(reopened.recoverLastValidGeneration(),
                  EnvironmentProfileStore::RecoveryResult::Unavailable);
        expectUnchanged(reopenedSettings, path, before);
    }

    {
        QTemporaryDir directory;
        const QString path = settingsFile(directory);
        QSettings settings(path, QSettings::IniFormat);
        EnvironmentProfileStore store(settings);
        ASSERT_EQ(store.initializeFromLegacy(validProfile()),
                  EnvironmentProfileStore::SaveResult::Success);
        ASSERT_EQ(store.setActive(EnvironmentProfile::Kind::Office),
                  EnvironmentProfileStore::SaveResult::Success);
        const QString failed = store.currentGeneration().value();
        settings.setValue(
            QStringLiteral("environmentProfiles/generations/%1/profiles/size").arg(failed),
            QStringLiteral("4"));

        settings.beginGroup(QStringLiteral("environmentProfiles/generations"));
        const QStringList existing = settings.childGroups();
        settings.endGroup();
        const QString source = *std::find_if(existing.cbegin(), existing.cend(),
                                             [&failed](const QString& value) {
            return value != failed;
        });
        const QString second = QStringLiteral("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        const QString sourcePrefix =
            QStringLiteral("environmentProfiles/generations/%1/").arg(source);
        const QString secondPrefix =
            QStringLiteral("environmentProfiles/generations/%1/").arg(second);
        for (const QString& key : settings.allKeys()) {
            if (key.startsWith(sourcePrefix))
                settings.setValue(secondPrefix + key.mid(sourcePrefix.size()),
                                  settings.value(key));
        }
        settings.sync();

        QSettings reopenedSettings(path, QSettings::IniFormat);
        EnvironmentProfileStore reopened(reopenedSettings);
        EXPECT_EQ(reopened.recoverLastValidGeneration(),
                  EnvironmentProfileStore::RecoveryResult::Recovered);
        EXPECT_EQ(reopenedSettings.value(
                      QStringLiteral("environmentProfiles/activeGeneration")).toString(),
                  source);
    }

    {
        QTemporaryDir directory;
        const QString path = settingsFile(directory);
        QSettings settings(path, QSettings::IniFormat);
        settings.setValue(QStringLiteral("environmentProfiles/schemaVersion"),
                          EnvironmentProfileStore::SchemaVersion + 1);
        settings.setValue(QStringLiteral("environmentProfiles/futurePayload"),
                          QStringLiteral("untouched"));
        settings.sync();
        const SettingsSnapshot before = snapshot(settings, path);
        EnvironmentProfileStore store(settings);
        EXPECT_EQ(store.recoverLastValidGeneration(),
                  EnvironmentProfileStore::RecoveryResult::ReadOnlyFutureSchema);
        expectUnchanged(settings, path, before);
    }
}

TEST(EnvironmentProfileStoreTests, RecoveryRollsBackFailedPointerPromotion)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings);
    ASSERT_EQ(initial.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    const QString previous = initial.currentGeneration().value();
    ASSERT_EQ(initial.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::Success);
    const QString failed = initial.currentGeneration().value();
    settings.setValue(
        QStringLiteral("environmentProfiles/generations/%1/profiles/size").arg(failed),
        QStringLiteral("4"));
    settings.sync();

    int syncCount = 0;
    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore recovering(reopenedSettings, [&](QSettings& value) {
        ++syncCount;
        value.sync();
        return syncCount != 2 && value.status() == QSettings::NoError;
    });
    EXPECT_EQ(recovering.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::SettingsError);
    EXPECT_EQ(reopenedSettings.value(
                  QStringLiteral("environmentProfiles/activeGeneration")).toString(),
              failed);
    EXPECT_NE(reopenedSettings.value(
                  QStringLiteral("environmentProfiles/activeGeneration")).toString(),
              previous);
}

TEST(EnvironmentProfileStoreTests, LiteralSchemaOneFixtureLoadsWithoutMutation)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    const QString generation = seedLiteralSchemaOneFixture(settings);
    const SettingsSnapshot before = snapshot(settings, path);

    EnvironmentProfileStore store(settings);
    ASSERT_EQ(store.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(store.currentGeneration(), generation);
    EXPECT_EQ(store.activeKind(), EnvironmentProfile::Kind::Home);
    ASSERT_EQ(store.profiles().size(), 4);
    for (const auto& profile : store.profiles())
        EXPECT_TRUE(profile.isValid());
    expectUnchanged(settings, path, before);
}

TEST(EnvironmentProfileStoreTests, LoadsSchemaOneAndMigratesOnNextSuccessfulPromotion)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    const QString original = seedLiteralSchemaOneFixture(settings);
    const SettingsSnapshot schemaOne = snapshot(settings, path);

    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(reopenedSettings);
    ASSERT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(reopened.currentGeneration(), original);
    expectUnchanged(reopenedSettings, path, schemaOne);

    ASSERT_EQ(reopened.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::Success);
    const QString promoted = reopened.currentGeneration().value();
    EXPECT_NE(promoted, original);
    EXPECT_EQ(reopenedSettings.value(
                  QStringLiteral("environmentProfiles/schemaVersion")).toInt(),
              EnvironmentProfileStore::SchemaVersion);
    EXPECT_EQ(reopenedSettings.value(
                  QStringLiteral("environmentProfiles/recoveryGeneration")).toString(),
              original);
}

TEST(EnvironmentProfileStoreTests, RejectsSchemaOneDowngradeWhenAuthenticationKeyExists)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings);
    ASSERT_EQ(initial.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    const QString original = initial.currentGeneration().value();

    settings.setValue(QStringLiteral("environmentProfiles/schemaVersion"),
                      EnvironmentProfileStore::OldestSupportedSchemaVersion);
    settings.remove(QStringLiteral("environmentProfiles/recoveryGeneration"));
    settings.remove(QStringLiteral("environmentProfiles/manifest"));
    settings.setValue(
        QStringLiteral("environmentProfiles/generations/%1/schemaVersion").arg(original),
        EnvironmentProfileStore::OldestSupportedSchemaVersion);
    settings.sync();
    const SettingsSnapshot downgraded = snapshot(settings, path);

    QSettings reopenedSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore reopened(
        reopenedSettings, {}, {}, [] { return true; });
    EXPECT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EXPECT_EQ(reopened.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::Unavailable);
    expectUnchanged(reopenedSettings, path, downgraded);
}

TEST(EnvironmentProfileStoreTests, MalformedRecoveryMetadataIsReadOnlyAndFailClosed)
{
    const QList<QVariant> malformed{
        QStringLiteral("../../escape"),
        QStringLiteral("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        7
    };
    for (const QVariant& value : malformed) {
        QTemporaryDir directory;
        const QString path = settingsFile(directory);
        QSettings settings(path, QSettings::IniFormat);
        EnvironmentProfileStore initial(settings);
        ASSERT_EQ(initial.initializeFromLegacy(validProfile()),
                  EnvironmentProfileStore::SaveResult::Success);
        settings.setValue(QStringLiteral("environmentProfiles/manifest"), value);
        settings.sync();
        const SettingsSnapshot before = snapshot(settings, path);

        QSettings reopenedSettings(path, QSettings::IniFormat);
        EnvironmentProfileStore reopened(reopenedSettings);
        EXPECT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
        EXPECT_EQ(reopened.recoverLastValidGeneration(),
                  EnvironmentProfileStore::RecoveryResult::Unavailable);
        expectUnchanged(reopenedSettings, path, before);
    }
}

TEST(EnvironmentProfileStoreTests, GarbageCollectionFailureDoesNotUndoConfirmedPromotion)
{
    QTemporaryDir directory; const QString path = settingsFile(directory); QSettings settings(path, QSettings::IniFormat);
    int syncCount = 0;
    EnvironmentProfileStore store(settings, [&](QSettings& value) {
        ++syncCount; value.sync(); return syncCount != 13 && value.status() == QSettings::NoError;
    });
    ASSERT_EQ(store.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    ASSERT_EQ(store.setActive(EnvironmentProfile::Kind::Presentation), EnvironmentProfileStore::SaveResult::Success);
    EXPECT_EQ(store.setActive(EnvironmentProfile::Kind::Travel), EnvironmentProfileStore::SaveResult::Success);
    EXPECT_EQ(syncCount, 13);
    QSettings reopenedSettings(path, QSettings::IniFormat); EnvironmentProfileStore reopened(reopenedSettings);
    EXPECT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(reopened.activeKind(), EnvironmentProfile::Kind::Travel);
}

TEST(EnvironmentProfileStoreTests, StaleWritersRebaseWithoutLosingIndependentChanges)
{
    QTemporaryDir directory; const QString path = settingsFile(directory);
    QSettings firstSettings(path, QSettings::IniFormat), secondSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore first(firstSettings);
    ASSERT_EQ(first.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    EnvironmentProfileStore stale(secondSettings);
    auto office = validProfile(EnvironmentProfile::Kind::Office);
    office.devices[0].requestedResources = DevicePermissions::AutoConnect;
    ASSERT_EQ(first.replaceProfile(office), EnvironmentProfileStore::SaveResult::Success);
    ASSERT_EQ(stale.setActive(EnvironmentProfile::Kind::Travel), EnvironmentProfileStore::SaveResult::Success);
    QSettings reopenedSettings(path, QSettings::IniFormat); EnvironmentProfileStore reopened(reopenedSettings);
    ASSERT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(reopened.activeKind(), EnvironmentProfile::Kind::Travel);
    ASSERT_TRUE(reopened.profile(EnvironmentProfile::Kind::Office));
    EXPECT_EQ(reopened.profile(EnvironmentProfile::Kind::Office)->devices[0].requestedResources, DevicePermissions::AutoConnect);
    const QString active = reopenedSettings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
    reopenedSettings.beginGroup(QStringLiteral("environmentProfiles/generations"));
    const QStringList generations = reopenedSettings.childGroups(); reopenedSettings.endGroup();
    EXPECT_TRUE(generations.contains(active)); EXPECT_LE(generations.size(), 2);
}

TEST(EnvironmentProfileStoreTests, PartialNamespaceAndUnknownKeysAreInvalidSchema)
{
    const QStringList suffixes = {QStringLiteral("activeGeneration"), QStringLiteral("payload"), QStringLiteral("generations/secretBlob")};
    for (const QString& suffix : suffixes) {
        QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
        settings.setValue(QStringLiteral("environmentProfiles/") + suffix, QByteArray("secret")); settings.sync();
        EnvironmentProfileStore store(settings);
        EXPECT_EQ(store.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema) << suffix.toStdString();
    }
    const QStringList unknownSuffixes = {QStringLiteral("unknown"), QStringLiteral("generations/%1/unknown"),
        QStringLiteral("generations/%1/profiles/1/secret"), QStringLiteral("generations/%1/profiles/1/devices/1/password"),
        QStringLiteral("generations/%1/profiles/1/layout/extension/opaque"),
        QStringLiteral("generations/%1/profiles/1/layout/extension/devices/1/token"),
        QStringLiteral("generations/%1/profiles/1/layout/extension/devices/1/monitors/1/privateKey")};
    for (const QString& pattern : unknownSuffixes) {
        QTemporaryDir directory; const QString path = settingsFile(directory); QSettings settings(path, QSettings::IniFormat);
        EnvironmentProfileStore initial(settings); ASSERT_EQ(initial.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
        const QString generation = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
        settings.setValue(QStringLiteral("environmentProfiles/") + pattern.arg(generation), QByteArray("secret")); settings.sync();
        QSettings reopenedSettings(path, QSettings::IniFormat); EnvironmentProfileStore reopened(reopenedSettings);
        EXPECT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema) << pattern.toStdString();
    }
}

TEST(EnvironmentProfileStoreTests, RejectsNonCanonicalGenerationIdentifiers)
{
    const QStringList invalid = {QStringLiteral("ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF"),
        QStringLiteral("{abcdefab-cdef-4abc-8def-abcdefabcdef}"), QStringLiteral("short"),
        QString(4096, QLatin1Char('a')), QStringLiteral("../../escape")};
    for (const QString& generation : invalid) {
        QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
        settings.setValue(QStringLiteral("environmentProfiles/schemaVersion"), 1);
        settings.setValue(QStringLiteral("environmentProfiles/activeGeneration"), generation); settings.sync();
        EnvironmentProfileStore store(settings);
        EXPECT_EQ(store.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema) << generation.left(80).toStdString();
    }
}

TEST(EnvironmentProfileStoreTests, RejectsSettingsWithExternalCurrentGroup)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
    settings.beginGroup(QStringLiteral("external")); EnvironmentProfileStore store(settings);
    EXPECT_EQ(store.loadStatus(), EnvironmentProfileStore::LoadStatus::SettingsError);
    EXPECT_EQ(store.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::SettingsError);
    EXPECT_EQ(settings.group(), QStringLiteral("external")); settings.endGroup();
    EXPECT_TRUE(settings.allKeys().isEmpty());
}

TEST(EnvironmentProfileStoreTests, InitializeIsExplicitlyIdempotent)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
    EnvironmentProfileStore store(settings);
    ASSERT_EQ(store.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    const QString active = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
    EXPECT_EQ(store.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::AlreadyInitialized);
    EXPECT_EQ(settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString(), active);
}

TEST(EnvironmentProfileStoreTests, FalsePromotionReportWithConfirmedRollbackIsSettingsError)
{
    QTemporaryDir directory; const QString path = settingsFile(directory); QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings); ASSERT_EQ(initial.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    const QString previous = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
    int syncCalls = 0;
    bool promotionFailed = false;
    EnvironmentProfileStore store(settings, [&](QSettings& value) {
        ++syncCalls;
        value.sync();
        const QString active = value.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
        if (!promotionFailed && active != previous) { promotionFailed = true; return false; }
        return value.status() == QSettings::NoError;
    });
    EXPECT_EQ(store.setActive(EnvironmentProfile::Kind::Office), EnvironmentProfileStore::SaveResult::SettingsError);
    EXPECT_TRUE(promotionFailed);
    EXPECT_EQ(syncCalls, 4);
    QSettings reopenedSettings(path, QSettings::IniFormat); EnvironmentProfileStore reopened(reopenedSettings);
    EXPECT_EQ(reopened.activeKind(), EnvironmentProfile::Kind::Home);
}

TEST(EnvironmentProfileStoreTests, FalsePromotionAndFalseRollbackReportAreIndeterminate)
{
    QTemporaryDir directory; const QString path = settingsFile(directory); QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings); ASSERT_EQ(initial.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    const QString previous = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
    int syncCalls = 0;
    bool promotionFailed = false;
    EnvironmentProfileStore store(settings, [&](QSettings& value) {
        ++syncCalls;
        value.sync();
        const QString active = value.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
        if (!promotionFailed && active != previous) { promotionFailed = true; return false; }
        if (promotionFailed) return false;
        return value.status() == QSettings::NoError;
    });
    EXPECT_EQ(store.setActive(EnvironmentProfile::Kind::Office), EnvironmentProfileStore::SaveResult::IndeterminateState);
    EXPECT_TRUE(promotionFailed);
    EXPECT_EQ(syncCalls, 4);
    EXPECT_NE(store.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);
}

TEST(EnvironmentProfileStoreTests, UnconfirmableRollbackReturnsIndeterminateAndReloadsCache)
{
    QTemporaryDir directory; const QString path = settingsFile(directory); QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings); ASSERT_EQ(initial.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    const QString previous = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
    bool sabotaged = false;
    EnvironmentProfileStore store(settings, [&](QSettings& value) {
        const QString active = value.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
        if (!sabotaged && !active.isEmpty() && active != previous) {
            value.sync();
            if (value.status() != QSettings::NoError) return false;
            QSettings durable(path, QSettings::IniFormat); durable.remove(QStringLiteral("environmentProfiles/activeGeneration")); durable.sync(); sabotaged = true;
            return false;
        }
        if (sabotaged) {
            QSettings durable(path, QSettings::IniFormat);
            durable.setValue(QStringLiteral("environmentProfiles/activeGeneration"), QStringLiteral("invalid"));
            durable.sync();
            return false;
        }
        value.sync(); return value.status() == QSettings::NoError;
    });
    EXPECT_EQ(store.setActive(EnvironmentProfile::Kind::Office), EnvironmentProfileStore::SaveResult::IndeterminateState);
    EXPECT_TRUE(sabotaged); EXPECT_NE(store.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);
}

TEST(EnvironmentProfileStoreTests, IndeterminateLatchBlocksMutationsUntilExplicitRecovery)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings);
    ASSERT_EQ(initial.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    const QString previous = settings.value(
        QStringLiteral("environmentProfiles/activeGeneration")).toString();
    bool promotionFailed = false;
    bool backendRecovered = false;
    EnvironmentProfileStore store(settings, [&](QSettings& value) {
        value.sync();
        const QString active = value.value(
            QStringLiteral("environmentProfiles/activeGeneration")).toString();
        if (!promotionFailed && active != previous) {
            promotionFailed = true;
            return false;
        }
        if (promotionFailed && !backendRecovered)
            return false;
        return value.status() == QSettings::NoError;
    });

    ASSERT_EQ(store.setActive(EnvironmentProfile::Kind::Office),
              EnvironmentProfileStore::SaveResult::IndeterminateState);
    backendRecovered = true;

    EXPECT_EQ(store.setActive(EnvironmentProfile::Kind::Travel),
              EnvironmentProfileStore::SaveResult::SettingsError);
    EXPECT_EQ(store.recoverLastValidGeneration(),
              EnvironmentProfileStore::RecoveryResult::NotNeeded);
    EXPECT_EQ(store.setActive(EnvironmentProfile::Kind::Travel),
              EnvironmentProfileStore::SaveResult::Success);
}

TEST(EnvironmentProfileStoreTests, IndeterminateMissingInitializationRemainsLatched)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    int syncCalls = 0;
    bool backendRecovered = false;
    EnvironmentProfileStore store(settings, [&](QSettings& value) {
        ++syncCalls;
        if (syncCalls == 2) {
            value.remove(QStringLiteral("environmentProfiles"));
            value.sync();
            return false;
        }
        value.sync();
        if (syncCalls == 3 && !backendRecovered)
            return false;
        return value.status() == QSettings::NoError;
    });

    ASSERT_EQ(store.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::IndeterminateState);
    backendRecovered = true;
    ASSERT_EQ(store.load(), EnvironmentProfileStore::LoadStatus::Missing);

    EXPECT_EQ(store.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::SettingsError);
    EXPECT_EQ(store.loadStatus(), EnvironmentProfileStore::LoadStatus::Missing);
}

TEST(EnvironmentProfileStoreTests, PrepromotionFailureCleansTransientGeneration)
{
    QTemporaryDir directory; const QString path = settingsFile(directory); QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings); ASSERT_EQ(initial.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    const QString previous = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
    int syncCalls = 0;
    EnvironmentProfileStore store(settings, [&](QSettings& value) {
        ++syncCalls; value.sync(); return syncCalls != 2 && value.status() == QSettings::NoError;
    });
    EXPECT_EQ(store.setActive(EnvironmentProfile::Kind::Presentation), EnvironmentProfileStore::SaveResult::SettingsError);
    QSettings durable(path, QSettings::IniFormat); durable.beginGroup(QStringLiteral("environmentProfiles/generations"));
    EXPECT_EQ(durable.childGroups(), QStringList({previous})); durable.endGroup();
}

TEST(EnvironmentProfileStoreTests, LoadsValidActiveGenerationDespitePartialAndManyCanonicalOrphans)
{
    QTemporaryDir directory; const QString path = settingsFile(directory); QSettings settings(path, QSettings::IniFormat);
    EnvironmentProfileStore initial(settings); ASSERT_EQ(initial.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    const QString active = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
    for (int i = 0; i < 17; ++i) {
        const QString orphan = QUuid::createUuid().toString(QUuid::WithoutBraces);
        if (i == 0) settings.setValue(QStringLiteral("environmentProfiles/generations/") + orphan + QStringLiteral("/partial"), true);
        else settings.setValue(QStringLiteral("environmentProfiles/generations/") + orphan + QStringLiteral("/corrupt/payload"), i);
    }
    settings.sync();

    QSettings reopenedSettings(path, QSettings::IniFormat); EnvironmentProfileStore reopened(reopenedSettings);
    ASSERT_EQ(reopened.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(reopened.activeKind(), EnvironmentProfile::Kind::Home);
    ASSERT_EQ(reopened.setActive(EnvironmentProfile::Kind::Travel), EnvironmentProfileStore::SaveResult::Success);
    reopenedSettings.beginGroup(QStringLiteral("environmentProfiles/generations"));
    const QStringList remaining = reopenedSettings.childGroups(); reopenedSettings.endGroup();
    EXPECT_LE(remaining.size(), 2);
    EXPECT_TRUE(remaining.contains(active));
}

TEST(EnvironmentProfileStoreTests, RejectsNonCanonicalPersistedProfileAndLayoutUuids)
{
    const QStringList invalidUuids = {
        QStringLiteral("{11111111-1111-1111-1111-111111111111}"),
        QStringLiteral("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")};
    for (const QString& invalid : invalidUuids) {
        QTemporaryDir directory; const QString path = settingsFile(directory); QSettings settings(path, QSettings::IniFormat);
        EnvironmentProfileStore initial(settings); ASSERT_EQ(initial.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
        const QString active = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
        const QString prefix = QStringLiteral("environmentProfiles/generations/") + active + QStringLiteral("/profiles/1/");
        settings.setValue(prefix + QStringLiteral("devices/1/uuid"), invalid); settings.sync();
        QSettings profileSettings(path, QSettings::IniFormat); EnvironmentProfileStore profileStore(profileSettings);
        EXPECT_EQ(profileStore.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);

        settings.setValue(prefix + QStringLiteral("devices/1/uuid"), firstUuid.toString(QUuid::WithoutBraces));
        settings.setValue(prefix + QStringLiteral("layout/extension/devices/1/uuid"), invalid); settings.sync();
        QSettings layoutSettings(path, QSettings::IniFormat); EnvironmentProfileStore layoutStore(layoutSettings);
        EXPECT_EQ(layoutStore.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    }
}

TEST(EnvironmentProfileStoreTests, IniLockIdentityIsCanonicalAdjacentAndIndependentOfApplicationName)
{
    QTemporaryDir directory;
    ASSERT_TRUE(QDir().mkpath(directory.filePath(QStringLiteral("real/sub"))));
    const QString canonical = directory.filePath(QStringLiteral("real/profiles.ini"));
    { QSettings seed(canonical, QSettings::IniFormat); seed.setValue(QStringLiteral("sentinel"), 1); seed.sync(); }
    const QString alias = directory.filePath(QStringLiteral("real/sub/../profiles.ini"));
    QSettings first(canonical, QSettings::IniFormat), second(alias, QSettings::IniFormat);
    const QString originalName = QCoreApplication::applicationName();
    const QString firstLock = EnvironmentProfileStore::lockFilePathForSettings(first);
    QCoreApplication::setApplicationName(QStringLiteral("other-app-name"));
    const QString secondLock = EnvironmentProfileStore::lockFilePathForSettings(second);
    QCoreApplication::setApplicationName(originalName);
    EXPECT_EQ(firstLock, secondLock);
    EXPECT_EQ(QFileInfo(firstLock).absolutePath().toLower(), QFileInfo(canonical).canonicalPath().toLower());
}

TEST(EnvironmentProfileStoreTests, MissingIniUsesCanonicalParentForAliasLockIdentity)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString realDirectory = directory.filePath(QStringLiteral("real"));
    const QString aliasDirectory = directory.filePath(QStringLiteral("alias"));
    ASSERT_TRUE(QDir().mkpath(realDirectory));

    std::error_code error;
#ifdef Q_OS_WIN
    QProcess junction;
    junction.start(QStringLiteral("cmd.exe"),
                   {QStringLiteral("/d"), QStringLiteral("/c"),
                    QStringLiteral("mklink"), QStringLiteral("/J"),
                    QDir::toNativeSeparators(aliasDirectory),
                    QDir::toNativeSeparators(realDirectory)});
    ASSERT_TRUE(junction.waitForFinished());
    ASSERT_EQ(junction.exitCode(), 0) << junction.readAllStandardError().toStdString();
#else
    std::filesystem::create_directory_symlink(
        std::filesystem::path(realDirectory.toStdString()),
        std::filesystem::path(aliasDirectory.toStdString()), error);
    if (error)
        GTEST_SKIP() << "directory symlinks unavailable: " << error.message();
#endif

    const QString canonical = QDir(realDirectory).filePath(QStringLiteral("profiles.ini"));
    const QString alias = QDir(aliasDirectory).filePath(QStringLiteral("profiles.ini"));
    ASSERT_FALSE(QFileInfo::exists(canonical));
    QSettings first(canonical, QSettings::IniFormat);
    QSettings second(alias, QSettings::IniFormat);

    const QString firstLock = EnvironmentProfileStore::lockFilePathForSettings(first);
    const QString secondLock = EnvironmentProfileStore::lockFilePathForSettings(second);
    EXPECT_EQ(firstLock, secondLock)
        << "firstPath=" << first.fileName().toStdString() << " firstLock="
        << firstLock.toStdString() << " secondPath=" << second.fileName().toStdString()
        << " secondLock=" << secondLock.toStdString();
}

TEST(EnvironmentProfileStoreTests, SyncCallbackReentrancyFailsFast)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
    EnvironmentProfileStore* storeAddress = nullptr;
    EnvironmentProfileStore store(settings, [&](QSettings& value) {
        if (storeAddress) EXPECT_EQ(storeAddress->setActive(EnvironmentProfile::Kind::Office),
                                    EnvironmentProfileStore::SaveResult::SettingsError);
        value.sync(); return value.status() == QSettings::NoError;
    });
    storeAddress = &store;
    EXPECT_EQ(store.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
}

TEST(EnvironmentProfileStoreTests, GenerationCasRejectsStaleActivationWithoutWriting)
{
    QTemporaryDir directory; const QString path = settingsFile(directory);
    QSettings firstSettings(path, QSettings::IniFormat), staleSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore first(firstSettings);
    ASSERT_EQ(first.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    EnvironmentProfileStore stale(staleSettings);
    const QString staleGeneration = *stale.currentGeneration();
    auto office = validProfile(EnvironmentProfile::Kind::Office);
    office.devices[0].requestedResources = DevicePermissions::AutoConnect;
    ASSERT_EQ(first.replaceProfile(office), EnvironmentProfileStore::SaveResult::Success);
    const QByteArray before = bytes(path);

    const auto mutation = stale.setActiveIfGeneration(EnvironmentProfile::Kind::Travel, staleGeneration);

    EXPECT_EQ(mutation.result, EnvironmentProfileStore::SaveResult::ConcurrentModification);
    EXPECT_TRUE(mutation.promotedProfile == std::nullopt);
    EXPECT_NE(mutation.resultingGeneration, staleGeneration);
    EXPECT_EQ(bytes(path), before);
    QSettings reopenedSettings(path, QSettings::IniFormat); EnvironmentProfileStore reopened(reopenedSettings);
    EXPECT_EQ(reopened.activeKind(), EnvironmentProfile::Kind::Home);
    EXPECT_EQ(reopened.profile(EnvironmentProfile::Kind::Office)->devices[0].requestedResources,
              DevicePermissions::AutoConnect);
}

TEST(EnvironmentProfileStoreTests, SuccessfulCasReturnsExactPromotedSnapshotAndGeneration)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
    EnvironmentProfileStore store(settings);
    ASSERT_EQ(store.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    const QString previous = *store.currentGeneration();

    const auto mutation = store.setActiveIfGeneration(EnvironmentProfile::Kind::Office, previous);

    ASSERT_EQ(mutation.result, EnvironmentProfileStore::SaveResult::Success);
    EXPECT_EQ(mutation.previousGeneration, previous);
    EXPECT_FALSE(mutation.resultingGeneration.isEmpty());
    EXPECT_NE(mutation.resultingGeneration, previous);
    ASSERT_TRUE(mutation.promotedProfile);
    EXPECT_EQ(mutation.promotedProfile->kind, EnvironmentProfile::Kind::Office);
    expectSameProfile(*mutation.promotedProfile, *store.profile(EnvironmentProfile::Kind::Office));
    EXPECT_EQ(store.currentGeneration(), mutation.resultingGeneration);
    EXPECT_EQ(store.verifyGeneration(mutation.resultingGeneration), EnvironmentProfileStore::SaveResult::Success);
}

TEST(EnvironmentProfileStoreTests, VerifiedSnapshotIsConsumedWhileStoreLockRemainsHeld)
{
    QTemporaryDir directory;
    QSettings settings(settingsFile(directory), QSettings::IniFormat);
    EnvironmentProfileStore store(settings);
    ASSERT_EQ(store.initializeFromLegacy(validProfile()),
              EnvironmentProfileStore::SaveResult::Success);
    const QString expected = *store.currentGeneration();
    bool consumed = false;

    const auto result = store.consumeVerifiedGeneration(
        expected,
        [&](const EnvironmentProfileStore::VerifiedState& state) {
            QLockFile competing(EnvironmentProfileStore::lockFilePathForSettings(settings));
            competing.setStaleLockTime(30000);
            EXPECT_FALSE(competing.tryLock(0));
            EXPECT_EQ(state.generation, expected);
            EXPECT_EQ(state.activeKind, EnvironmentProfile::Kind::Home);
            EXPECT_EQ(state.profile.kind, state.activeKind);
            EXPECT_TRUE(state.profile.isValid());
            consumed = true;
            return true;
        });

    EXPECT_EQ(result, EnvironmentProfileStore::SaveResult::Success);
    EXPECT_TRUE(consumed);
}

TEST(EnvironmentProfileStoreTests, SecondProcessBlocksDuringOwnershipAndRecoversAfterHolderDeath)
{
#ifndef INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH
    FAIL() << "process fixture helper path was not registered for guimodeltests";
#else
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString lockPath = directory.filePath(QStringLiteral("configuration-transaction.lock"));
    const QString helper = QStringLiteral(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH);
    QProcess holder;
    holder.setProgram(helper);
    holder.setArguments({QStringLiteral("--hold-configuration-lock"), lockPath});
    holder.start();
    ASSERT_TRUE(holder.waitForStarted(5000));
    ASSERT_TRUE(holder.waitForReadyRead(5000));
    ASSERT_EQ(holder.readLine().trimmed(), QByteArray("READY"));
    ASSERT_TRUE(QFileInfo::exists(lockPath));

    QProcess blocked;
    blocked.start(helper, {QStringLiteral("--try-configuration-lock"), QStringLiteral("100"), lockPath});
    ASSERT_TRUE(blocked.waitForFinished(5000));
    EXPECT_EQ(blocked.readAllStandardOutput().trimmed(), QByteArray("BLOCKED"));

    holder.kill();
    ASSERT_TRUE(holder.waitForFinished(5000));

    QProcess recovered;
    recovered.start(helper, {QStringLiteral("--try-configuration-lock"), QStringLiteral("5000"), lockPath});
    ASSERT_TRUE(recovered.waitForFinished(10000));
    EXPECT_EQ(recovered.readAllStandardOutput().trimmed(), QByteArray("LOCKED"));
#endif
}

TEST(EnvironmentProfileStoreTests, ReplaceCasProtectsCaptureFromStaleWriter)
{
    QTemporaryDir directory; const QString path = settingsFile(directory);
    QSettings firstSettings(path, QSettings::IniFormat), staleSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore first(firstSettings);
    ASSERT_EQ(first.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    EnvironmentProfileStore stale(staleSettings);
    const QString expected = *stale.currentGeneration();
    ASSERT_EQ(first.setActive(EnvironmentProfile::Kind::Travel), EnvironmentProfileStore::SaveResult::Success);
    auto replacement = validProfile(EnvironmentProfile::Kind::Office);
    replacement.devices[0].requestedResources = DevicePermissions::None;

    const auto mutation = stale.replaceProfileIfGeneration(replacement, expected);

    EXPECT_EQ(mutation.result, EnvironmentProfileStore::SaveResult::ConcurrentModification);
    QSettings reopenedSettings(path, QSettings::IniFormat); EnvironmentProfileStore reopened(reopenedSettings);
    EXPECT_EQ(reopened.activeKind(), EnvironmentProfile::Kind::Travel);
    EXPECT_NE(reopened.profile(EnvironmentProfile::Kind::Office)->devices[0].requestedResources,
              DevicePermissions::None);
}

TEST(EnvironmentProfileStoreTests, ReplaceAllCasPersistsExactlyFourCanonicalProfilesAndActiveKind)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
    EnvironmentProfileStore store(settings);
    ASSERT_EQ(store.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    const QString previous = *store.currentGeneration();
    QList<EnvironmentProfile> replacements;
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        auto profile = validProfile(kind);
        if (kind == EnvironmentProfile::Kind::Office)
            profile.devices[0].requestedResources = DevicePermissions::None;
        replacements.push_back(profile);
    }

    const auto mutation = store.replaceAllIfGeneration(
        replacements, EnvironmentProfile::Kind::Travel, previous);

    ASSERT_EQ(mutation.result, EnvironmentProfileStore::SaveResult::Success);
    EXPECT_EQ(mutation.previousGeneration, previous);
    EXPECT_NE(mutation.resultingGeneration, previous);
    EXPECT_EQ(store.activeKind(), EnvironmentProfile::Kind::Travel);
    ASSERT_EQ(store.profiles().size(), 4);
    for (const auto& expected : replacements)
        expectSameProfile(*store.profile(expected.kind), expected);
}

TEST(EnvironmentProfileStoreTests, ReplaceAllRejectsDuplicateKindsWithoutMutation)
{
    QTemporaryDir directory; const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat); EnvironmentProfileStore store(settings);
    ASSERT_EQ(store.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    QList<EnvironmentProfile> invalid;
    for (int index = 0; index < 4; ++index)
        invalid.push_back(validProfile(EnvironmentProfile::Kind::Home));
    const SettingsSnapshot before = snapshot(settings, path);

    const auto mutation = store.replaceAllIfGeneration(
        invalid, EnvironmentProfile::Kind::Home, *store.currentGeneration());

    EXPECT_EQ(mutation.result, EnvironmentProfileStore::SaveResult::InvalidProfile);
    expectUnchanged(settings, path, before);
}

TEST(EnvironmentProfileStoreTests, ReplaceAllCasRejectsStaleWriterWithoutMutation)
{
    QTemporaryDir directory; const QString path = settingsFile(directory);
    QSettings firstSettings(path, QSettings::IniFormat), staleSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore first(firstSettings);
    ASSERT_EQ(first.initializeFromLegacy(validProfile()), EnvironmentProfileStore::SaveResult::Success);
    EnvironmentProfileStore stale(staleSettings);
    const QString expected = *stale.currentGeneration();
    ASSERT_EQ(first.setActive(EnvironmentProfile::Kind::Office), EnvironmentProfileStore::SaveResult::Success);
    QList<EnvironmentProfile> replacements;
    for (const auto kind : EnvironmentProfile::canonicalKinds())
        replacements.push_back(validProfile(kind));
    const QByteArray before = bytes(path);

    const auto mutation = stale.replaceAllIfGeneration(
        replacements, EnvironmentProfile::Kind::Travel, expected);

    EXPECT_EQ(mutation.result, EnvironmentProfileStore::SaveResult::ConcurrentModification);
    EXPECT_EQ(bytes(path), before);
}
