/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#include "DeviceInfo.h"
#include "DeviceRegistry.h"
#include "ConfigurationTransactionLock.h"

#include <gtest/gtest.h>

#include <QDateTime>
#include <QFile>
#include <QSettings>
#include <QTemporaryDir>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace
{
DeviceInfo makeDevice(const QUuid& id, const QString& name = "workstation")
{
    DeviceInfo device(id);
    device.setTechnicalName(name);
    device.setLocalAlias("Desk");
    device.setOperatingSystem("Windows");
    device.setIpAddresses({"192.0.2.10", "2001:db8::10"});
    device.setVersion("3.0.0");
    device.setCapabilities({"keyboard", "clipboard"});
    device.setTrustState(DeviceInfo::TrustState::Trusted);
    device.setLastSeen(QDateTime::fromString("2026-07-10T12:34:56Z", Qt::ISODate));
    return device;
}
QString settingsFile(QTemporaryDir& directory) { return directory.filePath("devices.ini"); }
}

TEST(DeviceRegistryTests, RejectsNullIdentity)
{
    DeviceInfo invalid;
    EXPECT_FALSE(invalid.isValid());
    QTemporaryDir directory;
    QSettings settings(settingsFile(directory), QSettings::IniFormat);
    DeviceRegistry registry(settings);
    EXPECT_EQ(registry.add(invalid), DeviceRegistry::AddResult::Rejected);
    EXPECT_TRUE(registry.devices().isEmpty());
}

TEST(DeviceRegistryTests, CreatesAndUpdatesUsingSnapshots)
{
    QTemporaryDir directory;
    QSettings settings(settingsFile(directory), QSettings::IniFormat);
    DeviceRegistry registry(settings);
    const QUuid id = registry.create("new-host");
    ASSERT_FALSE(id.isNull());
    auto found = registry.find(id);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->technicalName(), "new-host");
    found->setLocalAlias("Laptop");
    EXPECT_TRUE(registry.update(*found));
    EXPECT_EQ(registry.find(id)->localAlias(), "Laptop");
    EXPECT_TRUE(registry.remove(id));
    EXPECT_FALSE(registry.find(id).has_value());
}

TEST(DeviceRegistryTests, RediscoveryPreservesLocalAliasAndTrust)
{
    QTemporaryDir directory;
    QSettings settings(settingsFile(directory), QSettings::IniFormat);
    DeviceRegistry registry(settings);
    const QUuid id = QUuid::createUuid();
    ASSERT_EQ(registry.add(makeDevice(id, "old-name")), DeviceRegistry::AddResult::Added);
    DeviceInfo rediscovered(id);
    rediscovered.setTechnicalName("new-name");
    rediscovered.setOperatingSystem("Linux");
    EXPECT_EQ(registry.add(rediscovered), DeviceRegistry::AddResult::Merged);
    const auto result = registry.find(id);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->technicalName(), "new-name");
    EXPECT_EQ(result->operatingSystem(), "Linux");
    EXPECT_EQ(result->localAlias(), "Desk");
    EXPECT_EQ(result->trustState(), DeviceInfo::TrustState::Trusted);
}

TEST(DeviceRegistryTests, UpdateDeliberatelyChangesAliasAndTrust)
{
    QTemporaryDir directory;
    QSettings settings(settingsFile(directory), QSettings::IniFormat);
    DeviceRegistry registry(settings);
    const QUuid id = QUuid::createUuid();
    registry.add(makeDevice(id));
    DeviceInfo changed = *registry.find(id);
    changed.setLocalAlias({});
    changed.setTrustState(DeviceInfo::TrustState::Untrusted);
    ASSERT_TRUE(registry.update(changed));
    EXPECT_TRUE(registry.find(id)->localAlias().isEmpty());
    EXPECT_EQ(registry.find(id)->trustState(), DeviceInfo::TrustState::Untrusted);
}

TEST(DeviceRegistryTests, InvalidTrustStateIsNormalized)
{
    DeviceInfo device(QUuid::createUuid());
    device.setTrustState(static_cast<DeviceInfo::TrustState>(99));
    EXPECT_EQ(device.trustState(), DeviceInfo::TrustState::Unknown);
}

TEST(DeviceRegistryTests, LoadsInvalidTrustAsUnknownAndDeduplicatesPersistedUuid)
{
    QTemporaryDir directory;
    QSettings settings(settingsFile(directory), QSettings::IniFormat);
    const QUuid id = QUuid::createUuid();
    settings.setValue("deviceRegistry/schemaVersion", 1);
    settings.beginWriteArray("deviceRegistry/devices");
    settings.setArrayIndex(0); settings.setValue("uuid", id.toString()); settings.setValue("localAlias", "Keep"); settings.setValue("trustState", 77);
    settings.setArrayIndex(1); settings.setValue("uuid", id.toString()); settings.setValue("technicalName", "latest");
    settings.endArray();
    DeviceRegistry registry(settings);
    ASSERT_EQ(registry.devices().size(), 1);
    const auto device = registry.find(id);
    ASSERT_TRUE(device.has_value());
    EXPECT_EQ(device->technicalName(), "latest");
    EXPECT_EQ(device->localAlias(), "Keep");
    EXPECT_EQ(device->trustState(), DeviceInfo::TrustState::Unknown);
}

TEST(DeviceRegistryTests, SkipsMalformedPersistedUuid)
{
    QTemporaryDir directory;
    QSettings settings(settingsFile(directory), QSettings::IniFormat);
    settings.setValue("deviceRegistry/schemaVersion", 1);
    settings.beginWriteArray("deviceRegistry/devices");
    settings.setArrayIndex(0);
    settings.setValue("uuid", "definitely-not-a-uuid");
    settings.endArray();
    DeviceRegistry registry(settings);
    EXPECT_TRUE(registry.devices().isEmpty());
}

TEST(DeviceRegistryTests, FutureSchemaIsExplicitAndCannotBeOverwritten)
{
    QTemporaryDir directory;
    const QString filename = settingsFile(directory);
    QSettings settings(filename, QSettings::IniFormat);
    settings.setValue("deviceRegistry/schemaVersion", DeviceRegistry::SchemaVersion + 1);
    settings.setValue("deviceRegistry/futurePayload", "untouched");
    settings.sync();
    const QByteArray before = [&] { QFile file(filename); file.open(QIODevice::ReadOnly); return file.readAll(); }();
    DeviceRegistry registry(settings);
    EXPECT_EQ(registry.loadStatus(), DeviceRegistry::LoadStatus::FutureSchema);
    EXPECT_TRUE(registry.devices().isEmpty());
    EXPECT_EQ(registry.add(makeDevice(QUuid::createUuid())), DeviceRegistry::AddResult::Error);
    EXPECT_EQ(registry.save(), DeviceRegistry::SaveResult::FutureSchema);
    settings.sync();
    QFile file(filename); file.open(QIODevice::ReadOnly);
    EXPECT_EQ(file.readAll(), before);
}

TEST(DeviceRegistryTests, VersionOneEmptyRegistryNeverMigratesLegacyData)
{
    QTemporaryDir directory;
    QSettings settings(settingsFile(directory), QSettings::IniFormat);
    const QUuid legacyId = QUuid::createUuid();
    settings.setValue("deviceRegistry/schemaVersion", 1);
    settings.beginWriteArray("deviceRegistry/devices"); settings.endArray();
    settings.beginWriteArray("recentDestinations"); settings.setArrayIndex(0); settings.setValue("uuid", legacyId.toString()); settings.endArray();
    DeviceRegistry registry(settings);
    EXPECT_TRUE(registry.devices().isEmpty());
}

TEST(DeviceRegistryTests, MigrationOnlyRunsOnceAndRecordsSchema)
{
    QTemporaryDir directory;
    QSettings settings(settingsFile(directory), QSettings::IniFormat);
    const QUuid legacyId = QUuid::createUuid();
    settings.beginWriteArray("recentDestinations"); settings.setArrayIndex(0); settings.setValue("uuid", legacyId.toString()); settings.setValue("name", "legacy"); settings.endArray();
    { DeviceRegistry registry(settings); ASSERT_TRUE(registry.find(legacyId).has_value()); }
    EXPECT_EQ(settings.value("deviceRegistry/schemaVersion").toInt(), DeviceRegistry::SchemaVersion);
    settings.remove("deviceRegistry/generations/" + settings.value("deviceRegistry/activeGeneration").toString() + "/devices");
    DeviceRegistry second(settings);
    EXPECT_TRUE(second.devices().isEmpty());
}

TEST(DeviceRegistryTests, ReadOnlyLoadDefersLegacyMigrationUntilPersistenceIsEnabled)
{
    QTemporaryDir directory;
    QSettings settings(settingsFile(directory), QSettings::IniFormat);
    const QUuid legacyId = QUuid::createUuid();
    settings.beginWriteArray("recentDestinations");
    settings.setArrayIndex(0);
    settings.setValue("uuid", legacyId.toString());
    settings.setValue("name", "legacy");
    settings.endArray();
    settings.sync();

    DeviceRegistry registry(settings, {}, DeviceRegistry::PersistenceMode::ReadOnly);
    EXPECT_TRUE(registry.find(legacyId).has_value());
    EXPECT_FALSE(settings.contains("deviceRegistry/schemaVersion"));
    EXPECT_FALSE(settings.contains("deviceRegistry/activeGeneration"));

    ASSERT_TRUE(registry.enablePersistence());
    EXPECT_EQ(settings.value("deviceRegistry/schemaVersion").toInt(),
              DeviceRegistry::SchemaVersion);
    EXPECT_FALSE(settings.value("deviceRegistry/activeGeneration").toString().isEmpty());
}

TEST(DeviceRegistryTests, PersistsAndReloadsEveryField)
{
    QTemporaryDir directory;
    const QString filename = settingsFile(directory);
    const QUuid id = QUuid::createUuid();
    { QSettings settings(filename, QSettings::IniFormat); DeviceRegistry registry(settings); registry.add(makeDevice(id)); EXPECT_EQ(registry.save(), DeviceRegistry::SaveResult::Success); }
    { QSettings settings(filename, QSettings::IniFormat); DeviceRegistry registry(settings); const auto device = registry.find(id); ASSERT_TRUE(device.has_value()); EXPECT_EQ(device->localAlias(), "Desk"); EXPECT_EQ(device->ipAddresses(), QStringList({"192.0.2.10", "2001:db8::10"})); EXPECT_EQ(device->trustState(), DeviceInfo::TrustState::Trusted); }
}

TEST(DeviceRegistryTests, ReportsSettingsWriteFailure)
{
    QTemporaryDir directory;
    // A directory cannot be replaced by the INI backend as a settings file.
    QSettings settings(directory.path(), QSettings::IniFormat);
    DeviceRegistry registry(settings);
    EXPECT_EQ(registry.loadStatus(), DeviceRegistry::LoadStatus::SettingsError);
    EXPECT_EQ(registry.save(), DeviceRegistry::SaveResult::SettingsError);
}

TEST(DeviceRegistryTests, PromotesAndLoadsAnImmutableGeneration)
{
    QTemporaryDir directory; const QString filename = settingsFile(directory); const QUuid id = QUuid::createUuid();
    { QSettings settings(filename, QSettings::IniFormat); DeviceRegistry registry(settings);
      EXPECT_EQ(registry.add(makeDevice(id)), DeviceRegistry::AddResult::Added); ASSERT_EQ(registry.save(), DeviceRegistry::SaveResult::Success);
      const QString generation = settings.value("deviceRegistry/activeGeneration").toString(); EXPECT_FALSE(generation.isEmpty());
      EXPECT_EQ(settings.value("deviceRegistry/generations/" + generation + "/schemaVersion").toInt(), 1); }
    { QSettings settings(filename, QSettings::IniFormat); DeviceRegistry registry(settings); EXPECT_TRUE(registry.find(id).has_value()); }
}

TEST(DeviceRegistryTests, IgnoresIncompleteInactiveGeneration)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat); DeviceRegistry registry(settings);
    const QUuid active = QUuid::createUuid(); registry.add(makeDevice(active)); ASSERT_EQ(registry.save(), DeviceRegistry::SaveResult::Success);
    settings.setValue("deviceRegistry/generations/incomplete/schemaVersion", 1);
    settings.beginWriteArray("deviceRegistry/generations/incomplete/devices"); settings.setArrayIndex(0);
    settings.setValue("uuid", QUuid::createUuid().toString()); settings.endArray(); settings.sync();
    DeviceRegistry reloaded(settings); EXPECT_EQ(reloaded.devices().size(), 1); EXPECT_TRUE(reloaded.find(active).has_value());
}

TEST(DeviceRegistryTests, RejectsTruncatedActiveGeneration)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
    const QString generation = "truncated";
    settings.setValue("deviceRegistry/schemaVersion", 1);
    settings.setValue("deviceRegistry/activeGeneration", generation);
    settings.setValue("deviceRegistry/generations/" + generation + "/schemaVersion", 1);
    settings.setValue("deviceRegistry/generations/" + generation + "/devices/1/uuid", QUuid::createUuid().toString());
    settings.sync();
    DeviceRegistry registry(settings);
    EXPECT_EQ(registry.loadStatus(), DeviceRegistry::LoadStatus::InvalidSchema);
    EXPECT_TRUE(registry.devices().isEmpty());
    EXPECT_TRUE(registry.create("blocked").isNull());
    EXPECT_EQ(registry.save(), DeviceRegistry::SaveResult::InvalidSchema);
}

TEST(DeviceRegistryTests, ValidatesRootSchemaBeforeActiveGeneration)
{
    const QList<QPair<QVariant, DeviceRegistry::LoadStatus>> cases = {
        {DeviceRegistry::SchemaVersion + 1, DeviceRegistry::LoadStatus::FutureSchema},
        {QString("bad"), DeviceRegistry::LoadStatus::InvalidSchema},
        {DeviceRegistry::SchemaVersion - 1, DeviceRegistry::LoadStatus::InvalidSchema},
    };
    for (const auto& testCase : cases) {
        QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
        const QString generation = "valid-v1";
        settings.setValue("deviceRegistry/schemaVersion", testCase.first);
        settings.setValue("deviceRegistry/activeGeneration", generation);
        settings.setValue("deviceRegistry/generations/" + generation + "/schemaVersion", 1);
        settings.setValue("deviceRegistry/generations/" + generation + "/devices/size", 0);
        settings.setValue("deviceRegistry/payload", "preserve"); settings.sync();
        DeviceRegistry registry(settings);
        EXPECT_EQ(registry.loadStatus(), testCase.second);
        EXPECT_TRUE(registry.devices().isEmpty());
        EXPECT_EQ(registry.add(makeDevice(QUuid::createUuid())), DeviceRegistry::AddResult::Error);
        EXPECT_NE(registry.save(), DeviceRegistry::SaveResult::Success);
        EXPECT_EQ(settings.value("deviceRegistry/payload").toString(), "preserve");
    }
}

TEST(DeviceRegistryTests, RejectsNumericStringRootSchemaWithoutMutation)
{
    QTemporaryDir directory; const QString filename = settingsFile(directory);
    QSettings settings(filename, QSettings::IniFormat);
    settings.setValue("deviceRegistry/schemaVersion", QString("1"));
    settings.setValue("deviceRegistry/payload", "preserve"); settings.sync();
    const QByteArray before = [&] { QFile file(filename); file.open(QIODevice::ReadOnly); return file.readAll(); }();

    DeviceRegistry registry(settings);
    EXPECT_EQ(registry.loadStatus(), DeviceRegistry::LoadStatus::InvalidSchema);
    EXPECT_EQ(registry.add(makeDevice(QUuid::createUuid())), DeviceRegistry::AddResult::Error);
    EXPECT_EQ(registry.save(), DeviceRegistry::SaveResult::InvalidSchema);
    settings.sync();
    QFile file(filename); file.open(QIODevice::ReadOnly);
    EXPECT_EQ(file.readAll(), before);
}

TEST(DeviceRegistryTests, RejectsNumericStringGenerationSchemaWithoutMutation)
{
    QTemporaryDir directory; const QString filename = settingsFile(directory);
    QSettings settings(filename, QSettings::IniFormat); const QString generation = "active";
    settings.setValue("deviceRegistry/schemaVersion", 1);
    settings.setValue("deviceRegistry/activeGeneration", generation);
    settings.setValue("deviceRegistry/generations/" + generation + "/schemaVersion", QString("1"));
    settings.setValue("deviceRegistry/generations/" + generation + "/devices/size", 0);
    settings.setValue("deviceRegistry/payload", "preserve"); settings.sync();
    const QByteArray before = [&] { QFile file(filename); file.open(QIODevice::ReadOnly); return file.readAll(); }();

    DeviceRegistry registry(settings);
    EXPECT_EQ(registry.loadStatus(), DeviceRegistry::LoadStatus::InvalidSchema);
    EXPECT_EQ(registry.add(makeDevice(QUuid::createUuid())), DeviceRegistry::AddResult::Error);
    EXPECT_EQ(registry.save(), DeviceRegistry::SaveResult::InvalidSchema);
    settings.sync();
    QFile file(filename); file.open(QIODevice::ReadOnly);
    EXPECT_EQ(file.readAll(), before);
}

TEST(DeviceRegistryTests, RejectsNumericStringActiveGenerationSizeWithoutMutation)
{
    QTemporaryDir directory; const QString filename = settingsFile(directory);
    QSettings settings(filename, QSettings::IniFormat); const QString generation = "active";
    settings.setValue("deviceRegistry/schemaVersion", 1);
    settings.setValue("deviceRegistry/activeGeneration", generation);
    settings.setValue("deviceRegistry/generations/" + generation + "/schemaVersion", 1);
    settings.setValue("deviceRegistry/generations/" + generation + "/devices/size", QString("0"));
    settings.setValue("deviceRegistry/payload", "preserve"); settings.sync();
    const QByteArray before = [&] { QFile file(filename); file.open(QIODevice::ReadOnly); return file.readAll(); }();

    DeviceRegistry registry(settings);
    EXPECT_EQ(registry.loadStatus(), DeviceRegistry::LoadStatus::InvalidSchema);
    EXPECT_EQ(registry.add(makeDevice(QUuid::createUuid())), DeviceRegistry::AddResult::Error);
    EXPECT_EQ(registry.save(), DeviceRegistry::SaveResult::InvalidSchema);
    settings.sync();
    QFile file(filename); file.open(QIODevice::ReadOnly);
    EXPECT_EQ(file.readAll(), before);
}

TEST(DeviceRegistryTests, RejectsCorruptedGenerationBeforePromotionWithoutChangingDevices)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
    const QUuid id = QUuid::createUuid();
    { DeviceRegistry initial(settings); initial.add(makeDevice(id)); ASSERT_EQ(initial.save(), DeviceRegistry::SaveResult::Success); }
    const QString previous = settings.value("deviceRegistry/activeGeneration").toString();
    int syncCount = 0;
    DeviceRegistry registry(settings, [&](QSettings& value) {
        value.sync();
        if (++syncCount == 1) {
            value.beginGroup("deviceRegistry/generations");
            const QStringList generations = value.childGroups(); value.endGroup();
            for (const QString& generation : generations) {
                if (generation != previous)
                    value.setValue("deviceRegistry/generations/" + generation + "/devices/size", "not-an-integer");
            }
        }
        return value.status() == QSettings::NoError;
    });
    ASSERT_TRUE(registry.find(id).has_value());
    DeviceInfo changed = *registry.find(id); changed.setTechnicalName("changed");
    ASSERT_TRUE(registry.update(changed));
    EXPECT_EQ(registry.save(), DeviceRegistry::SaveResult::SettingsError);
    ASSERT_EQ(registry.devices().size(), 1);
    EXPECT_EQ(registry.find(id)->technicalName(), "changed");
    EXPECT_EQ(settings.value("deviceRegistry/activeGeneration").toString(), previous);
}

TEST(DeviceRegistryTests, FailedPromotionSyncRollsBackDurablyToPreviousGeneration)
{
    QTemporaryDir directory; const QString filename = settingsFile(directory);
    const QUuid original = QUuid::createUuid(); QString previous;
    {
        QSettings settings(filename, QSettings::IniFormat); DeviceRegistry initial(settings);
        initial.add(makeDevice(original)); ASSERT_EQ(initial.save(), DeviceRegistry::SaveResult::Success);
        previous = settings.value("deviceRegistry/activeGeneration").toString();
    }
    {
        QSettings settings(filename, QSettings::IniFormat); int syncCount = 0;
        DeviceRegistry failing(settings, [&](QSettings& value) {
            ++syncCount;
            if (syncCount == 2) return false;
            value.sync(); return value.status() == QSettings::NoError;
        });
        ASSERT_TRUE(failing.find(original).has_value());
        failing.add(makeDevice(QUuid::createUuid()));
        EXPECT_EQ(failing.save(), DeviceRegistry::SaveResult::SettingsError);
        EXPECT_EQ(syncCount, 3);
        EXPECT_EQ(settings.value("deviceRegistry/activeGeneration").toString(), previous);
    }
    {
        QSettings settings(filename, QSettings::IniFormat); DeviceRegistry reloaded(settings);
        EXPECT_EQ(reloaded.loadStatus(), DeviceRegistry::LoadStatus::Loaded);
        EXPECT_EQ(reloaded.devices().size(), 1);
        EXPECT_TRUE(reloaded.find(original).has_value());
        EXPECT_EQ(settings.value("deviceRegistry/activeGeneration").toString(), previous);
    }
}

TEST(DeviceRegistryTests, FailedSavePreservesActiveGenerationAndBlocksMutations)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat); DeviceRegistry registry(settings);
    const QUuid original = QUuid::createUuid(); registry.add(makeDevice(original)); ASSERT_EQ(registry.save(), DeviceRegistry::SaveResult::Success);
    const QString active = settings.value("deviceRegistry/activeGeneration").toString();
    DeviceRegistry failing(settings, [](QSettings&) { return false; }); ASSERT_EQ(failing.loadStatus(), DeviceRegistry::LoadStatus::Loaded);
    failing.add(makeDevice(QUuid::createUuid())); EXPECT_EQ(failing.save(), DeviceRegistry::SaveResult::SettingsError);
    EXPECT_EQ(failing.saveStatus(), DeviceRegistry::SaveStatus::Error); EXPECT_EQ(settings.value("deviceRegistry/activeGeneration").toString(), active);
    EXPECT_EQ(failing.add(makeDevice(QUuid::createUuid())), DeviceRegistry::AddResult::Error);
    EXPECT_TRUE(failing.create("blocked").isNull()); EXPECT_FALSE(failing.remove(original));
    EXPECT_EQ(failing.load(), DeviceRegistry::LoadStatus::Loaded); EXPECT_NE(failing.saveStatus(), DeviceRegistry::SaveStatus::Error);
}

TEST(DeviceRegistryTests, RejectsInvalidSchemasWithoutMutation)
{
    const QList<QVariant> invalid = {QString("one"), QStringList({"invalid"}), -1, 0};
    for (const QVariant& schema : invalid) {
        QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
        settings.setValue("deviceRegistry/schemaVersion", schema); settings.setValue("deviceRegistry/payload", "keep"); settings.sync();
        DeviceRegistry registry(settings); EXPECT_EQ(registry.loadStatus(), DeviceRegistry::LoadStatus::InvalidSchema);
        EXPECT_EQ(registry.add(makeDevice(QUuid::createUuid())), DeviceRegistry::AddResult::Error);
        EXPECT_EQ(registry.save(), DeviceRegistry::SaveResult::InvalidSchema); EXPECT_EQ(settings.value("deviceRegistry/payload").toString(), "keep");
    }
}

TEST(DeviceRegistryTests, AddResultDistinguishesAllOutcomes)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat); DeviceRegistry registry(settings); const QUuid id = QUuid::createUuid();
    EXPECT_EQ(registry.add(makeDevice(id, "first")), DeviceRegistry::AddResult::Added);
    EXPECT_EQ(registry.add(makeDevice(id, "second")), DeviceRegistry::AddResult::Merged);
    EXPECT_EQ(registry.add(DeviceInfo()), DeviceRegistry::AddResult::Rejected);
    const QString active = settings.value("deviceRegistry/activeGeneration").toString();
    settings.setValue("deviceRegistry/generations/" + active + "/schemaVersion", "bad"); registry.load();
    EXPECT_EQ(registry.add(makeDevice(QUuid::createUuid())), DeviceRegistry::AddResult::Error);
}

TEST(DeviceRegistryTests, ResolveCreatesPersistsAndFindsExactTechnicalName)
{
    QTemporaryDir directory; const QString filename = settingsFile(directory); QUuid created;
    { QSettings settings(filename, QSettings::IniFormat); DeviceRegistry registry(settings);
      const auto result = registry.resolveOrCreateByTechnicalName("peer-A");
      EXPECT_EQ(result.status, DeviceRegistry::ResolveStatus::Created); ASSERT_FALSE(result.uuid.isNull()); created = result.uuid;
      EXPECT_EQ(registry.resolveOrCreateByTechnicalName("peer-A").status, DeviceRegistry::ResolveStatus::Found);
      EXPECT_NE(registry.resolveOrCreateByTechnicalName("peer-a").uuid, created); }
    QSettings settings(filename, QSettings::IniFormat); DeviceRegistry reloaded(settings);
    const auto found = reloaded.resolveOrCreateByTechnicalName("peer-A");
    EXPECT_EQ(found.status, DeviceRegistry::ResolveStatus::Found); EXPECT_EQ(found.uuid, created);
}

TEST(DeviceRegistryTests, ResolveRejectsEmptyNameWithoutMutation)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat); DeviceRegistry registry(settings);
    EXPECT_EQ(registry.resolveOrCreateByTechnicalName("").status, DeviceRegistry::ResolveStatus::Rejected);
    EXPECT_TRUE(registry.devices().isEmpty());
}

TEST(DeviceRegistryTests, ResolveSaveFailureDoesNotPublishTemporaryIdentity)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
    DeviceRegistry registry(settings, [](QSettings&) { return false; });
    const auto result = registry.resolveOrCreateByTechnicalName("peer-A");
    EXPECT_EQ(result.status, DeviceRegistry::ResolveStatus::PersistenceError);
    EXPECT_TRUE(result.uuid.isNull()); EXPECT_TRUE(registry.devices().isEmpty());
}

TEST(DeviceRegistryTests, LocalAliasIsTrimmedUnicodeRemovableAndPreservesRemoteFields)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
    DeviceRegistry registry(settings); const QUuid id = QUuid::createUuid();
    ASSERT_EQ(registry.add(makeDevice(id, "peer-tech")), DeviceRegistry::AddResult::Added);
    ASSERT_EQ(registry.save(), DeviceRegistry::SaveResult::Success);
    EXPECT_EQ(registry.setLocalAlias(id, QString::fromUtf8("  Notebook da sala 🖥️  ")), DeviceRegistry::AliasResult::Changed);
    const auto renamed = registry.find(id); ASSERT_TRUE(renamed);
    EXPECT_EQ(renamed->localAlias(), QString::fromUtf8("Notebook da sala 🖥️"));
    EXPECT_EQ(renamed->technicalName(), "peer-tech"); EXPECT_EQ(renamed->trustState(), DeviceInfo::TrustState::Trusted);
    EXPECT_EQ(registry.setLocalAlias(id, "   "), DeviceRegistry::AliasResult::Changed);
    EXPECT_TRUE(registry.find(id)->localAlias().isEmpty());
}

TEST(DeviceRegistryTests, LocalAliasRejectsUnknownInvalidControlsAndLimits)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
    DeviceRegistry registry(settings); const QUuid id = QUuid::createUuid(); registry.add(makeDevice(id));
    EXPECT_EQ(registry.setLocalAlias(QUuid::createUuid(), "Sala"), DeviceRegistry::AliasResult::UnknownDevice);
    const QList<QString> invalid = {QString(97, QChar('a')), QString(193, QChar(0x00E1)), QString("linha\nnova"),
        QString("tab\tname"), QString(QChar(0)), QString(QChar(0xD800))};
    for (const QString& value : invalid) EXPECT_EQ(registry.setLocalAlias(id, value), DeviceRegistry::AliasResult::InvalidAlias);
    EXPECT_EQ(registry.find(id)->localAlias(), "Desk");
    const char32_t formatCodePoint = 0xE0001;
    EXPECT_EQ(registry.setLocalAlias(id, QString::fromUcs4(&formatCodePoint, 1)), DeviceRegistry::AliasResult::InvalidAlias);
    const char32_t emojiCodePoint = 0x1F5A5;
    const QString emoji = QString::fromUcs4(&emojiCodePoint, 1);
    EXPECT_EQ(registry.setLocalAlias(id, emoji), DeviceRegistry::AliasResult::Changed);
    EXPECT_EQ(registry.find(id)->localAlias(), emoji);
}

TEST(DeviceRegistryTests, SameAliasDoesNotSaveAndFailedSaveRollsBack)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat);
    int syncs = 0; DeviceRegistry registry(settings, [&](QSettings& value) { ++syncs; value.sync(); return true; });
    const QUuid id = QUuid::createUuid(); registry.add(makeDevice(id)); ASSERT_EQ(registry.save(), DeviceRegistry::SaveResult::Success);
    const int before = syncs; EXPECT_EQ(registry.setLocalAlias(id, " Desk "), DeviceRegistry::AliasResult::Unchanged); EXPECT_EQ(syncs, before);
    QSettings failingSettings(directory.filePath("failure.ini"), QSettings::IniFormat);
    bool allowSync = true; DeviceRegistry failing(failingSettings, [&](QSettings& value) { if (!allowSync) return false; value.sync(); return true; });
    const QUuid failedId = QUuid::createUuid(); failing.add(makeDevice(failedId)); ASSERT_EQ(failing.save(), DeviceRegistry::SaveResult::Success);
    allowSync = false;
    EXPECT_EQ(failing.setLocalAlias(failedId, "Novo"), DeviceRegistry::AliasResult::PersistenceError);
    ASSERT_TRUE(failing.find(failedId)); EXPECT_EQ(failing.find(failedId)->localAlias(), "Desk");
}

TEST(DeviceRegistryTests, CleanupSyncFailureDoesNotRollBackDurableAlias)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings settings(path, QSettings::IniFormat);
    int syncs = 0;
    DeviceRegistry registry(settings, [&](QSettings& value) {
        ++syncs;
        value.sync();
        return syncs != 6;
    });
    const QUuid id = QUuid::createUuid();
    ASSERT_EQ(registry.add(makeDevice(id)), DeviceRegistry::AddResult::Added);
    ASSERT_EQ(registry.save(), DeviceRegistry::SaveResult::Success);
    EXPECT_EQ(registry.setLocalAlias(id, "Novo durável"), DeviceRegistry::AliasResult::Changed);
    ASSERT_TRUE(registry.find(id));
    EXPECT_EQ(registry.find(id)->localAlias(), "Novo durável");

    QSettings reloadedSettings(path, QSettings::IniFormat);
    DeviceRegistry reloaded(reloadedSettings);
    ASSERT_TRUE(reloaded.find(id));
    EXPECT_EQ(reloaded.find(id)->localAlias(), "Novo durável");
}

TEST(DeviceRegistryTests, PermissionReadWaitsForConcurrentMutationCommit)
{
    QTemporaryDir directory;
    QSettings settings(settingsFile(directory), QSettings::IniFormat);
    std::mutex mutex;
    std::condition_variable entered;
    std::condition_variable release;
    bool blockSync = false;
    bool syncEntered = false;
    bool releaseSync = false;
    DeviceRegistry registry(settings, [&](QSettings& value) {
        value.sync();
        std::unique_lock lock(mutex);
        if (blockSync) {
            syncEntered = true;
            entered.notify_one();
            release.wait(lock, [&] { return releaseSync; });
        }
        return value.status() == QSettings::NoError;
    });
    const QUuid uuid = QUuid::createUuid();
    ASSERT_EQ(registry.add(makeDevice(uuid)), DeviceRegistry::AddResult::Added);
    ASSERT_EQ(registry.save(), DeviceRegistry::SaveResult::Success);

    {
        std::lock_guard lock(mutex);
        blockSync = true;
    }
    bool writeResult = false;
    std::thread writer([&] {
        writeResult = registry.setPermissions(uuid, DevicePermissions::SendFiles);
    });
    {
        std::unique_lock lock(mutex);
        ASSERT_TRUE(entered.wait_for(lock, std::chrono::seconds(5), [&] { return syncEntered; }));
    }

    std::atomic_bool readerFinished = false;
    bool readResult = false;
    std::thread reader([&] {
        readResult = registry.allows(uuid, DevicePermissions::SendFiles);
        readerFinished.store(true, std::memory_order_release);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(readerFinished.load(std::memory_order_acquire));

    {
        std::lock_guard lock(mutex);
        releaseSync = true;
    }
    release.notify_all();
    writer.join();
    reader.join();
    EXPECT_TRUE(writeResult);
    EXPECT_TRUE(readResult);
}

TEST(DeviceRegistryTests, DuplicateAliasesRemainDistinctByUuid)
{
    QTemporaryDir directory; QSettings settings(settingsFile(directory), QSettings::IniFormat); DeviceRegistry registry(settings);
    const QUuid a=QUuid::createUuid(), b=QUuid::createUuid(); registry.add(makeDevice(a,"a")); registry.add(makeDevice(b,"b")); ASSERT_EQ(registry.save(), DeviceRegistry::SaveResult::Success);
    EXPECT_EQ(registry.setLocalAlias(a,"Mesmo"),DeviceRegistry::AliasResult::Changed); EXPECT_EQ(registry.setLocalAlias(b,"Mesmo"),DeviceRegistry::AliasResult::Changed);
    EXPECT_NE(a,b); EXPECT_EQ(registry.find(a)->localAlias(),registry.find(b)->localAlias());
}

TEST(DeviceRegistryTests, StaleInstanceCannotOverwriteNewerGeneration)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    QSettings firstSettings(path, QSettings::IniFormat);
    QSettings staleSettings(path, QSettings::IniFormat);
    DeviceRegistry first(firstSettings);
    DeviceRegistry stale(staleSettings);
    const QUuid committedId = QUuid::createUuid();
    const QUuid staleId = QUuid::createUuid();

    ASSERT_EQ(first.upsertDiscovered(makeDevice(committedId)),
              DeviceRegistry::AddResult::Added);
    EXPECT_EQ(stale.upsertDiscovered(makeDevice(staleId)),
              DeviceRegistry::AddResult::Error);

    QSettings reopenedSettings(path, QSettings::IniFormat);
    DeviceRegistry reopened(reopenedSettings);
    EXPECT_TRUE(reopened.find(committedId).has_value());
    EXPECT_FALSE(reopened.find(staleId).has_value());
}

TEST(DeviceRegistryTests, GlobalTransactionLockBlocksPersistence)
{
    QTemporaryDir directory;
    const QString path = settingsFile(directory);
    ConfigurationTransactionLock held;
    ASSERT_TRUE(held.isLocked());
    DeviceRegistry::SaveResult result = DeviceRegistry::SaveResult::Success;
    std::thread writer([&] {
        QSettings settings(path, QSettings::IniFormat);
        DeviceRegistry registry(settings);
        result = registry.save();
    });
    writer.join();
    EXPECT_EQ(result, DeviceRegistry::SaveResult::SettingsError);
    QSettings observer(path, QSettings::IniFormat);
    EXPECT_FALSE(observer.contains(
        QStringLiteral("deviceRegistry/activeGeneration")));
}
