#include "StartupSettingsPreflight.h"

#include <gtest/gtest.h>

#include <QFile>
#include <QSettings>
#include <QTemporaryDir>
#include <QUuid>

#include <limits>

namespace {
QByteArray bytes(const QString& path)
{
    QFile file(path);
    if (!file.exists())
        return {};
    EXPECT_TRUE(file.open(QIODevice::ReadOnly));
    return file.readAll();
}

TEST(StartupSettingsPreflightTests, MissingSettingsAreReportedWithoutCreatingAFile)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("missing.ini"));
    QSettings settings(path, QSettings::IniFormat);

    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::Missing);
    EXPECT_FALSE(QFile::exists(path));
}

#ifdef Q_OS_WIN
TEST(StartupSettingsPreflightTests, ExistingEmptyNativeStoreFailsClosed)
{
    const QString application = QStringLiteral("StartupSettingsPreflightTests-") +
        QUuid::createUuid().toString(QUuid::WithoutBraces);
    QSettings settings(QSettings::NativeFormat, QSettings::UserScope,
                       QStringLiteral("InputLeapTests"), application);
    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::Missing)
        << settings.fileName().toStdString();

    settings.setValue(QStringLiteral("physical-presence"), true);
    settings.sync();
    settings.remove(QStringLiteral("physical-presence"));
    settings.sync();

    EXPECT_TRUE(settings.allKeys().isEmpty());
    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::FormatError);
    settings.clear();
    settings.sync();
}
#endif

TEST(StartupSettingsPreflightTests, ValidSettingsAreReadOnly)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("valid.ini"));
    {
        QSettings seed(path, QSettings::IniFormat);
        seed.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
        seed.sync();
        ASSERT_EQ(seed.status(), QSettings::NoError);
    }
    const QByteArray before = bytes(path);
    QSettings settings(path, QSettings::IniFormat);

    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::Valid);
    EXPECT_EQ(bytes(path), before);
}

TEST(StartupSettingsPreflightTests, MalformedIniFailsClosedWithoutChangingBytes)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("malformed.ini"));
    const QByteArray malformed = QByteArrayLiteral("[broken\nkey=value\n");
    {
        QFile file(path);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
        ASSERT_EQ(file.write(malformed), malformed.size());
    }
    QSettings settings(path, QSettings::IniFormat);

    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::FormatError);
    EXPECT_EQ(bytes(path), malformed);
}

TEST(StartupSettingsPreflightTests, RejectsMalformedPortablePreferencesWithoutMutation)
{
    const QList<QPair<QString, QVariant>> corruptions{
        {QStringLiteral("port"), QStringLiteral("24800")},
        {QStringLiteral("port"), 0},
        {QStringLiteral("logLevel"), 7},
        {QStringLiteral("language"), QStringLiteral("not-supported")},
        {QStringLiteral("cryptoEnabled"), QStringLiteral("False")},
        {QStringLiteral("requireClientCertificate"), 1},
        {QStringLiteral("fileTransferPairingCode"), 123456}
    };
    for (const auto& corruption : corruptions) {
        QTemporaryDir directory;
        const QString path = directory.filePath(QStringLiteral("invalid.ini"));
        {
            QSettings seed(path, QSettings::IniFormat);
            seed.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
            seed.setValue(corruption.first, corruption.second);
            seed.sync();
        }
        const QByteArray before = bytes(path);
        QSettings settings(path, QSettings::IniFormat);
        EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
                  StartupSettingsPreflight::Status::InvalidValue)
            << corruption.first.toStdString();
        EXPECT_EQ(bytes(path), before);
    }
}

TEST(StartupSettingsPreflightTests, RejectsMalformedAppConfigPreferencesWithoutMutation)
{
    const QList<QPair<QString, QVariant>> corruptions{
        {QStringLiteral("screenName"), 7},
        {QStringLiteral("interface"), true},
        {QStringLiteral("logToFile"), 1},
        {QStringLiteral("logFilename"), false},
        {QStringLiteral("receiveDirectory"), 42},
        {QStringLiteral("wizardLastRun"), QStringLiteral("9")},
        {QStringLiteral("wizardLastRun"), 10},
        {QStringLiteral("startedBefore"), 1},
        {QStringLiteral("autoConfig"), QStringLiteral("TRUE")},
        {QStringLiteral("elevateMode"), 1},
        {QStringLiteral("elevateModeEnum"), 999},
        {QStringLiteral("autoConfigPrompted"), 0}
    };
    for (const auto& corruption : corruptions) {
        QTemporaryDir directory;
        const QString path = directory.filePath(QStringLiteral("invalid-app-config.ini"));
        {
            QSettings seed(path, QSettings::IniFormat);
            seed.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
            seed.setValue(corruption.first, corruption.second);
            seed.sync();
        }
        const QByteArray before = bytes(path);
        QSettings settings(path, QSettings::IniFormat);
        EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
                  StartupSettingsPreflight::Status::InvalidValue)
            << corruption.first.toStdString();
        EXPECT_EQ(bytes(path), before);
    }
}

TEST(StartupSettingsPreflightTests, RejectsInconsistentTransportSecurityWithoutMutation)
{
    QTemporaryDir directory;
    const QString path = directory.filePath(QStringLiteral("security.ini"));
    {
        QSettings seed(path, QSettings::IniFormat);
        seed.setValue(QStringLiteral("cryptoEnabled"), QStringLiteral("false"));
        seed.setValue(QStringLiteral("requireClientCertificate"), QStringLiteral("true"));
        seed.sync();
    }
    const QByteArray before = bytes(path);
    QSettings settings(path, QSettings::IniFormat);
    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::InvalidValue);
    EXPECT_EQ(bytes(path), before);
}

TEST(StartupSettingsPreflightTests, CanonicalLegacyBooleanStringsAreValidAndBytePreserving)
{
    QTemporaryDir directory;
    const QString path = directory.filePath(QStringLiteral("legacy-booleans.ini"));
    {
        QSettings seed(path, QSettings::IniFormat);
        seed.setValue(QStringLiteral("cryptoEnabled"), QStringLiteral("true"));
        seed.setValue(QStringLiteral("requireClientCertificate"), QStringLiteral("false"));
        seed.setValue(QStringLiteral("autoHide"), QStringLiteral("false"));
        seed.setValue(QStringLiteral("autoStart"), QStringLiteral("true"));
        seed.setValue(QStringLiteral("minimizeToTray"), QStringLiteral("true"));
        seed.sync();
    }
    const QByteArray before = bytes(path);
    QSettings settings(path, QSettings::IniFormat);
    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::Valid);
    EXPECT_EQ(bytes(path), before);
}

TEST(StartupSettingsPreflightTests, AcceptsCanonicalLegacyLanguageAliasReadOnly)
{
    QTemporaryDir directory;
    const QString path = directory.filePath(QStringLiteral("legacy-language.ini"));
    {
        QSettings seed(path, QSettings::IniFormat);
        seed.setValue(QStringLiteral("language"), QStringLiteral("pt_BR"));
        seed.sync();
    }
    const QByteArray before = bytes(path);
    QSettings settings(path, QSettings::IniFormat);
    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::Valid);
    EXPECT_EQ(bytes(path), before);
}

TEST(StartupSettingsPreflightTests, ExistingEmptyFileIsCorruptAndBytePreserving)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("empty.ini"));
    {
        QFile file(path);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    }
    QSettings settings(path, QSettings::IniFormat);

    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::FormatError);
    EXPECT_TRUE(QFile::exists(path));
    EXPECT_TRUE(bytes(path).isEmpty());
}

TEST(StartupSettingsPreflightTests, ExistingKeylessIniIsCorruptAndBytePreserving)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("comments-only.ini"));
    const QByteArray original = QByteArrayLiteral("; retained evidence\n\n");
    {
        QFile file(path);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
        ASSERT_EQ(file.write(original), original.size());
    }
    QSettings settings(path, QSettings::IniFormat);

    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::FormatError);
    EXPECT_EQ(bytes(path), original);
}

TEST(StartupSettingsPreflightTests, RejectsInternalScreenCountOutsideGridWithoutMutation)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("invalid-internal-config.ini"));
    {
        QSettings seed(path, QSettings::IniFormat);
        seed.setValue(QStringLiteral("internalConfig/numColumns"), 1);
        seed.setValue(QStringLiteral("internalConfig/numRows"), 1);
        seed.setValue(QStringLiteral("internalConfig/screens/size"), 2);
        seed.sync();
    }
    const QByteArray before = bytes(path);
    QSettings settings(path, QSettings::IniFormat);

    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::InvalidValue);
    EXPECT_EQ(bytes(path), before);
}

TEST(StartupSettingsPreflightTests, RejectsUnboundedInternalHotkeyArray)
{
    QTemporaryDir directory;
    const QString path = directory.filePath(QStringLiteral("settings.ini"));
    QSettings settings(path, QSettings::IniFormat);
    settings.setValue(QStringLiteral("internalConfig/hotkeys/size"),
                      std::numeric_limits<int>::max());
    settings.sync();
    const QByteArray before = bytes(path);

    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::InvalidValue);
    EXPECT_EQ(bytes(path), before);
}

TEST(StartupSettingsPreflightTests, RejectsInvalidInternalActionEnum)
{
    QTemporaryDir directory;
    const QString path = directory.filePath(QStringLiteral("settings.ini"));
    QSettings settings(path, QSettings::IniFormat);
    settings.setValue(QStringLiteral("internalConfig/hotkeys/size"), 1);
    settings.setValue(QStringLiteral("internalConfig/hotkeys/1/actions/size"), 1);
    settings.setValue(QStringLiteral("internalConfig/hotkeys/1/actions/1/type"), 999);
    settings.sync();
    const QByteArray before = bytes(path);

    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::InvalidValue);
    EXPECT_EQ(bytes(path), before);
}

TEST(StartupSettingsPreflightTests, RejectsUnboundedStartupConsumerArrays)
{
    const QStringList keys{
        QStringLiteral("deviceRegistry/devices/size"),
        QStringLiteral("deviceRegistry/generations/11111111-1111-1111-1111-111111111111/devices/size"),
        QStringLiteral("recentDestinations/size"),
        QStringLiteral("transferHistory/size")};
    for (const QString& key : keys) {
        QTemporaryDir directory;
        const QString path = directory.filePath(QStringLiteral("settings.ini"));
        QSettings settings(path, QSettings::IniFormat);
        settings.setValue(key, std::numeric_limits<int>::max());
        settings.sync();
        const QByteArray before = bytes(path);

        EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
                  StartupSettingsPreflight::Status::InvalidValue) << key.toStdString();
        EXPECT_EQ(bytes(path), before) << key.toStdString();
    }
}

TEST(StartupSettingsPreflightTests, FutureScreenLayoutSchemaIsRejectedBytePreserving)
{
    QTemporaryDir directory;
    const QString path = directory.filePath(QStringLiteral("settings.ini"));
    QSettings settings(path, QSettings::IniFormat);
    settings.setValue(QStringLiteral("internalConfig/screenLayoutExtension/schemaVersion"), 3);
    settings.setValue(QStringLiteral("internalConfig/screenLayoutExtension/futurePayload"),
                      QStringLiteral("preservar"));
    settings.sync();
    const QByteArray before = bytes(path);

    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::InvalidValue);
    EXPECT_EQ(bytes(path), before);
}

TEST(StartupSettingsPreflightTests, LegacyCopyExcludesPlaintextCredential)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings source(directory.filePath(QStringLiteral("legacy.ini")),
                     QSettings::IniFormat);
    QSettings destination(directory.filePath(QStringLiteral("current.ini")),
                          QSettings::IniFormat);
    source.setValue(QStringLiteral("port"), 24800);
    source.setValue(QStringLiteral("screenName"), QStringLiteral("legacy-host"));
    source.setValue(QStringLiteral("fileTransferPairingCode"),
                    QStringLiteral("[REDACTED]"));
    source.setValue(QStringLiteral("credentials/fileTransferPairingCode"),
                    QStringLiteral("[REDACTED-NESTED]"));
    source.setValue(QStringLiteral("identity/privateKey"),
                    QStringLiteral("[REDACTED-IDENTITY]"));
    source.setValue(QStringLiteral("environmentProfiles/schemaVersion"), 99);
    source.setValue(QStringLiteral("unknown/schemaVersion"), 99);
    source.sync();
    ASSERT_EQ(StartupSettingsPreflight::inspect(source),
              StartupSettingsPreflight::Status::Valid);

    EXPECT_EQ(StartupSettingsPreflight::copyLegacyPublicSettings(source, destination), 2);
    destination.sync();
    EXPECT_EQ(destination.value(QStringLiteral("port")).toInt(), 24800);
    EXPECT_EQ(destination.value(QStringLiteral("screenName")).toString(),
              QStringLiteral("legacy-host"));
    EXPECT_FALSE(destination.contains(QStringLiteral("fileTransferPairingCode")));
    EXPECT_FALSE(destination.contains(QStringLiteral("credentials/fileTransferPairingCode")));
    EXPECT_FALSE(destination.contains(QStringLiteral("identity/privateKey")));
    EXPECT_FALSE(destination.contains(QStringLiteral("environmentProfiles/schemaVersion")));
    EXPECT_FALSE(destination.contains(QStringLiteral("unknown/schemaVersion")));
    EXPECT_FALSE(bytes(destination.fileName()).contains("[REDACTED]"));
}

TEST(StartupSettingsPreflightTests, LegacyCopyDoesNotOverwriteStoreCreatedAfterMissingPreflight)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString currentPath = directory.filePath(QStringLiteral("current.ini"));
    QSettings source(directory.filePath(QStringLiteral("legacy.ini")),
                     QSettings::IniFormat);
    QSettings destination(currentPath, QSettings::IniFormat);
    source.setValue(QStringLiteral("screenName"), QStringLiteral("legacy-host"));
    source.setValue(QStringLiteral("port"), 24800);
    source.sync();
    ASSERT_EQ(StartupSettingsPreflight::inspect(source),
              StartupSettingsPreflight::Status::Valid);
    ASSERT_EQ(StartupSettingsPreflight::inspect(destination),
              StartupSettingsPreflight::Status::Missing);

    QSettings concurrentWriter(currentPath, QSettings::IniFormat);
    concurrentWriter.setValue(QStringLiteral("screenName"), QStringLiteral("current-host"));
    concurrentWriter.setValue(QStringLiteral("port"), 24801);
    concurrentWriter.sync();
    ASSERT_EQ(concurrentWriter.status(), QSettings::NoError);

    EXPECT_EQ(StartupSettingsPreflight::copyLegacyPublicSettings(source, destination), 0);
    destination.sync();
    EXPECT_EQ(destination.value(QStringLiteral("screenName")).toString(),
              QStringLiteral("current-host"));
    EXPECT_EQ(destination.value(QStringLiteral("port")).toInt(), 24801);
}
} // namespace
