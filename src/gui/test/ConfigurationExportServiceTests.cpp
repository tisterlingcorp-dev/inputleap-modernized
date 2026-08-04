#include "ConfigurationExportService.h"
#include "ConfigurationSensitiveEnvelope.h"
#include "ConfigurationSensitivePayload.h"

#include <gtest/gtest.h>

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QTemporaryDir>

#if defined(Q_OS_WIN)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace {
ConfigurationPublicSnapshot exportSnapshot()
{
    ConfigurationPublicSnapshot snapshot;
    const QUuid uuid(QStringLiteral("{11111111-1111-1111-1111-111111111111}"));
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        ScreenLayout::Device layoutDevice{uuid, QStringLiteral("desktop"), QRect(0, 0, 100, 100),
                                           {{QStringLiteral("display"), QRect(0, 0, 100, 100), 1.0,
                                             Qt::PrimaryOrientation, false}}};
        EnvironmentProfile profile;
        profile.kind = kind;
        profile.layout = {1, 1, {QStringLiteral("desktop")}, ScreenLayout({layoutDevice})};
        profile.devices = {{uuid, QStringLiteral("desktop"), DevicePermissions::ControlMouseKeyboard}};
        snapshot.environmentProfiles.profiles.push_back(profile);
    }
    snapshot.environmentProfiles.activeKind = EnvironmentProfile::Kind::Home;
    return snapshot;
}

TEST(ConfigurationExportServiceTests, PublicExportNeverReadsSensitiveProvider)
{
    int reads = 0;
    ConfigurationExportService::Options options;
    const auto result = ConfigurationExportService::build(
        exportSnapshot(), options, [&] {
            ++reads;
            return ConfigurationExportService::SensitiveData{
                true, SensitiveBytes(QByteArrayLiteral("secret"))};
        });

    ASSERT_EQ(result.error, ConfigurationExportService::Error::None);
    EXPECT_EQ(reads, 0);
    ASSERT_TRUE(result.package.has_value());
    const auto package = ConfigurationPackageCodec::decode(*result.package);
    ASSERT_EQ(package.error, ConfigurationPackageCodec::Error::None);
    ASSERT_TRUE(package.package);
    EXPECT_FALSE(package.package->sensitive.has_value());
    EXPECT_EQ(ConfigurationPublicSnapshotCodec::decode(package.package->publicData).error,
              ConfigurationPublicSnapshotCodec::Error::None);
}

TEST(ConfigurationExportServiceTests, ExplicitSensitiveExportEncryptsOnlyAuthorizedPairingCode)
{
    int reads = 0;
    ConfigurationExportService::Options options;
    options.includeSensitive = true;
    SensitiveBytes password(QByteArrayLiteral("backup-password"));
    options.password = &password;
    const auto result = ConfigurationExportService::build(
        exportSnapshot(), options, [&] {
            ++reads;
            return ConfigurationExportService::SensitiveData{
                true, SensitiveBytes(QByteArrayLiteral("PAIR-CODE-123"))};
        });

    ASSERT_EQ(result.error, ConfigurationExportService::Error::None);
    EXPECT_EQ(reads, 1);
    ASSERT_TRUE(result.package);
    EXPECT_FALSE(result.package->contains(QByteArrayLiteral("PAIR-CODE-123")));
    const auto package = ConfigurationPackageCodec::decode(*result.package);
    ASSERT_TRUE(package.package && package.package->sensitive);
    const QByteArray publicBytes = QJsonDocument(package.package->publicData).toJson(QJsonDocument::Compact);
    const QByteArray digest = QCryptographicHash::hash(publicBytes, QCryptographicHash::Sha256);
    const auto decrypted = ConfigurationSensitiveEnvelope::decrypt(
        *package.package->sensitive, password, digest);
    ASSERT_EQ(decrypted.error, ConfigurationSensitiveEnvelope::Error::None);
    ASSERT_TRUE(decrypted.plaintext);
    const auto sensitive = ConfigurationSensitivePayload::decode(*decrypted.plaintext);
    ASSERT_TRUE(sensitive.snapshot && sensitive.snapshot->pairingCode);
    EXPECT_EQ(sensitive.snapshot->pairingCode->bytes(), QByteArrayLiteral("PAIR-CODE-123"));
}

TEST(ConfigurationExportServiceTests, SensitiveConsentWithoutPasswordOrSecretFailsBeforePackage)
{
    int reads = 0;
    ConfigurationExportService::Options options;
    options.includeSensitive = true;
    auto result = ConfigurationExportService::build(
        exportSnapshot(), options, [&] {
            ++reads;
            return ConfigurationExportService::SensitiveData{
                true, SensitiveBytes(QByteArrayLiteral("secret"))};
        });
    EXPECT_EQ(result.error, ConfigurationExportService::Error::PasswordRequired);
    EXPECT_EQ(reads, 0);

    SensitiveBytes password(QByteArrayLiteral("password"));
    options.password = &password;
    result = ConfigurationExportService::build(
        exportSnapshot(), options, [&] {
            ++reads;
            return ConfigurationExportService::SensitiveData{};
        });
    EXPECT_EQ(result.error, ConfigurationExportService::Error::SensitiveDataUnavailable);
    EXPECT_EQ(reads, 1);
}

TEST(ConfigurationExportServiceTests, AtomicWriteCanBeReadBackAndInvalidDestinationFails)
{
    const auto package = ConfigurationExportService::build(exportSnapshot(), {}, {});
    ASSERT_TRUE(package.package);
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("backup.ilconfig"));

    EXPECT_EQ(ConfigurationExportService::writeAtomically(path, *package.package),
              ConfigurationExportService::Error::None);
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::ReadOnly));
    EXPECT_EQ(file.readAll(), *package.package);
    EXPECT_EQ(ConfigurationPackageCodec::decode(*package.package).error,
              ConfigurationPackageCodec::Error::None);

    EXPECT_EQ(ConfigurationExportService::writeAtomically(
                  directory.filePath(QStringLiteral("missing/backup.ilconfig")), *package.package),
              ConfigurationExportService::Error::FileOpenFailed);
}

TEST(ConfigurationExportServiceTests, NoClobberWritePreservesExistingDestination)
{
    const auto package = ConfigurationExportService::build(exportSnapshot(), {}, {});
    ASSERT_TRUE(package.package);
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("automatic-backup.ilconfig"));
    QFile existing(path);
    ASSERT_TRUE(existing.open(QIODevice::WriteOnly));
    ASSERT_EQ(existing.write(QByteArrayLiteral("ORIGINAL")), 8);
    existing.close();

    EXPECT_EQ(ConfigurationExportService::writeAtomically(
                  path, *package.package, false),
              ConfigurationExportService::Error::FileCommitFailed);
    QFile preserved(path);
    ASSERT_TRUE(preserved.open(QIODevice::ReadOnly));
    EXPECT_EQ(preserved.readAll(), QByteArrayLiteral("ORIGINAL"));
}

#if defined(Q_OS_WIN)
TEST(ConfigurationExportServiceTests, CommitFailurePreservesDestinationAndLeavesNoTemporaryResidue)
{
    const auto package = ConfigurationExportService::build(exportSnapshot(), {}, {});
    ASSERT_TRUE(package.package);
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("backup.ilconfig"));
    QFile existing(path);
    ASSERT_TRUE(existing.open(QIODevice::WriteOnly));
    ASSERT_EQ(existing.write(QByteArrayLiteral("ORIGINAL")), 8);
    existing.close();
    const QStringList before = QDir(directory.path()).entryList(
        QDir::Files | QDir::Hidden | QDir::NoDotAndDotDot);

    const HANDLE lockedDestination = CreateFileW(
        reinterpret_cast<LPCWSTR>(path.utf16()), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(lockedDestination, INVALID_HANDLE_VALUE);

    const auto result = ConfigurationExportService::writeAtomically(
        path, *package.package);
    CloseHandle(lockedDestination);

    EXPECT_EQ(result, ConfigurationExportService::Error::FileCommitFailed);
    QFile preserved(path);
    ASSERT_TRUE(preserved.open(QIODevice::ReadOnly));
    EXPECT_EQ(preserved.readAll(), QByteArrayLiteral("ORIGINAL"));
    EXPECT_EQ(QDir(directory.path()).entryList(
                  QDir::Files | QDir::Hidden | QDir::NoDotAndDotDot), before);
}
#endif

} // namespace
