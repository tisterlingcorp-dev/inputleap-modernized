#include "ConfigurationImportPreview.h"
#include "ConfigurationExportService.h"
#include "ConfigurationSensitiveEnvelope.h"

#include <gtest/gtest.h>

#include <QCryptographicHash>
#include <QJsonDocument>

namespace {
ConfigurationPublicSnapshot previewSnapshot(const QString& language = QStringLiteral("pt-BR"),
                                            int logLevel = 3)
{
    ConfigurationPublicSnapshot snapshot;
    snapshot.preferences = *ConfigurationPortablePreferences::create(
        24800, logLevel, language, true, false, false, false, false);
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

TEST(ConfigurationImportPreviewTests, PublicPreviewReportsExactChangesWithoutSensitiveData)
{
    const auto current = previewSnapshot(QStringLiteral("en"));
    auto candidate = previewSnapshot(QStringLiteral("pt-BR"), 5);
    candidate.environmentProfiles.profiles[1].devices[0].requestedResources |=
        DevicePermissions::ShareClipboard;
    const auto exported = ConfigurationExportService::build(candidate);
    ASSERT_TRUE(exported.package);

    const auto preview = ConfigurationImportPreview::create(*exported.package, current, {});

    ASSERT_EQ(preview.error, ConfigurationImportPreview::Error::None);
    ASSERT_TRUE(preview.preview);
    EXPECT_EQ(preview.preview->summary.preferenceChanges, 2);
    EXPECT_EQ(preview.preview->summary.profileChanges, 1);
    EXPECT_EQ(preview.preview->summary.profileCount, 4);
    EXPECT_EQ(preview.preview->summary.deviceReferences, 4);
    EXPECT_FALSE(preview.preview->summary.includesPairingCode);
    EXPECT_FALSE(preview.preview->summary.authenticated);
    EXPECT_EQ(preview.preview->summary.pairingCodeAction,
              ConfigurationImportPreview::Summary::PairingCodeAction::Preserve);
    EXPECT_FALSE(preview.preview->candidate.sensitive.has_value());
    EXPECT_EQ(preview.preview->candidate.snapshot.preferences.language(), QStringLiteral("pt-BR"));
}

TEST(ConfigurationImportPreviewTests, PreviewExplicitlyFlagsTransportSecurityDowngrade)
{
    auto current = previewSnapshot();
    current.preferences = *ConfigurationPortablePreferences::create(
        24800, 3, QStringLiteral("pt-BR"), true, true, false, false, false);
    auto candidate = previewSnapshot();
    candidate.preferences = *ConfigurationPortablePreferences::create(
        24800, 3, QStringLiteral("pt-BR"), false, false, false, false, false);
    const auto exported = ConfigurationExportService::build(candidate);
    ASSERT_TRUE(exported.package);

    const auto preview = ConfigurationImportPreview::create(*exported.package, current, {});

    ASSERT_EQ(preview.error, ConfigurationImportPreview::Error::None);
    ASSERT_TRUE(preview.preview);
    EXPECT_TRUE(preview.preview->summary.weakensTransportSecurity);
}

TEST(ConfigurationImportPreviewTests, SensitivePreviewRequiresPasswordAndNeverExposesItInSummary)
{
    ConfigurationExportService::Options options;
    options.includeSensitive = true;
    SensitiveBytes password(QByteArrayLiteral("backup-password"));
    options.password = &password;
    const auto exported = ConfigurationExportService::build(
        previewSnapshot(), options,
        [] {
            return ConfigurationExportService::SensitiveData{
                true, SensitiveBytes(QByteArrayLiteral("PAIR-CODE"))};
        });
    ASSERT_TRUE(exported.package);

    EXPECT_EQ(ConfigurationImportPreview::create(*exported.package, previewSnapshot(), {}).error,
              ConfigurationImportPreview::Error::PasswordRequired);
    const auto preview = ConfigurationImportPreview::create(
        *exported.package, previewSnapshot(), password);
    ASSERT_EQ(preview.error, ConfigurationImportPreview::Error::None);
    ASSERT_TRUE(preview.preview);
    EXPECT_TRUE(preview.preview->summary.includesPairingCode);
    EXPECT_TRUE(preview.preview->summary.authenticated);
    EXPECT_EQ(preview.preview->summary.pairingCodeAction,
              ConfigurationImportPreview::Summary::PairingCodeAction::Set);
    ASSERT_TRUE(preview.preview->candidate.sensitive &&
                preview.preview->candidate.sensitive->pairingCode);
    EXPECT_EQ(preview.preview->candidate.sensitive->pairingCode->bytes(),
              QByteArrayLiteral("PAIR-CODE"));
}

TEST(ConfigurationImportPreviewTests, AuthenticatedAbsentSecretExplicitlyMeansClear)
{
    SensitiveBytes password(QByteArrayLiteral("password"));
    ConfigurationExportService::Options options{true, &password};
    const auto exported = ConfigurationExportService::build(
        previewSnapshot(), options,
        [] { return ConfigurationExportService::SensitiveData{true, std::nullopt}; });
    ASSERT_TRUE(exported.package);

    const auto preview = ConfigurationImportPreview::create(
        *exported.package, previewSnapshot(), password);

    ASSERT_EQ(preview.error, ConfigurationImportPreview::Error::None);
    ASSERT_TRUE(preview.preview && preview.preview->candidate.sensitive);
    EXPECT_TRUE(preview.preview->summary.authenticated);
    EXPECT_FALSE(preview.preview->summary.includesPairingCode);
    EXPECT_EQ(preview.preview->summary.pairingCodeAction,
              ConfigurationImportPreview::Summary::PairingCodeAction::Clear);
    EXPECT_FALSE(preview.preview->candidate.sensitive->pairingCode.has_value());
}

TEST(ConfigurationImportPreviewTests, RemovedEnvelopeIsExplicitlyUnauthenticated)
{
    SensitiveBytes password(QByteArrayLiteral("password"));
    ConfigurationExportService::Options options{true, &password};
    const auto exported = ConfigurationExportService::build(
        previewSnapshot(), options,
        [] {
            return ConfigurationExportService::SensitiveData{
                true, SensitiveBytes(QByteArrayLiteral("PAIR-CODE"))};
        });
    ASSERT_TRUE(exported.package);
    auto package = ConfigurationPackageCodec::decode(*exported.package);
    ASSERT_TRUE(package.package && package.package->sensitive);
    package.package->sensitive.reset();

    const auto preview = ConfigurationImportPreview::create(
        ConfigurationPackageCodec::encode(*package.package), previewSnapshot(), {});

    ASSERT_EQ(preview.error, ConfigurationImportPreview::Error::None);
    ASSERT_TRUE(preview.preview);
    EXPECT_FALSE(preview.preview->summary.authenticated);
    EXPECT_EQ(preview.preview->summary.pairingCodeAction,
              ConfigurationImportPreview::Summary::PairingCodeAction::Preserve);
}

TEST(ConfigurationImportPreviewTests, PublicTamperingInvalidatesBoundSensitiveSection)
{
    SensitiveBytes password(QByteArrayLiteral("password"));
    ConfigurationExportService::Options options{true, &password};
    const auto exported = ConfigurationExportService::build(
        previewSnapshot(), options,
        [] {
            return ConfigurationExportService::SensitiveData{
                true, SensitiveBytes(QByteArrayLiteral("PAIR-CODE"))};
        });
    ASSERT_TRUE(exported.package);
    auto package = ConfigurationPackageCodec::decode(*exported.package);
    ASSERT_TRUE(package.package && package.package->sensitive);
    QJsonObject preferences = package.package->publicData.value(QStringLiteral("preferences")).toObject();
    preferences.insert(QStringLiteral("language"), QStringLiteral("en"));
    package.package->publicData.insert(QStringLiteral("preferences"), preferences);
    const QByteArray tampered = ConfigurationPackageCodec::encode(*package.package);

    EXPECT_EQ(ConfigurationImportPreview::create(tampered, previewSnapshot(), password).error,
              ConfigurationImportPreview::Error::SensitiveAuthenticationFailed);
}

TEST(ConfigurationImportPreviewTests, MalformedPackageAndInvalidPublicSnapshotFailClosed)
{
    EXPECT_EQ(ConfigurationImportPreview::create(QByteArrayLiteral("{"), previewSnapshot(), {}).error,
              ConfigurationImportPreview::Error::InvalidPackage);

    auto exported = ConfigurationExportService::build(previewSnapshot());
    ASSERT_TRUE(exported.package);
    auto package = ConfigurationPackageCodec::decode(*exported.package);
    ASSERT_TRUE(package.package);
    package.package->publicData.insert(QStringLiteral("credentials"), QJsonObject{});
    EXPECT_EQ(ConfigurationImportPreview::create(
                  ConfigurationPackageCodec::encode(*package.package), previewSnapshot(), {}).error,
              ConfigurationImportPreview::Error::InvalidPublicSnapshot);
}

TEST(ConfigurationImportPreviewTests, AuthenticatedInvalidUtf8SensitivePayloadFailsClosed)
{
    const QJsonObject publicObject = ConfigurationPublicSnapshotCodec::encode(previewSnapshot());
    const QByteArray publicBytes = QJsonDocument(publicObject).toJson(QJsonDocument::Compact);
    const QByteArray digest = QCryptographicHash::hash(publicBytes, QCryptographicHash::Sha256);
    SensitiveBytes password(QByteArrayLiteral("password"));
    const QByteArray invalidPayload = QByteArray::fromHex("494c5350010100000002c328");
    const auto encrypted = ConfigurationSensitiveEnvelope::encrypt(
        invalidPayload, password, digest);
    ASSERT_TRUE(encrypted.envelope);
    ConfigurationPackageCodec::Package package;
    package.publicData = publicObject;
    package.sensitive = *encrypted.envelope;

    EXPECT_EQ(ConfigurationImportPreview::create(
                  ConfigurationPackageCodec::encode(package), previewSnapshot(), password).error,
              ConfigurationImportPreview::Error::InvalidSensitivePayload);
}

} // namespace
