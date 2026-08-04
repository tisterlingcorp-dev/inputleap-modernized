#include "ConfigurationRecoveryStore.h"
#include "ConfigurationPackageCodec.h"

#include <gtest/gtest.h>

#include <QJsonDocument>
#include <QJsonObject>

namespace {
using Error = ConfigurationRecoveryStore::Error;

ConfigurationPortablePreferences validPreferences()
{
    auto value = ConfigurationPortablePreferences::create(
        24800, 3, QStringLiteral("pt-BR"), true, false, false, false, false);
    EXPECT_TRUE(value.has_value());
    return *value;
}

TEST(ConfigurationRecoveryStoreCodecTests, CanonicalPublicSnapshotRoundTrips)
{
    const auto expected = validPreferences();
    const QByteArray encoded = ConfigurationRecoveryStore::encodeSnapshot(expected);
    const auto decoded = ConfigurationRecoveryStore::decodeSnapshot(encoded);

    ASSERT_EQ(decoded.error, Error::None);
    ASSERT_TRUE(decoded.preferences.has_value());
    EXPECT_EQ(*decoded.preferences, expected);

    const QJsonObject root = QJsonDocument::fromJson(encoded).object();
    EXPECT_EQ(root.value(QStringLiteral("format")).toString(),
              QStringLiteral("inputleap-configuration"));
    EXPECT_EQ(root.value(QStringLiteral("schemaVersion")).toInt(), 1);
    EXPECT_FALSE(root.contains(QStringLiteral("sensitive")));
    EXPECT_EQ(root.value(QStringLiteral("public")).toObject().keys(),
              QStringList{QStringLiteral("preferences")});
}

TEST(ConfigurationRecoveryStoreCodecTests, LiteralSchemaOnePreferencesFixtureIsSupported)
{
    const QByteArray fixture = QByteArrayLiteral(
        R"json({"format":"inputleap-configuration","schemaVersion":1,"public":{"preferences":{"autoHide":false,"autoStart":false,"cryptoEnabled":true,"language":"pt-BR","logLevel":3,"minimizeToTray":false,"port":24800,"requireClientCertificate":false}}})json");
    QByteArray input = fixture;
    const auto decoded = ConfigurationRecoveryStore::decodeSnapshot(input);
    ASSERT_EQ(decoded.error, Error::None);
    ASSERT_TRUE(decoded.preferences.has_value());
    EXPECT_EQ(*decoded.preferences, validPreferences());
    EXPECT_EQ(input, fixture);
}

TEST(ConfigurationRecoveryStoreCodecTests, RejectsSensitiveAndNonPreferencePublicSections)
{
    const QJsonObject preferences =
        ConfigurationPortablePreferencesCodec::encode(validPreferences());
    ConfigurationPackageCodec::Package package;
    package.publicData.insert(QStringLiteral("preferences"), preferences);
    package.sensitive = QJsonObject{{QStringLiteral("ciphertext"), QStringLiteral("AA==")}};
    EXPECT_EQ(ConfigurationRecoveryStore::decodeSnapshot(
                  ConfigurationPackageCodec::encode(package)).error,
              Error::SensitiveForbidden);

    package.sensitive.reset();
    package.publicData.insert(QStringLiteral("environmentProfiles"), QJsonObject{});
    EXPECT_EQ(ConfigurationRecoveryStore::decodeSnapshot(
                  ConfigurationPackageCodec::encode(package)).error,
              Error::InvalidPublicSection);

    package.publicData = QJsonObject{};
    EXPECT_EQ(ConfigurationRecoveryStore::decodeSnapshot(
                  ConfigurationPackageCodec::encode(package)).error,
              Error::InvalidPublicSection);
}

TEST(ConfigurationRecoveryStoreCodecTests, RejectsMalformedFutureDuplicateAndSecretLikeFields)
{
    const QList<QByteArray> invalidPackages{
        QByteArrayLiteral("{"),
        QByteArrayLiteral(R"json({"format":"inputleap-configuration","schemaVersion":0,"public":{"preferences":{}}})json"),
        QByteArrayLiteral(R"json({"format":"inputleap-configuration","schemaVersion":1.0,"public":{"preferences":{}}})json"),
        QByteArrayLiteral(R"json({"format":"inputleap-configuration","schemaVersion":"1","public":{"preferences":{}}})json"),
        QByteArrayLiteral(R"json({"format":"inputleap-configuration","schemaVersion":2,"public":{"preferences":{}}})json"),
        QByteArrayLiteral(R"json({"format":"inputleap-configuration","schemaVersion":1,"public":{"preferences":{"port":24800,"port":24801}}})json")
    };
    for (const QByteArray& invalid : invalidPackages) {
        QByteArray input = invalid;
        EXPECT_EQ(ConfigurationRecoveryStore::decodeSnapshot(input).error,
                  Error::InvalidPackage);
        EXPECT_EQ(input, invalid);
    }

    QJsonObject preferences = ConfigurationPortablePreferencesCodec::encode(validPreferences());
    preferences.insert(QStringLiteral("fileTransferPairingCode"),
                       QStringLiteral("[REDACTED]"));
    ConfigurationPackageCodec::Package package;
    package.publicData.insert(QStringLiteral("preferences"), preferences);
    EXPECT_EQ(ConfigurationRecoveryStore::decodeSnapshot(
                  ConfigurationPackageCodec::encode(package)).error,
              Error::InvalidPreferences);
}

TEST(ConfigurationRecoveryStoreCodecTests, RejectsMalformedSupportedVersionWithoutMutation)
{
    const QByteArray malformed = QByteArrayLiteral(
        R"json({"format":"inputleap-configuration","schemaVersion":1,"public":{"preferences":{"port":"24800"}}})json");
    QByteArray input = malformed;
    EXPECT_EQ(ConfigurationRecoveryStore::decodeSnapshot(input).error,
              Error::InvalidPreferences);
    EXPECT_EQ(input, malformed);
}
} // namespace
