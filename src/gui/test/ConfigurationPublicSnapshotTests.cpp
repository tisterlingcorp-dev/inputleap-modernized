#include "ConfigurationPublicSnapshot.h"

#include <gtest/gtest.h>

#include <QJsonDocument>
#include <QJsonArray>

namespace {
ConfigurationPublicSnapshot validSnapshot()
{
    ConfigurationPublicSnapshot snapshot;
    snapshot.preferences = *ConfigurationPortablePreferences::create(
        24800, 3, QStringLiteral("pt-BR"), true, true, false, false, false);
    snapshot.environmentProfiles.activeKind = EnvironmentProfile::Kind::Home;

    const QUuid uuid(QStringLiteral("{11111111-1111-1111-1111-111111111111}"));
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        ScreenLayout::Device layoutDevice;
        layoutDevice.uuid = uuid;
        layoutDevice.technicalName = QStringLiteral("desktop");
        layoutDevice.geometry = QRect(0, 0, 100, 100);
        layoutDevice.monitors = {{QStringLiteral("display-1"), QRect(0, 0, 100, 100),
                                  1.0, Qt::PrimaryOrientation, false}};
        EnvironmentProfile profile;
        profile.kind = kind;
        profile.layout.columns = 1;
        profile.layout.rows = 1;
        profile.layout.gridTechnicalNames = {QStringLiteral("desktop")};
        profile.layout.extension = ScreenLayout({layoutDevice});
        profile.devices = {{uuid, QStringLiteral("desktop"), DevicePermissions::ControlMouseKeyboard}};
        snapshot.environmentProfiles.profiles.push_back(profile);
    }
    return snapshot;
}

TEST(ConfigurationPublicSnapshotTests, TypedPublicSectionsRoundTrip)
{
    const auto expected = validSnapshot();
    const QJsonObject encoded = ConfigurationPublicSnapshotCodec::encode(expected);
    const auto decoded = ConfigurationPublicSnapshotCodec::decode(encoded);

    ASSERT_EQ(decoded.error, ConfigurationPublicSnapshotCodec::Error::None);
    ASSERT_TRUE(decoded.snapshot.has_value());
    EXPECT_EQ(decoded.snapshot->preferences, expected.preferences);
    EXPECT_EQ(decoded.snapshot->environmentProfiles.activeKind,
              expected.environmentProfiles.activeKind);
    EXPECT_EQ(decoded.snapshot->environmentProfiles.profiles.size(), 4);
    const auto& decodedMonitor = decoded.snapshot->environmentProfiles.profiles.first()
                                     .layout.extension.devices().front().monitors.front();
    EXPECT_EQ(decodedMonitor.id, QStringLiteral("monitor-1"));
    EXPECT_FALSE(decodedMonitor.stableIdentity);
    EXPECT_EQ(encoded.keys(), (QStringList{QStringLiteral("environmentProfiles"),
                                           QStringLiteral("preferences")}));
}

TEST(ConfigurationPublicSnapshotTests, RejectsUnknownMissingAndWrongSectionTypes)
{
    QJsonObject encoded = ConfigurationPublicSnapshotCodec::encode(validSnapshot());
    encoded.insert(QStringLiteral("credentials"), QJsonObject{});
    EXPECT_EQ(ConfigurationPublicSnapshotCodec::decode(encoded).error,
              ConfigurationPublicSnapshotCodec::Error::UnknownField);

    encoded = ConfigurationPublicSnapshotCodec::encode(validSnapshot());
    encoded.remove(QStringLiteral("preferences"));
    EXPECT_EQ(ConfigurationPublicSnapshotCodec::decode(encoded).error,
              ConfigurationPublicSnapshotCodec::Error::MissingField);

    encoded = ConfigurationPublicSnapshotCodec::encode(validSnapshot());
    encoded.insert(QStringLiteral("environmentProfiles"), QStringLiteral("invalid"));
    EXPECT_EQ(ConfigurationPublicSnapshotCodec::decode(encoded).error,
              ConfigurationPublicSnapshotCodec::Error::InvalidType);
}

TEST(ConfigurationPublicSnapshotTests, RejectsMalformedNestedSectionsWithoutPartialSnapshot)
{
    const QJsonObject canonical = ConfigurationPublicSnapshotCodec::encode(validSnapshot());
    QList<QJsonObject> malformed;

    QJsonObject badPort = canonical;
    QJsonObject preferences = badPort.value(QStringLiteral("preferences")).toObject();
    preferences.insert(QStringLiteral("port"), QStringLiteral("24800"));
    badPort.insert(QStringLiteral("preferences"), preferences);
    malformed.push_back(badPort);

    QJsonObject unknownProfileField = canonical;
    QJsonObject profiles = unknownProfileField.value(
        QStringLiteral("environmentProfiles")).toObject();
    profiles.insert(QStringLiteral("credentials"), QJsonObject{});
    unknownProfileField.insert(QStringLiteral("environmentProfiles"), profiles);
    malformed.push_back(unknownProfileField);

    QJsonObject wrongProfilesType = canonical;
    wrongProfilesType.insert(QStringLiteral("environmentProfiles"), QJsonArray{});
    malformed.push_back(wrongProfilesType);

    for (const QJsonObject& invalid : malformed) {
        QJsonObject input = invalid;
        const auto decoded = ConfigurationPublicSnapshotCodec::decode(input);
        EXPECT_NE(decoded.error, ConfigurationPublicSnapshotCodec::Error::None);
        EXPECT_FALSE(decoded.snapshot.has_value());
        EXPECT_EQ(input, invalid);
    }
}

TEST(ConfigurationPublicSnapshotTests, EncodedPublicSnapshotContainsNoSecretOrRuntimeKeys)
{
    const QByteArray encoded = QJsonDocument(ConfigurationPublicSnapshotCodec::encode(validSnapshot()))
                                   .toJson(QJsonDocument::Compact);
    for (const QByteArray& forbidden : {QByteArrayLiteral("pairingCode"),
                                        QByteArrayLiteral("preSharedKey"),
                                        QByteArrayLiteral("privateKey"),
                                        QByteArrayLiteral("networkInterface"),
                                        QByteArrayLiteral("ipAddress"),
                                        QByteArrayLiteral("capabilities"),
                                        QByteArrayLiteral("trustState"),
                                        QByteArrayLiteral("\"id\""),
                                        QByteArrayLiteral("stableIdentity"),
                                        QByteArrayLiteral("receiveDirectory"),
                                        QByteArrayLiteral("logFilename")}) {
        EXPECT_FALSE(encoded.contains(forbidden)) << forbidden.constData();
    }
}

} // namespace
