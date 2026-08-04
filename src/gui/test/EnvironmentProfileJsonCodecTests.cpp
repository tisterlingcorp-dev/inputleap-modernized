#include "EnvironmentProfileJsonCodec.h"

#include <gtest/gtest.h>

#include <QJsonArray>
#include <QJsonObject>

namespace {
using Codec = EnvironmentProfileJsonCodec;
using Error = Codec::Error;
const QUuid DeviceUuid(QStringLiteral("{11111111-1111-1111-1111-111111111111}"));

EnvironmentProfile profile(EnvironmentProfile::Kind kind)
{
    ScreenLayout::Monitor monitor;
    monitor.id = QStringLiteral("display-1");
    monitor.geometry = QRect(0, 0, 1920, 1080);
    monitor.devicePixelRatio = 1.25;
    monitor.orientation = Qt::LandscapeOrientation;
    monitor.stableIdentity = true;

    ScreenLayout::Device extensionDevice;
    extensionDevice.uuid = DeviceUuid;
    extensionDevice.technicalName = QStringLiteral("desktop");
    extensionDevice.geometry = QRect(0, 0, 1920, 1080);
    extensionDevice.monitors = {monitor};

    EnvironmentProfile result;
    result.kind = kind;
    result.layout.columns = 1;
    result.layout.rows = 1;
    result.layout.gridTechnicalNames = {QStringLiteral("desktop")};
    result.layout.extension = ScreenLayout({extensionDevice});
    result.devices = {{DeviceUuid, QStringLiteral("desktop"),
                       DevicePermissions::ControlMouseKeyboard |
                           DevicePermissions::ShareClipboard}};
    return result;
}

Codec::Collection validCollection()
{
    Codec::Collection result;
    result.activeKind = EnvironmentProfile::Kind::Office;
    for (const auto kind : EnvironmentProfile::canonicalKinds())
        result.profiles.push_back(profile(kind));
    return result;
}

TEST(EnvironmentProfileJsonCodecTests, FourCanonicalProfilesAndActiveKindRoundTrip)
{
    const auto expected = validCollection();
    const QJsonObject encoded = Codec::encode(expected);
    const auto decoded = Codec::decode(encoded);

    ASSERT_EQ(decoded.error, Error::None);
    ASSERT_TRUE(decoded.collection.has_value());
    EXPECT_EQ(decoded.collection->activeKind, expected.activeKind);
    ASSERT_EQ(decoded.collection->profiles.size(), 4);
    for (int i = 0; i < 4; ++i) {
        const auto& actual = decoded.collection->profiles[i];
        EXPECT_EQ(actual.kind, expected.profiles[i].kind);
        EXPECT_TRUE(actual.isValid());
        EXPECT_EQ(actual.layout.columns, 1);
        EXPECT_EQ(actual.layout.gridTechnicalNames, QStringList{QStringLiteral("desktop")});
        ASSERT_EQ(actual.layout.extension.devices().size(), 1u);
        ASSERT_EQ(actual.layout.extension.devices()[0].monitors.size(), 1u);
        EXPECT_EQ(actual.layout.extension.devices()[0].monitors[0].devicePixelRatio, 1.25);
        EXPECT_EQ(actual.devices[0].requestedResources,
                  DevicePermissions::ControlMouseKeyboard | DevicePermissions::ShareClipboard);
    }
    EXPECT_EQ(encoded.keys(), (QStringList{QStringLiteral("activeKind"), QStringLiteral("profiles")}));
}

TEST(EnvironmentProfileJsonCodecTests, RejectsMissingDuplicateAndNonCanonicalProfileKinds)
{
    QJsonObject encoded = Codec::encode(validCollection());
    QJsonArray profiles = encoded.value(QStringLiteral("profiles")).toArray();
    profiles.removeLast();
    encoded.insert(QStringLiteral("profiles"), profiles);
    EXPECT_EQ(Codec::decode(encoded).error, Error::InvalidValue);

    encoded = Codec::encode(validCollection());
    profiles = encoded.value(QStringLiteral("profiles")).toArray();
    QJsonObject duplicate = profiles[1].toObject();
    duplicate.insert(QStringLiteral("kind"), QStringLiteral("home"));
    profiles[1] = duplicate;
    encoded.insert(QStringLiteral("profiles"), profiles);
    EXPECT_EQ(Codec::decode(encoded).error, Error::InvalidValue);

    encoded = Codec::encode(validCollection());
    encoded.insert(QStringLiteral("activeKind"), QStringLiteral("custom"));
    EXPECT_EQ(Codec::decode(encoded).error, Error::InvalidValue);
}

TEST(EnvironmentProfileJsonCodecTests, RejectsUnknownSecretAndForbiddenPermissionFields)
{
    QJsonObject encoded = Codec::encode(validCollection());
    QJsonArray profiles = encoded.value(QStringLiteral("profiles")).toArray();
    QJsonObject first = profiles[0].toObject();
    QJsonArray devices = first.value(QStringLiteral("devices")).toArray();
    QJsonObject device = devices[0].toObject();
    device.insert(QStringLiteral("preSharedKey"), QStringLiteral("PLAINTEXT_SECRET"));
    devices[0] = device;
    first.insert(QStringLiteral("devices"), devices);
    profiles[0] = first;
    encoded.insert(QStringLiteral("profiles"), profiles);
    EXPECT_EQ(Codec::decode(encoded).error, Error::UnknownField);

    encoded = Codec::encode(validCollection());
    profiles = encoded.value(QStringLiteral("profiles")).toArray();
    first = profiles[0].toObject();
    devices = first.value(QStringLiteral("devices")).toArray();
    device = devices[0].toObject();
    device.insert(QStringLiteral("requestedResources"),
                  static_cast<double>(DevicePermissions::OpenSafeFiles));
    devices[0] = device;
    first.insert(QStringLiteral("devices"), devices);
    profiles[0] = first;
    encoded.insert(QStringLiteral("profiles"), profiles);
    EXPECT_EQ(Codec::decode(encoded).error, Error::InvalidValue);
}

TEST(EnvironmentProfileJsonCodecTests, RejectsUnknownRootFieldsAndResourceExcess)
{
    QJsonObject encoded = Codec::encode(validCollection());
    encoded.insert(QStringLiteral("generation"), QStringLiteral("runtime-only"));
    EXPECT_EQ(Codec::decode(encoded).error, Error::UnknownField);

    encoded = Codec::encode(validCollection());
    QJsonArray profiles = encoded.value(QStringLiteral("profiles")).toArray();
    QJsonObject first = profiles[0].toObject();
    QJsonObject layout = first.value(QStringLiteral("layout")).toObject();
    QJsonArray grid;
    for (int i = 0; i <= ScreenLayout::MaxDevices; ++i)
        grid.push_back(QString());
    layout.insert(QStringLiteral("grid"), grid);
    first.insert(QStringLiteral("layout"), layout);
    profiles[0] = first;
    encoded.insert(QStringLiteral("profiles"), profiles);
    EXPECT_EQ(Codec::decode(encoded).error, Error::ResourceLimit);
}

} // namespace
