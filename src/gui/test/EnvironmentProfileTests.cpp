/* InputLeap -- canonical environment profile model tests. */
#include "EnvironmentProfile.h"

#include <gtest/gtest.h>

namespace {
const QUuid firstUuid(QStringLiteral("{11111111-1111-1111-1111-111111111111}"));
const QUuid secondUuid(QStringLiteral("{22222222-2222-2222-2222-222222222222}"));

ScreenLayout::Device layoutDevice(const QUuid& uuid, const QString& name, const QRect& geometry)
{
    ScreenLayout::Device result;
    result.uuid = uuid;
    result.technicalName = name;
    result.geometry = geometry;
    return result;
}

EnvironmentProfile validProfile()
{
    EnvironmentProfile profile;
    profile.kind = EnvironmentProfile::Kind::Home;
    profile.layout.columns = 2;
    profile.layout.rows = 1;
    profile.layout.gridTechnicalNames = {QStringLiteral("desktop"), QStringLiteral("notebook")};
    profile.layout.extension = ScreenLayout({
        layoutDevice(firstUuid, QStringLiteral("desktop"), QRect(0, 0, 100, 100)),
        layoutDevice(secondUuid, QStringLiteral("notebook"), QRect(100, 0, 100, 100)),
    });
    profile.devices = {
        {firstUuid, QStringLiteral("desktop"), DevicePermissions::ControlMouseKeyboard | DevicePermissions::ShareClipboard},
        {secondUuid, QStringLiteral("notebook"), DevicePermissions::SendFiles | DevicePermissions::ReceiveFiles},
    };
    return profile;
}

void setTechnicalNames(EnvironmentProfile& profile, const QString& first, const QString& second)
{
    profile.layout.gridTechnicalNames = {first, second};
    profile.layout.extension = ScreenLayout({
        layoutDevice(firstUuid, first, QRect(0, 0, 100, 100)),
        layoutDevice(secondUuid, second, QRect(100, 0, 100, 100)),
    });
    profile.devices[0].technicalName = first;
    profile.devices[1].technicalName = second;
}
}

TEST(EnvironmentProfileTests, HasExactlyFourCanonicalStableKinds)
{
    EXPECT_EQ(EnvironmentProfile::canonicalKinds(),
              QList({EnvironmentProfile::Kind::Home,
                     EnvironmentProfile::Kind::Office,
                     EnvironmentProfile::Kind::Travel,
                     EnvironmentProfile::Kind::Presentation}));
    EXPECT_EQ(EnvironmentProfile::key(EnvironmentProfile::Kind::Home), QStringLiteral("home"));
    EXPECT_EQ(EnvironmentProfile::key(EnvironmentProfile::Kind::Office), QStringLiteral("office"));
    EXPECT_EQ(EnvironmentProfile::key(EnvironmentProfile::Kind::Travel), QStringLiteral("travel"));
    EXPECT_EQ(EnvironmentProfile::key(EnvironmentProfile::Kind::Presentation), QStringLiteral("presentation"));
    EXPECT_EQ(EnvironmentProfile::canonicalDisplayName(EnvironmentProfile::Kind::Home), QStringLiteral("Casa"));
    EXPECT_EQ(EnvironmentProfile::canonicalDisplayName(EnvironmentProfile::Kind::Office), QStringLiteral("Escritório"));
    EXPECT_EQ(EnvironmentProfile::canonicalDisplayName(EnvironmentProfile::Kind::Travel), QStringLiteral("Viagem"));
    EXPECT_EQ(EnvironmentProfile::canonicalDisplayName(EnvironmentProfile::Kind::Presentation), QStringLiteral("Apresentação"));
    EXPECT_EQ(EnvironmentProfile::fromKey(QStringLiteral("presentation")), EnvironmentProfile::Kind::Presentation);
    EXPECT_FALSE(EnvironmentProfile::fromKey(QStringLiteral("Presentation")).has_value());
    EXPECT_FALSE(EnvironmentProfile::fromKey(QStringLiteral(" presentation")).has_value());
    EXPECT_FALSE(EnvironmentProfile::fromKey(QStringLiteral("custom")).has_value());
}

TEST(EnvironmentProfileTests, ValidatesUuidNameAndRequestedResourceIdentityFailClosed)
{
    EXPECT_TRUE(validProfile().isValid());

    auto nullUuid = validProfile();
    nullUuid.devices[0].uuid = {};
    EXPECT_FALSE(nullUuid.isValid());

    auto duplicateUuid = validProfile();
    duplicateUuid.devices[1].uuid = firstUuid;
    EXPECT_FALSE(duplicateUuid.isValid());

    auto forbiddenOpen = validProfile();
    forbiddenOpen.devices[0].requestedResources |= DevicePermissions::OpenSafeFiles;
    EXPECT_FALSE(forbiddenOpen.isValid());

    auto unknownBit = validProfile();
    unknownBit.devices[0].requestedResources |= (1u << 31);
    EXPECT_FALSE(unknownBit.isValid());

    auto divergentName = validProfile();
    divergentName.devices[0].technicalName = QStringLiteral("other-desktop");
    EXPECT_FALSE(divergentName.isValid());
}

TEST(EnvironmentProfileTests, AcceptsCanonicalCoreTechnicalNameGrammar)
{
    const QStringList validNames = {
        QStringLiteral("_"),
        QStringLiteral("A"),
        QStringLiteral("host_name"),
        QStringLiteral("host-name"),
        QStringLiteral("host.part_2"),
        QStringLiteral("host."),
    };

    for (const auto& name : validNames) {
        auto profile = validProfile();
        setTechnicalNames(profile, name, QStringLiteral("peer"));
        EXPECT_TRUE(profile.isValid()) << name.toStdString();
    }
}

TEST(EnvironmentProfileTests, RejectsWhitespaceControlsUnicodeAndInvalidUtf16TechnicalNames)
{
    const QString invalidSurrogate(QChar(0xd800));
    const QStringList invalidNames = {
        QString(),
        QStringLiteral(" "),
        QStringLiteral(" host"),
        QStringLiteral("host "),
        QStringLiteral("host\tname"),
        QStringLiteral("host\nname"),
        QString::fromUtf8("h\xC3\xB4st"),
        QString::fromUtf8("host-\xF0\x9F\x92\xBB"),
        invalidSurrogate,
    };

    for (const auto& name : invalidNames) {
        auto profile = validProfile();
        setTechnicalNames(profile, name, QStringLiteral("peer"));
        EXPECT_FALSE(profile.isValid()) << name.toUtf8().toHex().constData();
    }
}

TEST(EnvironmentProfileTests, RejectsInvalidCoreComponentsSeparatorsAndCharacters)
{
    const QStringList invalidNames = {
        QStringLiteral(".host"),
        QStringLiteral("host..part"),
        QStringLiteral("-host"),
        QStringLiteral("host-"),
        QStringLiteral("host-.part"),
        QStringLiteral("host.-part"),
        QStringLiteral("host/name"),
        QStringLiteral("host:name"),
        QStringLiteral("host#name"),
        QStringLiteral("host+name"),
    };

    for (const auto& name : invalidNames) {
        auto profile = validProfile();
        setTechnicalNames(profile, name, QStringLiteral("peer"));
        EXPECT_FALSE(profile.isValid()) << name.toStdString();
    }
}

TEST(EnvironmentProfileTests, EnforcesCoreHelloTechnicalNameByteLimit)
{
    // Barrier + two 16-bit versions + uint32 string length leave 1009 bytes
    // for the name inside the core's 1024-byte hello reply limit.
    constexpr qsizetype maxCoreTechnicalNameBytes = 1024 - 7 - 2 - 2 - 4;

    auto atLimit = validProfile();
    setTechnicalNames(atLimit, QString(maxCoreTechnicalNameBytes, QLatin1Char('a')), QStringLiteral("peer"));
    EXPECT_TRUE(atLimit.isValid());

    auto overLimit = validProfile();
    setTechnicalNames(overLimit, QString(maxCoreTechnicalNameBytes + 1, QLatin1Char('a')), QStringLiteral("peer"));
    EXPECT_FALSE(overLimit.isValid());
}

TEST(EnvironmentProfileTests, RejectsCaseInsensitiveTechnicalNameCollisionsLikeCoreConfig)
{
    auto profile = validProfile();
    setTechnicalNames(profile, QStringLiteral("Desktop.Example"), QStringLiteral("desktop.example"));

    EXPECT_FALSE(profile.isValid());
}

TEST(EnvironmentProfileTests, ValidatesGridAndScreenLayoutOneToOne)
{
    auto invalidDimensions = validProfile();
    invalidDimensions.layout.columns = 0;
    EXPECT_FALSE(invalidDimensions.isValid());

    auto mismatchedGrid = validProfile();
    mismatchedGrid.layout.gridTechnicalNames.removeLast();
    EXPECT_FALSE(mismatchedGrid.isValid());

    auto duplicateGridName = validProfile();
    duplicateGridName.layout.gridTechnicalNames[1] = QStringLiteral("desktop");
    EXPECT_FALSE(duplicateGridName.isValid());

    auto missingDevice = validProfile();
    missingDevice.devices.removeLast();
    EXPECT_FALSE(missingDevice.isValid());

    auto invalidScreenLayout = validProfile();
    invalidScreenLayout.layout.extension = ScreenLayout({
        layoutDevice(firstUuid, QStringLiteral("desktop"), QRect(0, 0, 100, 100)),
        layoutDevice(secondUuid, QStringLiteral("notebook"), QRect(50, 0, 100, 100)),
    });
    EXPECT_FALSE(invalidScreenLayout.isValid());
}

TEST(EnvironmentProfileTests, RequestedResourcesAreResolvedOnlyByExactUuid)
{
    auto profile = validProfile();
    profile.devices[1].technicalName = profile.devices[0].technicalName;

    EXPECT_EQ(profile.requestedResourcesFor(firstUuid),
              DevicePermissions::ControlMouseKeyboard | DevicePermissions::ShareClipboard);
    EXPECT_EQ(profile.requestedResourcesFor(secondUuid),
              DevicePermissions::SendFiles | DevicePermissions::ReceiveFiles);
    EXPECT_EQ(profile.requestedResourcesFor(QUuid::createUuid()), DevicePermissions::None);
    EXPECT_EQ(profile.requestedResourcesFor({}), DevicePermissions::None);

    EXPECT_TRUE(profile.requests(firstUuid, DevicePermissions::ShareClipboard));
    EXPECT_FALSE(profile.requests(secondUuid, DevicePermissions::ShareClipboard));
    EXPECT_FALSE(profile.requests(firstUuid, DevicePermissions::OpenSafeFiles));
}

TEST(EnvironmentProfileTests, RequestedResourcesFailClosedForDuplicateUuidEvenWhenProfileIsInvalid)
{
    auto profile = validProfile();
    profile.devices[1].uuid = firstUuid;

    ASSERT_FALSE(profile.isValid());
    EXPECT_EQ(profile.requestedResourcesFor(firstUuid), DevicePermissions::None);
}

TEST(EnvironmentProfileTests, AutoConnectAloneIsAValidAndReturnedManagedResource)
{
    auto profile = validProfile();
    profile.devices[0].requestedResources = DevicePermissions::AutoConnect;

    ASSERT_TRUE(profile.isValid());
    EXPECT_EQ(profile.requestedResourcesFor(firstUuid), DevicePermissions::AutoConnect);
    EXPECT_TRUE(profile.requests(firstUuid, DevicePermissions::AutoConnect));
}
