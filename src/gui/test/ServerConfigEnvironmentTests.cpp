/* InputLeap -- ServerConfig environment layout transaction tests. */
#include "EnvironmentProfile.h"
#include "ServerConfig.h"

#include <gtest/gtest.h>

#include <algorithm>

#include <QBuffer>
#include <QFile>
#include <QSettings>
#include <QTemporaryDir>

namespace {
const QUuid alphaId(QStringLiteral("11111111-1111-1111-1111-111111111111"));
const QUuid betaId(QStringLiteral("22222222-2222-2222-2222-222222222222"));
const QUuid gammaId(QStringLiteral("33333333-3333-3333-3333-333333333333"));

class TestServerConfig : public ServerConfig
{
public:
    using ServerConfig::ServerConfig;
    std::vector<Screen>& editableScreens() { return screens(); }
};

ScreenLayout::Device layoutDevice(const QUuid& uuid, const QString& name, const QRect& geometry)
{
    ScreenLayout::Device result;
    result.uuid = uuid;
    result.technicalName = name;
    result.geometry = geometry;
    return result;
}

QByteArray serializeScreen(const Screen& screen)
{
    QByteArray bytes;
    QDataStream stream(&bytes, QIODevice::WriteOnly);
    stream << screen;
    return bytes;
}

void seedConfig(QSettings& settings)
{
    settings.beginGroup(QStringLiteral("internalConfig"));
    settings.setValue(QStringLiteral("numColumns"), 5);
    settings.setValue(QStringLiteral("numRows"), 3);
    settings.setValue(QStringLiteral("hasHeartbeat"), true);
    settings.setValue(QStringLiteral("heartbeat"), 4321);
    settings.beginWriteArray(QStringLiteral("screens"));
    for (int i = 0; i < 15; ++i) {
        settings.setArrayIndex(i);
        if (i == 1) {
            settings.setValue(QStringLiteral("name"), QStringLiteral("alpha"));
            settings.setValue(QStringLiteral("switchCornerSize"), 17);
            settings.beginWriteArray(QStringLiteral("aliasArray"));
            settings.setArrayIndex(0);
            settings.setValue(QStringLiteral("alias"), QStringLiteral("alpha-alias"));
            settings.endArray();
            settings.beginWriteArray(QStringLiteral("modifierArray"));
            for (int modifier = 0; modifier < static_cast<int>(BaseConfig::Modifier::Count); ++modifier) {
                settings.setArrayIndex(modifier);
                settings.setValue(QStringLiteral("modifier"), modifier == 0
                    ? static_cast<int>(BaseConfig::Modifier::Ctrl) : modifier);
            }
            settings.endArray();
            settings.beginWriteArray(QStringLiteral("switchCornerArray"));
            for (int corner = 0; corner < static_cast<int>(BaseConfig::SwitchCorner::Count); ++corner) {
                settings.setArrayIndex(corner);
                settings.setValue(QStringLiteral("switchCorner"), corner == 2);
            }
            settings.endArray();
            settings.beginWriteArray(QStringLiteral("fixArray"));
            for (int fix = 0; fix < static_cast<int>(BaseConfig::Fix::Count); ++fix) {
                settings.setArrayIndex(fix);
                settings.setValue(QStringLiteral("fix"), fix == 3);
            }
            settings.endArray();
        }
        else if (i == 9) {
            settings.setValue(QStringLiteral("name"), QStringLiteral("beta"));
        }
        else {
            settings.setValue(QStringLiteral("name"), QString());
        }
    }
    settings.endArray();
    auto alpha = layoutDevice(alphaId, QStringLiteral("alpha"), QRect(0, 0, 120, 100));
    alpha.monitors.push_back({QStringLiteral("alpha-primary"), QRect(0, 0, 120, 100),
                              1.25, Qt::LandscapeOrientation, true});
    const ScreenLayout extension({
        alpha, layoutDevice(betaId, QStringLiteral("beta"), QRect(120, 0, 80, 100))});
    ASSERT_TRUE(extension.saveMetadata(settings));
    settings.endGroup();
    settings.sync();
}

EnvironmentProfile::Layout validTarget()
{
    EnvironmentProfile::Layout target;
    target.columns = 3;
    target.rows = 2;
    target.gridTechnicalNames = {
        QStringLiteral("beta"), QString(), QStringLiteral("gamma"),
        QString(), QStringLiteral("alpha"), QString()};
    target.extension = ScreenLayout({
        layoutDevice(betaId, QStringLiteral("beta"), QRect(0, 0, 100, 100)),
        layoutDevice(gammaId, QStringLiteral("gamma"), QRect(100, 0, 100, 100)),
        layoutDevice(alphaId, QStringLiteral("alpha"), QRect(200, 0, 100, 100))});
    return target;
}

void expectLayoutEqual(const ScreenLayout& actual, const ScreenLayout& expected)
{
    ASSERT_EQ(actual.devices().size(), expected.devices().size());
    for (size_t i = 0; i < expected.devices().size(); ++i) {
        EXPECT_EQ(actual.devices()[i].uuid, expected.devices()[i].uuid);
        EXPECT_EQ(actual.devices()[i].technicalName, expected.devices()[i].technicalName);
        EXPECT_EQ(actual.devices()[i].geometry, expected.devices()[i].geometry);
        ASSERT_EQ(actual.devices()[i].monitors.size(), expected.devices()[i].monitors.size());
        for (size_t monitor = 0; monitor < expected.devices()[i].monitors.size(); ++monitor) {
            EXPECT_EQ(actual.devices()[i].monitors[monitor].id,
                      expected.devices()[i].monitors[monitor].id);
            EXPECT_EQ(actual.devices()[i].monitors[monitor].geometry,
                      expected.devices()[i].monitors[monitor].geometry);
            EXPECT_DOUBLE_EQ(actual.devices()[i].monitors[monitor].devicePixelRatio,
                             expected.devices()[i].monitors[monitor].devicePixelRatio);
            EXPECT_EQ(actual.devices()[i].monitors[monitor].orientation,
                      expected.devices()[i].monitors[monitor].orientation);
            EXPECT_EQ(actual.devices()[i].monitors[monitor].stableIdentity,
                      expected.devices()[i].monitors[monitor].stableIdentity);
        }
    }
}

struct StateSnapshot {
    int columns;
    int rows;
    std::vector<QByteArray> screens;
    ScreenLayout layout;
    bool hasHeartbeat;
    int heartbeat;
};

StateSnapshot stateOf(const ServerConfig& config)
{
    StateSnapshot state{config.numColumns(), config.numRows(), {}, config.screenLayout(),
                        config.hasHeartbeat(), config.heartbeat()};
    for (const auto& screen : config.screens()) state.screens.push_back(serializeScreen(screen));
    return state;
}

void expectStateEqual(const ServerConfig& config, const StateSnapshot& expected)
{
    EXPECT_EQ(config.numColumns(), expected.columns);
    EXPECT_EQ(config.numRows(), expected.rows);
    ASSERT_EQ(config.screens().size(), expected.screens.size());
    for (size_t i = 0; i < expected.screens.size(); ++i)
        EXPECT_EQ(serializeScreen(config.screens()[i]), expected.screens[i]);
    expectLayoutEqual(config.screenLayout(), expected.layout);
    EXPECT_EQ(config.hasHeartbeat(), expected.hasHeartbeat);
    EXPECT_EQ(config.heartbeat(), expected.heartbeat);
}
}

TEST(ServerConfigEnvironmentTests, SnapshotFaithfullyIncludesDimensionsAllCellsAndExtension)
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath(QStringLiteral("server.ini")), QSettings::IniFormat);
    seedConfig(settings);
    ServerConfig config(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
    const ScreenLayout storedBefore = config.screenLayout();

    const auto snapshot = config.environmentLayoutSnapshot();

    EXPECT_EQ(snapshot.columns, 5);
    EXPECT_EQ(snapshot.rows, 3);
    ASSERT_EQ(snapshot.gridTechnicalNames.size(), 15);
    EXPECT_EQ(snapshot.gridTechnicalNames[1], QStringLiteral("alpha"));
    EXPECT_EQ(snapshot.gridTechnicalNames[9], QStringLiteral("beta"));
    for (int i = 0; i < 15; ++i)
        if (i != 1 && i != 9) EXPECT_TRUE(snapshot.gridTechnicalNames[i].isEmpty());
    const auto expectedExtension = config.screenLayout().synchronizedToLegacyGrid(
        snapshot.gridTechnicalNames, snapshot.columns, snapshot.rows);
    expectLayoutEqual(snapshot.extension, expectedExtension);
    EXPECT_TRUE(snapshot.extension.validate().isValid());
    expectLayoutEqual(config.screenLayout(), storedBefore);
}

TEST(ServerConfigEnvironmentTests, SnapshotFailsClosedOnAsciiCaselessRemoteIdentityCollision)
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath(QStringLiteral("collision.ini")), QSettings::IniFormat);
    seedConfig(settings);
    ServerConfig config(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
    QHash<QString, QUuid> identities;
    identities.insert(QStringLiteral("beta"), betaId);
    identities.insert(QStringLiteral("BETA"), gammaId);

    const auto snapshot = config.environmentLayoutSnapshot(alphaId, identities);

    EXPECT_TRUE(snapshot.extension.devices().empty());
}

TEST(ServerConfigEnvironmentTests, LegacyLocalOnlySnapshotBindsProvidedStableIdentity)
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath(QStringLiteral("legacy-local.ini")),
                       QSettings::IniFormat);
    settings.beginGroup(QStringLiteral("internalConfig"));
    settings.setValue(QStringLiteral("numColumns"), 5);
    settings.setValue(QStringLiteral("numRows"), 3);
    settings.beginWriteArray(QStringLiteral("screens"));
    for (int i = 0; i < 15; ++i) {
        settings.setArrayIndex(i);
        settings.setValue(QStringLiteral("name"),
                          i == 7 ? QStringLiteral("local-pc") : QString());
    }
    settings.endArray();
    settings.endGroup();
    settings.sync();
    const QUuid localUuid(QStringLiteral("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
    ServerConfig config(&settings, 1, 1, QStringLiteral("local-pc"), nullptr);

    const auto snapshot = config.environmentLayoutSnapshot(localUuid);

    ASSERT_EQ(snapshot.extension.devices().size(), 1u);
    EXPECT_EQ(snapshot.extension.devices().front().uuid, localUuid);
    EXPECT_EQ(snapshot.extension.devices().front().technicalName,
              QStringLiteral("local-pc"));
    EXPECT_TRUE(snapshot.extension.validate().isValid());
    EnvironmentProfile profile;
    profile.kind = EnvironmentProfile::Kind::Home;
    profile.layout = snapshot;
    profile.devices.push_back({localUuid, QStringLiteral("local-pc"),
                               DevicePermissions::None});
    EXPECT_TRUE(profile.isValid());
}

TEST(ServerConfigEnvironmentTests, ValidApplicationMovesCompleteScreensAndCreatesOnlyFreshDefaults)
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath(QStringLiteral("server.ini")), QSettings::IniFormat);
    seedConfig(settings);
    ServerConfig config(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
    const auto& screensBefore = static_cast<const ServerConfig&>(config).screens();
    const QByteArray alphaBefore = serializeScreen(screensBefore[1]);
    const QByteArray betaBefore = serializeScreen(screensBefore[9]);

    const auto target = validTarget();
    ASSERT_TRUE(config.applyEnvironmentLayout(target));

    const auto& screensAfter = static_cast<const ServerConfig&>(config).screens();
    EXPECT_EQ(config.numColumns(), 3);
    EXPECT_EQ(config.numRows(), 2);
    ASSERT_EQ(screensAfter.size(), 6u);
    EXPECT_EQ(serializeScreen(screensAfter[0]), betaBefore);
    EXPECT_TRUE(screensAfter[1].isNull());
    EXPECT_EQ(screensAfter[2].name(), QStringLiteral("gamma"));
    EXPECT_TRUE(screensAfter[2].aliases().isEmpty());
    EXPECT_EQ(screensAfter[2].switchCornerSize(), 0);
    EXPECT_EQ(serializeScreen(screensAfter[4]), alphaBefore);
    expectLayoutEqual(config.screenLayout(), target.extension);
    EXPECT_TRUE(config.hasHeartbeat());
    EXPECT_EQ(config.heartbeat(), 4321);
}

TEST(ServerConfigEnvironmentTests, EveryInvalidLayoutFailsWithoutAnyMutation)
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath(QStringLiteral("server.ini")), QSettings::IniFormat);
    seedConfig(settings);
    ServerConfig config(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
    const auto before = stateOf(config);

    QList<EnvironmentProfile::Layout> invalid;
    auto missingDevice = validTarget();
    missingDevice.extension = ScreenLayout({
        layoutDevice(betaId, QStringLiteral("beta"), QRect(0, 0, 100, 100)),
        layoutDevice(alphaId, QStringLiteral("alpha"), QRect(100, 0, 100, 100))});
    invalid.push_back(missingDevice);

    auto duplicateUuid = validTarget();
    auto duplicateUuidDevices = duplicateUuid.extension.devices();
    duplicateUuidDevices[1].uuid = betaId;
    duplicateUuid.extension = ScreenLayout(std::move(duplicateUuidDevices));
    invalid.push_back(duplicateUuid);

    auto duplicateName = validTarget();
    duplicateName.gridTechnicalNames[2] = QStringLiteral("beta");
    auto duplicateNameDevices = duplicateName.extension.devices();
    duplicateNameDevices[1].technicalName = QStringLiteral("beta");
    duplicateName.extension = ScreenLayout(std::move(duplicateNameDevices));
    invalid.push_back(duplicateName);

    auto caseCollision = validTarget();
    caseCollision.gridTechnicalNames[2] = QStringLiteral("ALPHA");
    auto caseDevices = caseCollision.extension.devices();
    caseDevices[1].technicalName = QStringLiteral("ALPHA");
    caseCollision.extension = ScreenLayout(std::move(caseDevices));
    invalid.push_back(caseCollision);

    auto divergence = validTarget();
    divergence.gridTechnicalNames[2] = QStringLiteral("delta");
    invalid.push_back(divergence);

    auto badDimensions = validTarget();
    badDimensions.columns = 4;
    invalid.push_back(badDimensions);

    for (const auto& candidate : invalid) {
        EXPECT_FALSE(config.applyEnvironmentLayout(candidate));
        expectStateEqual(config, before);
    }
}

TEST(ServerConfigEnvironmentTests, SnapshotWithUnknownGridDeviceKeepsStaleIdentityInvalidWithoutMutation)
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath(QStringLiteral("server.ini")), QSettings::IniFormat);
    seedConfig(settings);
    TestServerConfig config(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
    const ScreenLayout storedBefore = config.screenLayout();
    config.editableScreens()[9].setName(QStringLiteral("new-device"));

    const auto snapshot = config.environmentLayoutSnapshot();

    expectLayoutEqual(snapshot.extension, storedBefore);
    ASSERT_EQ(snapshot.extension.devices().size(), 2u);
    EXPECT_EQ(snapshot.extension.devices()[0].uuid, alphaId);
    EXPECT_EQ(snapshot.extension.devices()[1].uuid, betaId);
    EXPECT_TRUE(std::none_of(snapshot.extension.devices().cbegin(), snapshot.extension.devices().cend(),
        [](const ScreenLayout::Device& device) {
            return device.technicalName == QStringLiteral("new-device");
        }));
    EnvironmentProfile profile;
    profile.layout = snapshot;
    for (const auto& device : snapshot.extension.devices())
        profile.devices.push_back({device.uuid, device.technicalName, DevicePermissions::None});
    EXPECT_FALSE(profile.isValid());
    expectLayoutEqual(config.screenLayout(), storedBefore);
}

TEST(ServerConfigEnvironmentTests, SnapshotBindsCapitalizationOnlyNameToExistingUuidWithoutMutation)
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath(QStringLiteral("server.ini")), QSettings::IniFormat);
    seedConfig(settings);
    TestServerConfig config(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
    const ScreenLayout storedBefore = config.screenLayout();
    config.editableScreens()[1].setName(QStringLiteral("ALPHA"));

    const auto snapshot = config.environmentLayoutSnapshot();

    ASSERT_TRUE(snapshot.extension.validate().isValid());
    ASSERT_EQ(snapshot.extension.devices().size(), 2u);
    EXPECT_EQ(snapshot.extension.devices()[0].technicalName, QStringLiteral("ALPHA"));
    EXPECT_EQ(snapshot.extension.devices()[0].uuid, alphaId);
    EXPECT_EQ(snapshot.extension.devices()[1].technicalName, QStringLiteral("beta"));
    EXPECT_EQ(snapshot.extension.devices()[1].uuid, betaId);
    EnvironmentProfile profile;
    profile.layout = snapshot;
    for (const auto& device : snapshot.extension.devices())
        profile.devices.push_back({device.uuid, device.technicalName, DevicePermissions::None});
    EXPECT_TRUE(profile.isValid());
    expectLayoutEqual(config.screenLayout(), storedBefore);
}

TEST(ServerConfigEnvironmentTests, CapitalizationOnlyApplicationPreservesCompleteScreenState)
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath(QStringLiteral("server.ini")), QSettings::IniFormat);
    seedConfig(settings);
    ServerConfig config(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
    const auto& screensBefore = static_cast<const ServerConfig&>(config).screens();
    const Screen alphaBefore = screensBefore[1];
    const auto pixmapBefore = alphaBefore.pixmap()->cacheKey();
    auto target = validTarget();
    target.gridTechnicalNames[4] = QStringLiteral("ALPHA");
    auto devices = target.extension.devices();
    devices[2].technicalName = QStringLiteral("ALPHA");
    target.extension = ScreenLayout(std::move(devices));

    ASSERT_TRUE(config.applyEnvironmentLayout(target));

    const Screen& alphaAfter = static_cast<const ServerConfig&>(config).screens()[4];
    EXPECT_EQ(alphaAfter.name(), QStringLiteral("ALPHA"));
    EXPECT_EQ(alphaAfter.aliases(), alphaBefore.aliases());
    EXPECT_EQ(alphaAfter.modifiers(), alphaBefore.modifiers());
    EXPECT_EQ(alphaAfter.switchCorners(), alphaBefore.switchCorners());
    EXPECT_EQ(alphaAfter.switchCornerSize(), alphaBefore.switchCornerSize());
    EXPECT_EQ(alphaAfter.fixes(), alphaBefore.fixes());
    EXPECT_EQ(alphaAfter.swapped(), alphaBefore.swapped());
    EXPECT_EQ(alphaAfter.pixmap()->cacheKey(), pixmapBefore);
}

TEST(ServerConfigEnvironmentTests, RejectsCanonicalAliasAndAliasAliasCollisionsWithoutMutation)
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath(QStringLiteral("server.ini")), QSettings::IniFormat);
    seedConfig(settings);
    settings.beginGroup(QStringLiteral("internalConfig"));
    settings.beginWriteArray(QStringLiteral("screens"));
    settings.setArrayIndex(9);
    settings.setValue(QStringLiteral("name"), QStringLiteral("beta"));
    settings.beginWriteArray(QStringLiteral("aliasArray"));
    settings.setArrayIndex(0);
    settings.setValue(QStringLiteral("alias"), QStringLiteral("alpha-alias"));
    settings.endArray();
    settings.endArray();
    settings.endGroup();
    settings.sync();
    ServerConfig config(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
    const auto before = stateOf(config);

    auto canonicalAlias = validTarget();
    canonicalAlias.gridTechnicalNames[2] = QStringLiteral("ALPHA-ALIAS");
    auto canonicalAliasDevices = canonicalAlias.extension.devices();
    canonicalAliasDevices[1].technicalName = QStringLiteral("ALPHA-ALIAS");
    canonicalAlias.extension = ScreenLayout(std::move(canonicalAliasDevices));
    EXPECT_FALSE(config.applyEnvironmentLayout(canonicalAlias));
    expectStateEqual(config, before);

    auto duplicateAlias = validTarget();
    duplicateAlias.gridTechnicalNames[2] = QStringLiteral("alpha-alias");
    auto duplicateAliasDevices = duplicateAlias.extension.devices();
    duplicateAliasDevices[1].technicalName = QStringLiteral("alpha-alias");
    duplicateAlias.extension = ScreenLayout(std::move(duplicateAliasDevices));
    EXPECT_FALSE(config.applyEnvironmentLayout(duplicateAlias));
    expectStateEqual(config, before);
}

TEST(ServerConfigEnvironmentTests, AliasIsNeverUsedAsCanonicalIdentity)
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath(QStringLiteral("server.ini")), QSettings::IniFormat);
    seedConfig(settings);
    ServerConfig config(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
    auto target = validTarget();
    target.gridTechnicalNames[2] = QStringLiteral("alpha-alias");
    target.gridTechnicalNames[4].clear();
    auto devices = target.extension.devices();
    devices[1].technicalName = QStringLiteral("alpha-alias");
    devices.erase(devices.begin() + 2);
    target.extension = ScreenLayout(std::move(devices));

    ASSERT_TRUE(config.applyEnvironmentLayout(target));
    const Screen& fresh = static_cast<const ServerConfig&>(config).screens()[2];
    EXPECT_EQ(fresh.name(), QStringLiteral("alpha-alias"));
    EXPECT_TRUE(fresh.aliases().isEmpty());
    EXPECT_EQ(fresh.switchCornerSize(), 0);
}

TEST(ServerConfigEnvironmentTests, RejectsStructuralResourceOverflowBeforeMutationOrSettingsIo)
{
    QTemporaryDir directory;
    const QString path = directory.filePath(QStringLiteral("server.ini"));
    QSettings settings(path, QSettings::IniFormat);
    seedConfig(settings);
    ServerConfig config(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
    const auto before = stateOf(config);
    settings.sync();
    QFile beforeFile(path);
    ASSERT_TRUE(beforeFile.open(QIODevice::ReadOnly));
    const QByteArray bytesBefore = beforeFile.readAll();

    QList<EnvironmentProfile::Layout> invalid;
    auto tooWide = validTarget(); tooWide.columns = ServerConfig::MaxColumns + 1; invalid.push_back(tooWide);
    auto tooTall = validTarget(); tooTall.rows = ServerConfig::MaxRows + 1; invalid.push_back(tooTall);
    auto tooManyCells = validTarget(); tooManyCells.columns = ServerConfig::MaxColumns;
    tooManyCells.rows = ServerConfig::MaxRows; tooManyCells.gridTechnicalNames.push_back(QString()); invalid.push_back(tooManyCells);
    auto tooManyDevices = validTarget();
    auto devices = tooManyDevices.extension.devices();
    while (devices.size() <= static_cast<size_t>(ServerConfig::MaxGridCells))
        devices.push_back(layoutDevice(QUuid::createUuid(), QStringLiteral("extra-%1").arg(devices.size()),
                                      QRect(static_cast<int>(devices.size()) * 100, 0, 100, 100)));
    tooManyDevices.extension = ScreenLayout(std::move(devices)); invalid.push_back(tooManyDevices);
    auto tooManyMonitors = validTarget(); devices = tooManyMonitors.extension.devices();
    devices[0].monitors.assign(ScreenLayout::MaxMonitorsPerDevice + 1,
                               {QStringLiteral("monitor"), QRect(0, 0, 1, 1)});
    tooManyMonitors.extension = ScreenLayout(std::move(devices)); invalid.push_back(tooManyMonitors);

    for (const auto& candidate : invalid) {
        EXPECT_FALSE(config.applyEnvironmentLayout(candidate));
        expectStateEqual(config, before);
    }
    QFile afterFile(path);
    ASSERT_TRUE(afterFile.open(QIODevice::ReadOnly));
    EXPECT_EQ(afterFile.readAll(), bytesBefore);
}

TEST(ServerConfigEnvironmentTests, AcceptsMaximumGridDimensions)
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath(QStringLiteral("server.ini")), QSettings::IniFormat);
    seedConfig(settings);
    ServerConfig config(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
    auto target = config.environmentLayoutSnapshot();
    ASSERT_EQ(target.columns, ServerConfig::MaxColumns);
    ASSERT_EQ(target.rows, ServerConfig::MaxRows);
    ASSERT_EQ(target.gridTechnicalNames.size(), ServerConfig::MaxGridCells);
    EXPECT_TRUE(config.applyEnvironmentLayout(target));
}
