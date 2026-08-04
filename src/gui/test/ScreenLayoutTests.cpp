/*
 * InputLeap -- mouse and keyboard sharing utility
 */
#include "ScreenSetupModel.h"

#include <gtest/gtest.h>
#include <QFile>
#include <QSettings>
#include <QTemporaryDir>

namespace {
const QUuid id1("{11111111-1111-1111-1111-111111111111}");
const QUuid id2("{22222222-2222-2222-2222-222222222222}");

ScreenLayout::Device device(const QUuid& id, const QString& name, const QRect& geometry)
{
    ScreenLayout::Device result;
    result.uuid = id;
    result.technicalName = name;
    result.geometry = geometry;
    return result;
}
}

TEST(ScreenLayoutTests, AcceptsConnectedValidPositions)
{
    ScreenLayout layout({device(id1, "server", {0, 0, 100, 100}),
                         device(id2, "client", {100, 0, 100, 100})});
    EXPECT_TRUE(layout.validate().isValid());
}

TEST(ScreenLayoutTests, ReportsCollisionAndDisconnectedIsland)
{
    ScreenLayout collision({device(id1, "server", {0, 0, 100, 100}),
                            device(id2, "client", {50, 0, 100, 100})});
    EXPECT_TRUE(collision.validate().has(ScreenLayout::Issue::Collision));

    ScreenLayout island({device(id1, "server", {0, 0, 100, 100}),
                         device(id2, "client", {300, 0, 100, 100})});
    EXPECT_TRUE(island.validate().has(ScreenLayout::Issue::Disconnected));
}

TEST(ScreenLayoutTests, SupportsStableRelativeMultipleMonitors)
{
    auto workstation = device(id1, "server", {0, 0, 200, 100});
    workstation.monitors = {{"left", {0, 0, 100, 100}}, {"right", {100, 0, 100, 100}}};
    ScreenLayout layout({workstation});
    EXPECT_TRUE(layout.validate().isValid());
    EXPECT_EQ(layout.devices().front().monitors.front().id, "left");
}

TEST(ScreenLayoutTests, RejectsMonitorsOutsideTheirDeviceAndRepairsThemInside)
{
    auto workstation = device(id1, "server", {100, 50, 200, 100});
    workstation.monitors = {{"partial", {150, 0, 100, 100}}};
    ScreenLayout partial({workstation});
    EXPECT_FALSE(partial.validate().isValid());
    EXPECT_TRUE(partial.validate().has(ScreenLayout::Issue::InvalidRectangle));

    workstation.monitors = {{"outside", {250, 10, 50, 50}}};
    ScreenLayout outside({workstation});
    EXPECT_FALSE(outside.validate().isValid());

    const ScreenLayout repaired = outside.repaired();
    ASSERT_TRUE(repaired.validate().isValid());
    ASSERT_EQ(repaired.devices().front().monitors.size(), 1u);
    const QRect localBounds(QPoint(0, 0), repaired.devices().front().geometry.size());
    EXPECT_TRUE(localBounds.contains(repaired.devices().front().monitors.front().geometry));
}

TEST(ScreenLayoutTests, RejectsNullAndDuplicatedUuidsWithoutChangingIdentity)
{
    ScreenLayout layout({device({}, "null", {0, 0, 100, 100}),
                         device(id1, "first", {100, 0, 100, 100}),
                         device(id1, "second", {200, 0, 100, 100})});
    const auto validation = layout.validate();
    EXPECT_TRUE(validation.has(ScreenLayout::Issue::NullUuid));
    EXPECT_TRUE(validation.has(ScreenLayout::Issue::DuplicateUuid));
    const ScreenLayout repaired = layout.repaired();
    EXPECT_TRUE(repaired.devices()[0].uuid.isNull());
    EXPECT_EQ(repaired.devices()[1].uuid, id1);
    EXPECT_EQ(repaired.devices()[2].uuid, id1);
    EXPECT_EQ(repaired.devices()[2].technicalName, "second");
}

TEST(ScreenLayoutTests, RepairsCollisionAndIslandDeterministically)
{
    ScreenLayout broken({device(id1, "server", {13, 7, 100, 100}),
                         device(id2, "client", {50, 20, 100, 100})});
    const ScreenLayout first = broken.repaired();
    const ScreenLayout second = broken.repaired();
    ASSERT_TRUE(first.validate().isValid());
    EXPECT_EQ(first.devices()[0].geometry, second.devices()[0].geometry);
    EXPECT_EQ(first.devices()[1].geometry, second.devices()[1].geometry);
    EXPECT_EQ(first.devices()[0].uuid, id1);
    EXPECT_EQ(first.devices()[1].technicalName, "client");
}

TEST(ScreenLayoutTests, MigratesAndRoundTripsLegacyNamesAsExtensionMetadata)
{
    const QStringList names{"server", "client"};
    const ScreenLayout migrated = ScreenLayout::fromLegacyGrid(names, 2, 1);
    ASSERT_TRUE(migrated.validate().isValid());
    ASSERT_EQ(migrated.devices().size(), 2u);
    EXPECT_FALSE(migrated.devices()[0].uuid.isNull());
    EXPECT_EQ(migrated.devices()[1].technicalName, "client");

    QTemporaryDir directory;
    QSettings settings(directory.filePath("layout.ini"), QSettings::IniFormat);
    EXPECT_TRUE(migrated.saveMetadata(settings));
    const auto loaded = ScreenLayout::loadMetadata(settings);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->devices()[0].uuid, migrated.devices()[0].uuid);
    EXPECT_EQ(loaded->devices()[1].technicalName, "client");
}

TEST(ScreenLayoutTests, PersistsNestedProfileGroupsInIsolation)
{
    const ScreenLayout profileA({device(id1, "home-server", {0, 0, 100, 100})});
    const ScreenLayout profileB({device(id2, "office-server", {200, 300, 120, 80})});
    QTemporaryDir directory;
    QSettings settings(directory.filePath("profiles.ini"), QSettings::IniFormat);

    ASSERT_TRUE(profileA.saveMetadata(settings, QStringLiteral("profileA/layout")));
    ASSERT_TRUE(profileB.saveMetadata(settings, QStringLiteral("profile-2/layout_v3")));
    ASSERT_TRUE(profileA.saveMetadata(settings, QStringLiteral("outer")));

    const auto loadedA = ScreenLayout::loadMetadata(settings, QStringLiteral("profileA/layout"));
    const auto loadedB = ScreenLayout::loadMetadata(settings, QStringLiteral("profile-2/layout_v3"));
    const auto loadedOuter = ScreenLayout::loadMetadata(settings, QStringLiteral("outer"));
    ASSERT_TRUE(loadedA.has_value());
    ASSERT_TRUE(loadedB.has_value());
    ASSERT_TRUE(loadedOuter.has_value());
    ASSERT_EQ(loadedA->devices().size(), 1u);
    ASSERT_EQ(loadedB->devices().size(), 1u);
    EXPECT_EQ(loadedA->devices().front().uuid, id1);
    EXPECT_EQ(loadedA->devices().front().technicalName, "home-server");
    EXPECT_EQ(loadedB->devices().front().uuid, id2);
    EXPECT_EQ(loadedB->devices().front().technicalName, "office-server");
    EXPECT_EQ(loadedB->devices().front().geometry, QRect(200, 300, 120, 80));
}

TEST(ScreenLayoutTests, RejectsMalformedMetadataGroupsWithoutTouchingSettings)
{
    const ScreenLayout layout({device(id1, "server", {0, 0, 100, 100})});
    const QStringList malformedGroups{
        QString(),
        QStringLiteral(" "),
        QStringLiteral("/layout"),
        QStringLiteral("layout/"),
        QStringLiteral("profile//layout"),
        QStringLiteral("."),
        QStringLiteral(".."),
        QStringLiteral("profile/./layout"),
        QStringLiteral("profile/../layout"),
        QStringLiteral("profile\\layout"),
        QStringLiteral(" profile/layout"),
        QStringLiteral("profile/layout "),
        QStringLiteral("profile /layout"),
        QStringLiteral("profile/ layout"),
        QStringLiteral("profile layout"),
        QStringLiteral("profile/\x01layout"),
        QStringLiteral("profile") + QChar(0x00a0) + QStringLiteral("layout"),
        QStringLiteral("profile") + QChar(0xff0f) + QStringLiteral("layout"),
        QStringLiteral("profile") + QChar(0x2215) + QStringLiteral("layout"),
        QStringLiteral("profile") + QChar(0x2044) + QStringLiteral("layout"),
        QStringLiteral("profil") + QChar(0x00e9) + QStringLiteral("/layout")};

    QTemporaryDir directory;
    const QString path = directory.filePath("malformed-groups.ini");
    QSettings settings(path, QSettings::IniFormat);
    settings.setValue(QStringLiteral("rootSentinel"), QStringLiteral("root-value"));
    settings.beginGroup(QStringLiteral("already/open"));
    settings.setValue(QStringLiteral("outerSentinel"), QStringLiteral("outer-value"));
    settings.sync();
    ASSERT_EQ(settings.status(), QSettings::NoError);
    QFile beforeFile(path);
    ASSERT_TRUE(beforeFile.open(QIODevice::ReadOnly));
    const QByteArray beforeBytes = beforeFile.readAll();
    beforeFile.close();
    const QString initialGroup = settings.group();
    const QStringList initialKeys = settings.allKeys();

    for (const QString& malformedGroup : malformedGroups) {
        EXPECT_FALSE(layout.saveMetadata(settings, malformedGroup)) << malformedGroup.toStdString();
        EXPECT_FALSE(ScreenLayout::loadMetadata(settings, malformedGroup).has_value())
            << malformedGroup.toStdString();
        EXPECT_EQ(settings.group(), initialGroup);
        EXPECT_EQ(settings.allKeys(), initialKeys);
        EXPECT_EQ(settings.value(QStringLiteral("outerSentinel")).toString(),
                  QStringLiteral("outer-value"));
    }

    settings.sync();
    ASSERT_EQ(settings.status(), QSettings::NoError);
    QFile afterFile(path);
    ASSERT_TRUE(afterFile.open(QIODevice::ReadOnly));
    EXPECT_EQ(afterFile.readAll(), beforeBytes);
    afterFile.close();

    settings.endGroup();
    EXPECT_EQ(settings.value(QStringLiteral("rootSentinel")).toString(), QStringLiteral("root-value"));
    EXPECT_FALSE(settings.contains(QStringLiteral("schemaVersion")));
}

TEST(ScreenLayoutTests, SupportsNestedMetadataGroupInsideAnOpenOuterGroup)
{
    const ScreenLayout layout({device(id1, "server", {0, 0, 100, 100})});
    QTemporaryDir directory;
    QSettings settings(directory.filePath("outer-group.ini"), QSettings::IniFormat);
    settings.beginGroup(QStringLiteral("outer"));
    settings.setValue(QStringLiteral("sentinel"), QStringLiteral("preserved"));

    const QString metadataGroup = QStringLiteral("profile-A_2/layout-1");
    ASSERT_TRUE(layout.saveMetadata(settings, metadataGroup));
    EXPECT_EQ(settings.group(), QStringLiteral("outer"));
    const auto loaded = ScreenLayout::loadMetadata(settings, metadataGroup);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(settings.group(), QStringLiteral("outer"));
    ASSERT_EQ(loaded->devices().size(), 1u);
    EXPECT_EQ(loaded->devices().front().uuid, id1);
    EXPECT_EQ(settings.value(QStringLiteral("sentinel")).toString(), QStringLiteral("preserved"));

    settings.endGroup();
    EXPECT_FALSE(settings.contains(metadataGroup + QStringLiteral("/schemaVersion")));
    EXPECT_TRUE(settings.contains(QStringLiteral("outer/") + metadataGroup + QStringLiteral("/schemaVersion")));
}

TEST(ScreenLayoutTests, FutureSchemaInNestedGroupIsReadOnly)
{
    QTemporaryDir directory;
    const QString path = directory.filePath("future.ini");
    QSettings settings(path, QSettings::IniFormat);
    settings.beginGroup(QStringLiteral("profileA/layout"));
    settings.setValue(QStringLiteral("schemaVersion"), 999);
    settings.setValue(QStringLiteral("opaquePayload"), QByteArray("\x00\x7f future payload", 17));
    settings.setValue(QStringLiteral("sentinel"), QStringLiteral("must-not-change"));
    settings.endGroup();
    settings.sync();
    ASSERT_EQ(settings.status(), QSettings::NoError);

    QFile beforeFile(path);
    ASSERT_TRUE(beforeFile.open(QIODevice::ReadOnly));
    const QByteArray beforeBytes = beforeFile.readAll();
    beforeFile.close();

    EXPECT_FALSE(ScreenLayout::loadMetadata(settings, QStringLiteral("profileA/layout")).has_value());

    settings.sync();
    ASSERT_EQ(settings.status(), QSettings::NoError);
    QFile afterFile(path);
    ASSERT_TRUE(afterFile.open(QIODevice::ReadOnly));
    EXPECT_EQ(afterFile.readAll(), beforeBytes);
    afterFile.close();
    settings.beginGroup(QStringLiteral("profileA/layout"));
    EXPECT_EQ(settings.value(QStringLiteral("schemaVersion")).toInt(), 999);
    EXPECT_EQ(settings.value(QStringLiteral("opaquePayload")).toByteArray(),
              QByteArray("\x00\x7f future payload", 17));
    EXPECT_EQ(settings.value(QStringLiteral("sentinel")).toString(), QStringLiteral("must-not-change"));
    EXPECT_EQ(settings.allKeys().size(), 3);
    settings.endGroup();
}

TEST(ScreenLayoutTests, OptionalSynchronizationDefersDurabilityToCaller)
{
    QTemporaryDir directory; const QString path = directory.filePath("deferred.ini");
    QSettings settings(path, QSettings::IniFormat);
    const ScreenLayout layout({device(id1, "server", {0, 0, 100, 100})});
    ASSERT_TRUE(layout.saveMetadata(settings, QStringLiteral("deferred/layout"), false));
    QFile beforeSync(path);
    if (beforeSync.open(QIODevice::ReadOnly)) EXPECT_FALSE(beforeSync.readAll().contains("schemaVersion"));
    settings.sync();
    QSettings afterSync(path, QSettings::IniFormat);
    EXPECT_TRUE(afterSync.contains(QStringLiteral("deferred/layout/schemaVersion")));
}

TEST(ScreenLayoutTests, RejectsMalformedMonitorDataAndResourceLimitOverflow)
{
    auto malformed = device(id1, "server", {0, 0, 100, 100});
    malformed.monitors = {{"same", {0, 0, 0, 100}}, {"same", {0, 0, 100, 100}}};
    ScreenLayout bad({malformed});
    EXPECT_TRUE(bad.validate().has(ScreenLayout::Issue::InvalidRectangle));
    EXPECT_TRUE(bad.validate().has(ScreenLayout::Issue::DuplicateMonitorId));

    std::vector<ScreenLayout::Device> excessive(ScreenLayout::MaxDevices + 1,
                                                 device(id1, "x", {0, 0, 1, 1}));
    EXPECT_TRUE(ScreenLayout(excessive).validate().has(ScreenLayout::Issue::ResourceLimit));
    ScreenLayout huge({device(id1, "server", {ScreenLayout::MaxCoordinate + 1, 0, 100, 100})});
    EXPECT_TRUE(huge.validate().has(ScreenLayout::Issue::ResourceLimit));
}

TEST(ScreenLayoutTests, StructuralOverflowReturnsBeforeQuadraticValidation)
{
    std::vector<ScreenLayout::Device> hugeDevices(
        static_cast<size_t>(ScreenLayout::MaxDevices) + 100000,
        device(id1, QStringLiteral("duplicate"), QRect(0, 0, 1, 1)));
    const auto devicesValidation = ScreenLayout(std::move(hugeDevices)).validate();
    EXPECT_TRUE(devicesValidation.has(ScreenLayout::Issue::ResourceLimit));
    EXPECT_FALSE(devicesValidation.has(ScreenLayout::Issue::Collision));
    EXPECT_FALSE(devicesValidation.has(ScreenLayout::Issue::DuplicateUuid));

    auto monitorFlood = device(id1, QStringLiteral("server"), QRect(0, 0, 100, 100));
    monitorFlood.monitors.assign(
        static_cast<size_t>(ScreenLayout::MaxMonitorsPerDevice) + 100000,
        {QStringLiteral("duplicate"), QRect(0, 0, 1, 1)});
    const auto monitorsValidation = ScreenLayout({std::move(monitorFlood)}).validate();
    EXPECT_TRUE(monitorsValidation.has(ScreenLayout::Issue::ResourceLimit));
    EXPECT_FALSE(monitorsValidation.has(ScreenLayout::Issue::Collision));
    EXPECT_FALSE(monitorsValidation.has(ScreenLayout::Issue::DuplicateMonitorId));
}

TEST(ScreenLayoutTests, SynchronizesLegacyGridWithoutLosingPersistentIdentity)
{
    ScreenLayout current({device(id1,"server",{0,0,100,100}),device(id2,"client",{100,0,100,100})});
    const auto synchronized=current.synchronizedToLegacyGrid({"client","new-device",""},3,1);
    ASSERT_EQ(synchronized.devices().size(),2u);
    EXPECT_EQ(synchronized.devices()[0].uuid,id2);
    EXPECT_EQ(synchronized.devices()[0].geometry,QRect(0,0,100,100));
    EXPECT_FALSE(synchronized.devices()[1].uuid.isNull());
    EXPECT_EQ(synchronized.devices()[1].technicalName,"new-device");
    EXPECT_TRUE(synchronized.validate().isValid());
}

TEST(ScreenLayoutTests, StrictSynchronizationRequiresCompleteExistingIdentityBinding)
{
    ScreenLayout current({device(id1,"server",{0,0,120,100}),device(id2,"client",{120,0,80,100})});

    const auto casingOnly = current.synchronizedToLegacyGridWithExistingIdentity(
        {"CLIENT", "server"}, 2, 1);
    ASSERT_TRUE(casingOnly.has_value());
    ASSERT_EQ(casingOnly->devices().size(), 2u);
    EXPECT_EQ(casingOnly->devices()[0].uuid, id2);
    EXPECT_EQ(casingOnly->devices()[0].technicalName, "CLIENT");
    EXPECT_EQ(casingOnly->devices()[1].uuid, id1);
    EXPECT_TRUE(casingOnly->validate().isValid());

    EXPECT_FALSE(current.synchronizedToLegacyGridWithExistingIdentity(
        {"client", "new-device"}, 2, 1).has_value());
    EXPECT_FALSE(current.synchronizedToLegacyGridWithExistingIdentity(
        {"client", ""}, 2, 1).has_value());

    auto duplicateUuid = current.devices();
    duplicateUuid[1].uuid = id1;
    EXPECT_FALSE(ScreenLayout(std::move(duplicateUuid)).synchronizedToLegacyGridWithExistingIdentity(
        {"server", "client"}, 2, 1).has_value());

    ScreenLayout duplicateName({device(id1,"server",{0,0,100,100}),
                                device(id2,"SERVER",{100,0,100,100})});
    EXPECT_FALSE(duplicateName.synchronizedToLegacyGridWithExistingIdentity(
        {"server", "client"}, 2, 1).has_value());
}

TEST(ScreenLayoutTests, RepairsInvalidAndOverlappingMonitorGeometry)
{
    auto workstation=device(id1,"server",{0,0,3,1});
    workstation.monitors={{"left",{0,0,0,1}},{"right",{0,0,2,1}}};
    const auto repaired=ScreenLayout({workstation}).repaired();
    ASSERT_TRUE(repaired.validate().isValid());
    EXPECT_EQ(repaired.devices()[0].monitors[0].id,"left");
    EXPECT_EQ(repaired.devices()[0].monitors[1].id,"right");
}

TEST(ScreenLayoutTests, RejectsInvalidIdentityAndOversizedStringsFromMetadata)
{
    QTemporaryDir directory;QSettings settings(directory.filePath("invalid.ini"),QSettings::IniFormat);
    settings.beginGroup("screenLayoutExtension");settings.setValue("schemaVersion",1);settings.beginWriteArray("devices");
    settings.setArrayIndex(0);settings.setValue("uuid",QString());settings.setValue("technicalName","invalid");settings.setValue("geometry",QRect(0,0,100,100));
    settings.endArray();settings.endGroup();
    EXPECT_FALSE(ScreenLayout::loadMetadata(settings).has_value());
    auto oversized=device(id1,QString(ScreenLayout::MaxTechnicalNameBytes+1,'x'),{0,0,100,100});
    EXPECT_TRUE(ScreenLayout({oversized}).validate().has(ScreenLayout::Issue::ResourceLimit));
}

TEST(ScreenLayoutTests, RejectsBracedAndUppercasePersistedDeviceUuids)
{
    const QStringList invalidUuids = {
        QStringLiteral("{11111111-1111-1111-1111-111111111111}"),
        QStringLiteral("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")};
    for (const QString& invalid : invalidUuids) {
        QTemporaryDir directory; QSettings settings(directory.filePath(QStringLiteral("uuid.ini")), QSettings::IniFormat);
        ASSERT_TRUE(ScreenLayout({device(id1, "server", {0, 0, 100, 100})}).saveMetadata(settings));
        settings.setValue(QStringLiteral("screenLayoutExtension/devices/1/uuid"), invalid); settings.sync();
        EXPECT_FALSE(ScreenLayout::loadMetadata(settings).has_value()) << invalid.toStdString();
    }
}

TEST(ScreenLayoutTests, RepairsAdjacentDeviceWithoutCrossingCoordinateLimit)
{
    ScreenLayout boundary({device(id1,"first",{900000,0,100000,100}),device(id2,"second",{900000,0,100000,100})});
    const auto repaired=boundary.repaired();
    EXPECT_TRUE(repaired.validate().isValid());
    EXPECT_GE(repaired.devices()[1].geometry.left(),-ScreenLayout::MaxCoordinate);
    EXPECT_LE(qint64(repaired.devices()[1].geometry.x())+repaired.devices()[1].geometry.width(),ScreenLayout::MaxCoordinate);
}

TEST(ScreenLayoutTests, RepairsMonitorIntoAvailableSpaceOnTheLeft)
{
    auto workstation=device(id1,"server",{0,0,3,1});
    workstation.monitors={{"wide",{1,0,2,1}},{"small",{1,0,1,1}}};
    const auto repaired=ScreenLayout({workstation}).repaired();
    ASSERT_TRUE(repaired.validate().isValid());
    EXPECT_EQ(repaired.devices()[0].monitors[1].geometry,QRect(0,0,1,1));
}

TEST(ScreenLayoutTests, LegacyRenameInSameCellPreservesUuid)
{
    ScreenLayout current({device(id1,"old-name",{0,0,100,100})});
    const auto renamed=current.synchronizedToLegacyGrid({"new-name"},1,1,{"old-name"});
    ASSERT_EQ(renamed.devices().size(),1u);EXPECT_EQ(renamed.devices()[0].uuid,id1);EXPECT_EQ(renamed.devices()[0].technicalName,"new-name");
}

TEST(ScreenLayoutTests, MonitorMetadataRoundTripsAndLegacyGetsOneLogicalDefault)
{
    auto workstation=device(id1,"server",{0,0,300,200});
    workstation.monitors={{"physical",{0,0,300,200},1.5,Qt::LandscapeOrientation,true}};
    QTemporaryDir directory; QSettings settings(directory.filePath("monitors.ini"),QSettings::IniFormat);
    ASSERT_TRUE(ScreenLayout({workstation}).saveMetadata(settings));
    const auto loaded=ScreenLayout::loadMetadata(settings); ASSERT_TRUE(loaded); ASSERT_EQ(loaded->devices()[0].monitors.size(),1u);
    EXPECT_DOUBLE_EQ(loaded->devices()[0].monitors[0].devicePixelRatio,1.5);
    EXPECT_EQ(loaded->devices()[0].monitors[0].orientation,Qt::LandscapeOrientation);
    EXPECT_TRUE(loaded->devices()[0].monitors[0].stableIdentity);
    const auto legacy=ScreenLayout::fromLegacyGrid({"old-client"},1,1);
    ASSERT_EQ(legacy.devices()[0].monitors.size(),1u);
    EXPECT_FALSE(legacy.devices()[0].monitors[0].stableIdentity);
    EXPECT_EQ(legacy.devices()[0].monitors[0].geometry,QRect(0,0,100,100));
}

TEST(ScreenLayoutTests, MonitorUpdateIsUuidIsolated)
{
    auto first=device(id1,"first",{0,0,100,100}); auto second=device(id2,"second",{100,0,100,100});
    ScreenLayout layout({first,second});
    ASSERT_TRUE(layout.updateMonitorsForDevice(id1,{{"local",{0,0,100,100}}}));
    ASSERT_EQ(layout.devices()[0].monitors.size(),1u);
    EXPECT_TRUE(layout.devices()[1].monitors.empty());
    EXPECT_FALSE(layout.updateMonitorsForDevice(QUuid::createUuid(),{{"wrong",{0,0,100,100}}}));
    EXPECT_TRUE(layout.devices()[1].monitors.empty());
}

TEST(ScreenLayoutTests, PersistenceRejectsOverlappingMonitorsAndBindIsTransactional)
{
    auto workstation=device(id1,"server",{0,0,100,100});workstation.monitors={{"a",{0,0,60,100}},{"b",{50,0,50,100}}};
    QTemporaryDir directory;QSettings settings(directory.filePath("overlap.ini"),QSettings::IniFormat);
    EXPECT_FALSE(ScreenLayout({workstation}).saveMetadata(settings));
    settings.beginGroup("screenLayoutExtension");settings.setValue("schemaVersion",2);settings.beginWriteArray("devices");settings.setArrayIndex(0);
    settings.setValue("uuid",id1.toString(QUuid::WithoutBraces));settings.setValue("technicalName","server");settings.setValue("geometry",QRect(0,0,100,100));settings.beginWriteArray("monitors");
    settings.setArrayIndex(0);settings.setValue("id","a");settings.setValue("geometry",QRect(0,0,60,100));settings.setArrayIndex(1);settings.setValue("id","b");settings.setValue("geometry",QRect(50,0,50,100));settings.endArray();settings.endArray();settings.endGroup();
    EXPECT_FALSE(ScreenLayout::loadMetadata(settings).has_value());
    ScreenLayout original({device(id1,"server",{0,0,100,100})});const auto before=original.devices()[0].uuid;
    EXPECT_FALSE(original.bindLocalDevice(id2,"server",{{"bad",{0,0,0,100}}}));EXPECT_EQ(original.devices()[0].uuid,before);
}
