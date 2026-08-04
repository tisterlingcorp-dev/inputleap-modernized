#include "DevicePermissions.h"
#include "DeviceRegistry.h"
#include "DeviceInfo.h"
#include <gtest/gtest.h>
#include <QSettings>
#include <QTemporaryDir>

TEST(DevicePermissionsTests, DefaultsAreFailClosedAndUuidScoped)
{
    DevicePermissions permissions;
    const QUuid known = QUuid::createUuid();
    EXPECT_EQ(permissions.forDevice({}), DevicePermissions::None);
    EXPECT_FALSE(permissions.allows({}, DevicePermissions::ShareClipboard));
    EXPECT_FALSE(permissions.allows(known, DevicePermissions::ShareClipboard));
    EXPECT_TRUE(permissions.grant(known, DevicePermissions::ShareClipboard));
    EXPECT_TRUE(permissions.allows(known, DevicePermissions::ShareClipboard));
    EXPECT_FALSE(permissions.allows(QUuid::createUuid(), DevicePermissions::ShareClipboard));
}

TEST(DevicePermissionsTests, RevocationIsImmediateAndSerializationContainsOnlyMask)
{
    DevicePermissions permissions;
    const QUuid id = QUuid::createUuid();
    ASSERT_TRUE(permissions.set(id, DevicePermissions::ControlMouseKeyboard | DevicePermissions::SendFiles));
    EXPECT_EQ(permissions.serialize(id), "3");
    ASSERT_TRUE(permissions.revoke(id, DevicePermissions::SendFiles));
    EXPECT_FALSE(permissions.allows(id, DevicePermissions::SendFiles));
    EXPECT_EQ(permissions.labels(permissions.forDevice(id)).size(), 1);
    EXPECT_FALSE(permissions.deserialize(id, "999"));
}

TEST(DevicePermissionsTests, RegistryPersistsByExactUuidWithLeastPrivilegeDefault)
{
    QTemporaryDir directory;
    const QString path = directory.filePath("permissions.ini");
    const QUuid id = QUuid::createUuid();
    { QSettings settings(path, QSettings::IniFormat); DeviceRegistry registry(settings);
      DeviceInfo device(id); device.setTechnicalName("peer"); ASSERT_EQ(registry.add(device), DeviceRegistry::AddResult::Added);
      EXPECT_EQ(registry.permissions(id), DevicePermissions::None);
      ASSERT_TRUE(registry.setPermissions(id, DevicePermissions::ReceiveFiles));
      EXPECT_EQ(registry.permissions(id), DevicePermissions::ReceiveFiles); }
    { QSettings settings(path, QSettings::IniFormat); DeviceRegistry registry(settings);
      EXPECT_EQ(registry.permissions(id), DevicePermissions::ReceiveFiles);
      EXPECT_FALSE(registry.setPermissions(QUuid::createUuid(), DevicePermissions::SendFiles)); }
}
