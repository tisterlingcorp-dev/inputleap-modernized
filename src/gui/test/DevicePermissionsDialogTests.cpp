#include "DevicePermissionsDialog.h"
#include "DeviceRegistry.h"
#include "DeviceInfo.h"
#include <gtest/gtest.h>
#include <QApplication>
#include <QComboBox>
#include <QCheckBox>
#include <QSettings>
#include <QTemporaryDir>

namespace {
struct Fixture {
    QTemporaryDir dir;
    QSettings settings{dir.filePath("devices.ini"), QSettings::IniFormat};
    DeviceRegistry registry{settings};
    QUuid uuid = QUuid::createUuid();
    Fixture() { DeviceInfo device(uuid); device.setTechnicalName("peer"); EXPECT_EQ(registry.add(device), DeviceRegistry::AddResult::Added); }
};
}

TEST(DevicePermissionsDialog, PresetsOnlyUseSupportedLeastPrivilegeFlags)
{
    EXPECT_EQ(DevicePermissionsDialog::maskForPreset(DevicePermissionsDialog::Preset::FullAccess),
              DevicePermissions::ControlMouseKeyboard | DevicePermissions::SendFiles |
              DevicePermissions::ReceiveFiles | DevicePermissions::ShareClipboard |
              DevicePermissions::AutoConnect);
    EXPECT_EQ(DevicePermissionsDialog::maskForPreset(DevicePermissionsDialog::Preset::ControlOnly), DevicePermissions::ControlMouseKeyboard);
    EXPECT_EQ(DevicePermissionsDialog::maskForPreset(DevicePermissionsDialog::Preset::FilesOnly), DevicePermissions::SendFiles | DevicePermissions::ReceiveFiles);
    EXPECT_EQ(DevicePermissionsDialog::maskForPreset(DevicePermissionsDialog::Preset::Custom), DevicePermissions::None);
    EXPECT_EQ(DevicePermissionsDialog::maskForPreset(DevicePermissionsDialog::Preset::FullAccess) & DevicePermissions::OpenSafeFiles, 0u);
}

TEST(DevicePermissionsDialog, CustomPresetEditsEachPermissionWithAccessibleControls)
{
    Fixture f;
    DevicePermissionsDialog dialog(f.registry, f.uuid);
    auto* preset = dialog.findChild<QComboBox*>();
    ASSERT_NE(preset, nullptr);
    preset->setCurrentIndex(preset->findData(int(DevicePermissionsDialog::Preset::Custom)));
    const auto checks = dialog.findChildren<QCheckBox*>();
    ASSERT_EQ(checks.size(), 5);
    for (auto* check : checks) if (check->accessibleName().contains(QStringLiteral("enviar"))) check->setChecked(true);
    ASSERT_TRUE(dialog.applyPreset(DevicePermissionsDialog::Preset::Custom));
    EXPECT_EQ(f.registry.permissions(f.uuid), DevicePermissions::SendFiles);
}
TEST(DevicePermissionsDialog, AppliesAndRevokesImmediatelyByExactUuid)
{
    Fixture f;
    DevicePermissionsDialog dialog(f.registry, f.uuid);
    ASSERT_TRUE(dialog.applyPreset(DevicePermissionsDialog::Preset::FilesOnly));
    EXPECT_EQ(f.registry.permissions(f.uuid), DevicePermissions::SendFiles | DevicePermissions::ReceiveFiles);
    EXPECT_TRUE(dialog.revokeAll());
    EXPECT_EQ(f.registry.permissions(f.uuid), DevicePermissions::None);
    EXPECT_EQ(dialog.statusText(), QStringLiteral("Nenhuma permissão ativa"));
}

TEST(DevicePermissionsDialog, UnknownUuidAndSaveFailureNeverReportSuccess)
{
    Fixture f;
    DevicePermissionsDialog unknown(f.registry, {});
    EXPECT_FALSE(unknown.applyPreset(DevicePermissionsDialog::Preset::FullAccess));
    EXPECT_FALSE(unknown.statusText().contains(QStringLiteral("salvas"), Qt::CaseInsensitive));
    DeviceRegistry failing(f.settings, [](QSettings&) { return false; });
    DevicePermissionsDialog failed(failing, f.uuid);
    EXPECT_FALSE(failed.applyPreset(DevicePermissionsDialog::Preset::ControlOnly));
    EXPECT_EQ(failing.permissions(f.uuid), DevicePermissions::None);
}