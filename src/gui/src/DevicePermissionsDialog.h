#pragma once

#include "DevicePermissions.h"
#include <QDialog>

class DeviceRegistry;
class QComboBox;
class QLabel;
class QCheckBox;

class DevicePermissionsDialog : public QDialog {
    Q_OBJECT
public:
    enum class Preset { FullAccess, ControlOnly, FilesOnly, Custom };
    DevicePermissionsDialog(DeviceRegistry& registry, const QUuid& uuid, QWidget* parent = nullptr);
    static DevicePermissions::Mask maskForPreset(Preset preset);
    bool applyPreset(Preset preset);
    bool revokeAll();
    QString statusText() const;

private:
    bool applyMask(DevicePermissions::Mask mask);
    DevicePermissions::Mask selectedMask() const;
    void setControlsMask(DevicePermissions::Mask mask);
    void updatePresetView();
    void refreshState();
    DeviceRegistry& registry_;
    QUuid uuid_;
    QLabel* explanation_;
    QLabel* status_;
    QComboBox* preset_;
    QCheckBox* controlMouseKeyboard_;
    QCheckBox* sendFiles_;
    QCheckBox* receiveFiles_;
    QCheckBox* shareClipboard_;
    QCheckBox* autoConnect_;
};
