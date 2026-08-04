/* InputLeap -- canonical environment profile model. */
#pragma once

#include "DevicePermissions.h"
#include "ScreenSetupModel.h"

#include <QList>
#include <QString>
#include <QStringList>
#include <QUuid>

#include <optional>

class EnvironmentProfile
{
public:
    enum class Kind { Home, Office, Travel, Presentation };

    struct Device {
        QUuid uuid;
        QString technicalName;
        DevicePermissions::Mask requestedResources = DevicePermissions::None;
        bool operator==(const Device&) const = default;
    };

    struct Layout {
        int columns = 0;
        int rows = 0;
        QStringList gridTechnicalNames;
        ScreenLayout extension;
    };

    static constexpr DevicePermissions::Mask ManagedResources =
        DevicePermissions::ControlMouseKeyboard |
        DevicePermissions::SendFiles |
        DevicePermissions::ReceiveFiles |
        DevicePermissions::ShareClipboard |
        DevicePermissions::AutoConnect;

    Kind kind = Kind::Home;
    Layout layout;
    QList<Device> devices;

    bool isValid() const;
    std::optional<Device> device(const QUuid& uuid) const;
    DevicePermissions::Mask requestedResourcesFor(const QUuid& uuid) const;
    bool requests(const QUuid& uuid, DevicePermissions::Permission permission) const;

    static QString key(Kind kind);
    static std::optional<Kind> fromKey(const QString& key);
    static QString canonicalDisplayName(Kind kind);
    static QList<Kind> canonicalKinds();
};
