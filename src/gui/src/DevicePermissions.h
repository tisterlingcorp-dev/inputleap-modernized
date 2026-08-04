/* InputLeap -- per-device least-privilege permissions. */
#pragma once

#include <QHash>
#include <QStringList>
#include <QUuid>

class DevicePermissions
{
public:
    enum Permission : quint32 {
        None = 0,
        ControlMouseKeyboard = 1u << 0,
        SendFiles = 1u << 1,
        ReceiveFiles = 1u << 2,
        ShareClipboard = 1u << 3,
        AutoConnect = 1u << 4,
        OpenSafeFiles = 1u << 5,
    };
    using Mask = quint32;

    static constexpr Mask defaults() { return None; }
    static bool isKnown(const QUuid& uuid) { return !uuid.isNull(); }
    Mask forDevice(const QUuid& uuid) const;
    bool allows(const QUuid& uuid, Permission permission) const;
    bool set(const QUuid& uuid, Mask mask);
    bool grant(const QUuid& uuid, Permission permission);
    bool revoke(const QUuid& uuid, Permission permission);
    bool clear(const QUuid& uuid);
    QStringList labels(Mask mask) const;
    QString serialize(const QUuid& uuid) const;
    bool deserialize(const QUuid& uuid, const QString& value);

private:
    QHash<QUuid, Mask> permissions_;
};

constexpr DevicePermissions::Permission operator|(DevicePermissions::Permission a, DevicePermissions::Permission b)
{
    return static_cast<DevicePermissions::Permission>(static_cast<DevicePermissions::Mask>(a) | static_cast<DevicePermissions::Mask>(b));
}
