#include "DevicePermissions.h"

#include <QStringList>

namespace { constexpr DevicePermissions::Mask Known = (1u << 6) - 1; }

DevicePermissions::Mask DevicePermissions::forDevice(const QUuid& uuid) const
{
    if (!isKnown(uuid)) return defaults();
    return permissions_.value(uuid, defaults()) & Known;
}

bool DevicePermissions::allows(const QUuid& uuid, Permission permission) const
{
    const Mask bit = static_cast<Mask>(permission);
    return isKnown(uuid) && bit != 0 && (forDevice(uuid) & bit) == bit;
}

bool DevicePermissions::set(const QUuid& uuid, Mask mask)
{
    if (!isKnown(uuid) || (mask & ~Known) != 0) return false;
    if (mask == defaults()) permissions_.remove(uuid);
    else permissions_.insert(uuid, mask);
    return true;
}

bool DevicePermissions::grant(const QUuid& uuid, Permission permission)
{
    if (!isKnown(uuid) || (static_cast<Mask>(permission) & ~Known) != 0) return false;
    return set(uuid, forDevice(uuid) | static_cast<Mask>(permission));
}

bool DevicePermissions::revoke(const QUuid& uuid, Permission permission)
{
    if (!isKnown(uuid) || (static_cast<Mask>(permission) & ~Known) != 0) return false;
    return set(uuid, forDevice(uuid) & ~static_cast<Mask>(permission));
}

bool DevicePermissions::clear(const QUuid& uuid)
{
    if (!isKnown(uuid)) return false;
    permissions_.remove(uuid);
    return true;
}

QStringList DevicePermissions::labels(Mask mask) const
{
    QStringList result;
    if (mask & ControlMouseKeyboard) result << QStringLiteral("Controlar mouse e teclado");
    if (mask & SendFiles) result << QStringLiteral("Enviar arquivos");
    if (mask & ReceiveFiles) result << QStringLiteral("Receber arquivos");
    if (mask & ShareClipboard) result << QStringLiteral("Compartilhar área de transferência");
    if (mask & AutoConnect) result << QStringLiteral("Conexão automática");
    if (mask & OpenSafeFiles) result << QStringLiteral("Abrir arquivos seguros");
    return result;
}

QString DevicePermissions::serialize(const QUuid& uuid) const
{
    return QString::number(forDevice(uuid));
}

bool DevicePermissions::deserialize(const QUuid& uuid, const QString& value)
{
    if (!isKnown(uuid) || value.isEmpty()) return false;
    bool ok = false;
    const quint64 parsed = value.toULongLong(&ok);
    if (!ok || parsed > Known) return false;
    return set(uuid, static_cast<Mask>(parsed));
}
