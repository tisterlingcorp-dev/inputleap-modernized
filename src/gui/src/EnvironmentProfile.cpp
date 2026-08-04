/* InputLeap -- canonical environment profile model. */
#include "EnvironmentProfile.h"

#include <QHash>
#include <QSet>

namespace {
bool isAsciiAlphaNumeric(QChar character)
{
    const ushort value = character.unicode();
    return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
           (value >= '0' && value <= '9');
}

bool isCoreComponentEdge(QChar character)
{
    return isAsciiAlphaNumeric(character) || character == QLatin1Char('_');
}

bool validTechnicalName(const QString& name)
{
    // Keep this in lockstep with Config::isValidScreenName's validname grammar.
    // That public method is instance-bound and validates locale-sensitive bytes,
    // so it cannot safely validate a QString here without a GUI-to-server dependency.
    // Grammar: ASCII alphanumeric/underscore component edges, hyphens only
    // inside a component, dot-separated non-empty components, and the legacy
    // trailing dot.
    if (name.isEmpty() || name.size() > ScreenLayout::MaxTechnicalNameBytes) {
        return false;
    }

    qsizetype componentBegin = 0;
    for (;;) {
        if (componentBegin == name.size()) {
            return true; // The core intentionally accepts one trailing dot.
        }

        qsizetype componentEnd = name.indexOf(QLatin1Char('.'), componentBegin);
        if (componentEnd < 0) {
            componentEnd = name.size();
        }
        if (componentEnd == componentBegin || !isCoreComponentEdge(name[componentBegin]) ||
            !isCoreComponentEdge(name[componentEnd - 1])) {
            return false;
        }
        for (qsizetype i = componentBegin; i < componentEnd; ++i) {
            const auto character = name[i];
            if (!isCoreComponentEdge(character) && character != QLatin1Char('-')) {
                return false;
            }
        }
        if (componentEnd == name.size()) {
            return true;
        }
        componentBegin = componentEnd + 1;
    }
}

QString coreNameCollisionKey(const QString& name)
{
    return name.toLower();
}
}

bool EnvironmentProfile::isValid() const
{
    if (!canonicalKinds().contains(kind)) {
        return false;
    }
    if (layout.columns < 1 || layout.columns > 16 || layout.rows < 1 || layout.rows > 16) {
        return false;
    }

    const qsizetype cellCount = qsizetype(layout.columns) * layout.rows;
    if (cellCount < 1 || cellCount > ScreenLayout::MaxDevices ||
        layout.gridTechnicalNames.size() != cellCount || !layout.extension.validate().isValid()) {
        return false;
    }

    QSet<QString> gridNames;
    QSet<QString> gridNameKeys;
    for (const auto& name : layout.gridTechnicalNames) {
        if (name.isEmpty()) {
            continue;
        }
        const auto collisionKey = coreNameCollisionKey(name);
        if (!validTechnicalName(name) || gridNameKeys.contains(collisionKey)) {
            return false;
        }
        gridNames.insert(name);
        gridNameKeys.insert(collisionKey);
    }

    QHash<QUuid, QString> profileNamesByUuid;
    QSet<QString> profileNames;
    QSet<QString> profileNameKeys;
    for (const auto& profileDevice : devices) {
        const auto collisionKey = coreNameCollisionKey(profileDevice.technicalName);
        if (profileDevice.uuid.isNull() || !validTechnicalName(profileDevice.technicalName) ||
            (profileDevice.requestedResources & ~ManagedResources) != 0 ||
            profileNamesByUuid.contains(profileDevice.uuid) || profileNameKeys.contains(collisionKey)) {
            return false;
        }
        profileNamesByUuid.insert(profileDevice.uuid, profileDevice.technicalName);
        profileNames.insert(profileDevice.technicalName);
        profileNameKeys.insert(collisionKey);
    }

    const auto& extensionDevices = layout.extension.devices();
    if (extensionDevices.size() != static_cast<size_t>(devices.size()) ||
        gridNames.size() != devices.size() || gridNames != profileNames) {
        return false;
    }

    QSet<QUuid> extensionUuids;
    QSet<QString> extensionNames;
    QSet<QString> extensionNameKeys;
    for (const auto& extensionDevice : extensionDevices) {
        const auto collisionKey = coreNameCollisionKey(extensionDevice.technicalName);
        if (extensionDevice.uuid.isNull() || !validTechnicalName(extensionDevice.technicalName) ||
            extensionUuids.contains(extensionDevice.uuid) || extensionNameKeys.contains(collisionKey) ||
            profileNamesByUuid.value(extensionDevice.uuid) != extensionDevice.technicalName) {
            return false;
        }
        extensionUuids.insert(extensionDevice.uuid);
        extensionNames.insert(extensionDevice.technicalName);
        extensionNameKeys.insert(collisionKey);
    }

    return extensionNames == gridNames && extensionUuids.size() == devices.size();
}

std::optional<EnvironmentProfile::Device> EnvironmentProfile::device(const QUuid& uuid) const
{
    if (uuid.isNull()) {
        return std::nullopt;
    }

    std::optional<Device> found;
    for (const auto& candidate : devices) {
        if (candidate.uuid != uuid) {
            continue;
        }
        if (found.has_value()) {
            return std::nullopt;
        }
        found = candidate;
    }
    return found;
}

DevicePermissions::Mask EnvironmentProfile::requestedResourcesFor(const QUuid& uuid) const
{
    const auto profileDevice = device(uuid);
    if (!profileDevice.has_value() || (profileDevice->requestedResources & ~ManagedResources) != 0) {
        return DevicePermissions::None;
    }
    return profileDevice->requestedResources;
}

bool EnvironmentProfile::requests(const QUuid& uuid, DevicePermissions::Permission permission) const
{
    const auto requested = static_cast<DevicePermissions::Mask>(permission);
    return requested != DevicePermissions::None && (requested & ~ManagedResources) == 0 &&
           (requestedResourcesFor(uuid) & requested) == requested;
}

QString EnvironmentProfile::key(Kind kind)
{
    switch (kind) {
    case Kind::Home: return QStringLiteral("home");
    case Kind::Office: return QStringLiteral("office");
    case Kind::Travel: return QStringLiteral("travel");
    case Kind::Presentation: return QStringLiteral("presentation");
    }
    return {};
}

std::optional<EnvironmentProfile::Kind> EnvironmentProfile::fromKey(const QString& key)
{
    for (const auto kind : canonicalKinds()) {
        if (EnvironmentProfile::key(kind) == key) {
            return kind;
        }
    }
    return std::nullopt;
}

QString EnvironmentProfile::canonicalDisplayName(Kind kind)
{
    switch (kind) {
    case Kind::Home: return QStringLiteral("Casa");
    case Kind::Office: return QStringLiteral("Escritório");
    case Kind::Travel: return QStringLiteral("Viagem");
    case Kind::Presentation: return QStringLiteral("Apresentação");
    }
    return {};
}

QList<EnvironmentProfile::Kind> EnvironmentProfile::canonicalKinds()
{
    return {Kind::Home, Kind::Office, Kind::Travel, Kind::Presentation};
}
