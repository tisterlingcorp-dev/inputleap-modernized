#include "LocalDeviceIdentity.h"

#include <QSettings>

namespace {
QString canonical(const QUuid& uuid) { return uuid.toString(QUuid::WithoutBraces).toLower(); }
bool valid(const QString& text, QUuid& uuid)
{
    uuid = QUuid(text);
    return !uuid.isNull() && text == canonical(uuid);
}
}

LocalDeviceIdentityResult LocalDeviceIdentity::loadOrCreate(QSettings& settings, SyncFunction sync)
{
    constexpr auto legacyKey = "localDeviceIdentity/uuid";
    constexpr auto activeKey = "localDeviceIdentity/activeGeneration";
    constexpr auto generations = "localDeviceIdentity/generations/";
    if (!sync) sync = [](QSettings& value) { value.sync(); return value.status() == QSettings::NoError; };

    const QString active = settings.value(activeKey).toString();
    const QString key = active.isEmpty() ? QString(legacyKey) : QString(generations) + active + "/uuid";
    const QString stored = settings.value(key).toString();
    if (!stored.isEmpty()) {
        QUuid uuid;
        if (valid(stored, uuid)) return {true, uuid, {}};
        return {false, {}, QStringLiteral("Identidade local persistida inválida")};
    }
    if (!active.isEmpty()) return {false, {}, QStringLiteral("Geração ativa da identidade local inválida")};

    const QUuid created = QUuid::createUuid();
    const QString text = canonical(created);
    const QString generation = canonical(QUuid::createUuid());
    const QString stagedKey = QString(generations) + generation + "/uuid";
    settings.setValue(stagedKey, text);
    if (!sync(settings) || settings.value(stagedKey).toString() != text) {
        return {false, {}, QStringLiteral("Falha ao persistir identidade local")};
    }

    const QString previousActive = settings.value(activeKey).toString();
    settings.setValue(activeKey, generation);
    if (!sync(settings) || settings.value(activeKey).toString() != generation || settings.value(stagedKey).toString() != text) {
        if (previousActive.isEmpty()) settings.remove(activeKey);
        else settings.setValue(activeKey, previousActive);
        if (!sync(settings)) {
            return {false, {}, QStringLiteral("Falha ao restaurar identidade local anterior")};
        }
        return {false, {}, QStringLiteral("Falha ao promover identidade local")};
    }
    return {true, created, {}};
}

LocalDeviceIdentityResult LocalDeviceIdentity::loadExisting(QSettings& settings)
{
    constexpr auto legacyKey = "localDeviceIdentity/uuid";
    constexpr auto activeKey = "localDeviceIdentity/activeGeneration";
    constexpr auto generations = "localDeviceIdentity/generations/";
    const QString active = settings.value(activeKey).toString();
    const QString key = active.isEmpty() ? QString(legacyKey)
                                         : QString(generations) + active + "/uuid";
    const QString stored = settings.value(key).toString();
    if (stored.isEmpty()) {
        return {false, {}, active.isEmpty()
            ? QStringLiteral("Identidade local ainda não persistida")
            : QStringLiteral("Geração ativa da identidade local inválida")};
    }
    QUuid uuid;
    if (!valid(stored, uuid))
        return {false, {}, QStringLiteral("Identidade local persistida inválida")};
    return {true, uuid, {}};
}
