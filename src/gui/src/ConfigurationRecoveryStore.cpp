/* InputLeap -- strict public snapshot for local configuration recovery. */
#include "ConfigurationRecoveryStore.h"

#include "ConfigurationPackageCodec.h"

#include <QJsonObject>

QByteArray ConfigurationRecoveryStore::encodeSnapshot(
    const ConfigurationPortablePreferences& preferences)
{
    ConfigurationPackageCodec::Package package;
    package.publicData.insert(
        QStringLiteral("preferences"),
        ConfigurationPortablePreferencesCodec::encode(preferences));
    return ConfigurationPackageCodec::encode(package);
}

ConfigurationRecoveryStore::DecodeResult
ConfigurationRecoveryStore::decodeSnapshot(const QByteArray& encoded)
{
    const auto package = ConfigurationPackageCodec::decode(encoded);
    if (package.error != ConfigurationPackageCodec::Error::None || !package.package)
        return {Error::InvalidPackage, std::nullopt};
    if (package.package->sensitive)
        return {Error::SensitiveForbidden, std::nullopt};
    if (package.package->publicData.keys() !=
        QStringList{QStringLiteral("preferences")} ||
        !package.package->publicData.value(QStringLiteral("preferences")).isObject()) {
        return {Error::InvalidPublicSection, std::nullopt};
    }

    auto preferences = ConfigurationPortablePreferencesCodec::decode(
        package.package->publicData.value(QStringLiteral("preferences")).toObject());
    if (preferences.error != ConfigurationPortablePreferencesCodec::Error::None ||
        !preferences.preferences) {
        return {Error::InvalidPreferences, std::nullopt};
    }
    return {Error::None, std::move(preferences.preferences)};
}
