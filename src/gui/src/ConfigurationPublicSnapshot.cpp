/* InputLeap -- typed public configuration snapshot without secrets. */
#include "ConfigurationPublicSnapshot.h"

#include <QSet>
#include <QStringList>

#include <utility>

namespace {
const QString PreferencesKey = QStringLiteral("preferences");
const QString EnvironmentProfilesKey = QStringLiteral("environmentProfiles");
}

QJsonObject ConfigurationPublicSnapshotCodec::encode(const ConfigurationPublicSnapshot& snapshot)
{
    return {{PreferencesKey, ConfigurationPortablePreferencesCodec::encode(snapshot.preferences)},
            {EnvironmentProfilesKey, EnvironmentProfileJsonCodec::encode(snapshot.environmentProfiles)}};
}

ConfigurationPublicSnapshotCodec::DecodeResult
ConfigurationPublicSnapshotCodec::decode(const QJsonObject& object)
{
    const QSet<QString> allowed{PreferencesKey, EnvironmentProfilesKey};
    for (const QString& key : object.keys()) {
        if (!allowed.contains(key))
            return {Error::UnknownField, std::nullopt};
    }
    for (const QString& key : {PreferencesKey, EnvironmentProfilesKey}) {
        if (!object.contains(key))
            return {Error::MissingField, std::nullopt};
    }
    if (!object.value(PreferencesKey).isObject() ||
        !object.value(EnvironmentProfilesKey).isObject()) {
        return {Error::InvalidType, std::nullopt};
    }

    const auto preferences = ConfigurationPortablePreferencesCodec::decode(
        object.value(PreferencesKey).toObject());
    if (preferences.error != ConfigurationPortablePreferencesCodec::Error::None ||
        !preferences.preferences) {
        return {Error::InvalidPreferences, std::nullopt};
    }
    const auto profiles = EnvironmentProfileJsonCodec::decode(
        object.value(EnvironmentProfilesKey).toObject());
    if (profiles.error != EnvironmentProfileJsonCodec::Error::None || !profiles.collection)
        return {Error::InvalidEnvironmentProfiles, std::nullopt};

    ConfigurationPublicSnapshot snapshot;
    snapshot.preferences = *preferences.preferences;
    snapshot.environmentProfiles = std::move(*profiles.collection);
    return {Error::None, std::move(snapshot)};
}
