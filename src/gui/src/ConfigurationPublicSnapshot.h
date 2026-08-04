/* InputLeap -- typed public configuration snapshot without secrets. */
#pragma once

#include "ConfigurationPortablePreferences.h"
#include "EnvironmentProfileJsonCodec.h"

#include <QJsonObject>

#include <optional>

struct ConfigurationPublicSnapshot
{
    ConfigurationPortablePreferences preferences;
    EnvironmentProfileJsonCodec::Collection environmentProfiles;
};

class ConfigurationPublicSnapshotCodec
{
public:
    enum class Error {
        None,
        UnknownField,
        MissingField,
        InvalidType,
        InvalidPreferences,
        InvalidEnvironmentProfiles
    };

    struct DecodeResult {
        Error error = Error::InvalidType;
        std::optional<ConfigurationPublicSnapshot> snapshot;
    };

    static QJsonObject encode(const ConfigurationPublicSnapshot& snapshot);
    static DecodeResult decode(const QJsonObject& object);
};
