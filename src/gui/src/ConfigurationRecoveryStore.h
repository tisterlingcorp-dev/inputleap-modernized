/* InputLeap -- strict public snapshot for local configuration recovery. */
#pragma once

#include "ConfigurationPortablePreferences.h"

#include <QByteArray>

#include <optional>

class ConfigurationRecoveryStore
{
public:
    enum class Error {
        None,
        InvalidPackage,
        SensitiveForbidden,
        InvalidPublicSection,
        InvalidPreferences
    };

    struct DecodeResult {
        Error error = Error::InvalidPackage;
        std::optional<ConfigurationPortablePreferences> preferences;
    };

    static QByteArray encodeSnapshot(
        const ConfigurationPortablePreferences& preferences);
    static DecodeResult decodeSnapshot(const QByteArray& encoded);
};
