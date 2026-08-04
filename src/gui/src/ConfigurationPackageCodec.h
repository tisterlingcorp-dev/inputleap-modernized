/* InputLeap -- strict versioned configuration package envelope. */
#pragma once

#include <QByteArray>
#include <QJsonObject>

#include <optional>

class ConfigurationPackageCodec
{
public:
    static constexpr int OldestSupportedSchemaVersion = 1;
    static constexpr int SchemaVersion = 1;
    static constexpr qsizetype MaxPackageBytes = 4 * 1024 * 1024;

    struct Package {
        int sourceSchemaVersion = SchemaVersion;
        QJsonObject publicData;
        std::optional<QJsonObject> sensitive;
    };

    enum class Error {
        None,
        TooLarge,
        MalformedJson,
        RootNotObject,
        DuplicateField,
        UnknownField,
        MissingField,
        UnsupportedFormat,
        InvalidVersion,
        UnsupportedVersion,
        InvalidSection
    };

    struct DecodeResult {
        Error error = Error::MalformedJson;
        std::optional<Package> package;
    };

    static QByteArray encode(const Package& package);
    static DecodeResult decode(const QByteArray& encoded);
};
