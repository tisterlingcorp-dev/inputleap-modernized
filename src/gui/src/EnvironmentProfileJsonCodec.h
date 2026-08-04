/* InputLeap -- strict JSON codec for the four public environment profiles. */
#pragma once

#include "EnvironmentProfile.h"

#include <QJsonObject>
#include <QList>

#include <optional>

class EnvironmentProfileJsonCodec
{
public:
    struct Collection {
        QList<EnvironmentProfile> profiles;
        EnvironmentProfile::Kind activeKind = EnvironmentProfile::Kind::Home;
    };

    enum class Error {
        None,
        UnknownField,
        MissingField,
        InvalidType,
        InvalidValue,
        ResourceLimit
    };

    struct DecodeResult {
        Error error = Error::InvalidType;
        std::optional<Collection> collection;
    };

    static QJsonObject encode(const Collection& collection);
    static DecodeResult decode(const QJsonObject& object);
};
