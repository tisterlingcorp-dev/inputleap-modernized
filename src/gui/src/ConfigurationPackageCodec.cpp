/* InputLeap -- strict versioned configuration package envelope. */
#include "ConfigurationPackageCodec.h"

#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonParseError>
#include <QSet>
#include <QStringList>
#include <QVector>

#include <cctype>
#include <cmath>

namespace {
const QString FormatKey = QStringLiteral("format");
const QString VersionKey = QStringLiteral("schemaVersion");
const QString PublicKey = QStringLiteral("public");
const QString SensitiveKey = QStringLiteral("sensitive");
const QString FormatValue = QStringLiteral("inputleap-configuration");

struct RootScan {
    bool duplicate = false;
    std::optional<QByteArray> versionToken;
};

struct JsonContext {
    enum class Kind { Object, Array };
    Kind kind;
    bool expectingKey = false;
    QSet<QString> keys;
    QString currentKey;
};

RootScan scanRoot(const QByteArray& encoded)
{
    bool inString = false;
    bool escaped = false;
    qsizetype stringStart = -1;
    QVector<JsonContext> contexts;
    RootScan result;

    for (qsizetype i = 0; i < encoded.size(); ++i) {
        const char value = encoded.at(i);
        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (value == '\\') {
                escaped = true;
            } else if (value == '"') {
                inString = false;
                if (!contexts.isEmpty() &&
                    contexts.last().kind == JsonContext::Kind::Object &&
                    contexts.last().expectingKey) {
                    const QByteArray token = encoded.mid(stringStart, i - stringStart + 1);
                    const QJsonDocument keyDocument = QJsonDocument::fromJson(
                        QByteArrayLiteral("[") + token + QByteArrayLiteral("]"));
                    const QString key = keyDocument.array().first().toString();
                    JsonContext& object = contexts.last();
                    if (object.keys.contains(key)) {
                        result.duplicate = true;
                        return result;
                    }
                    object.keys.insert(key);
                    object.currentKey = key;
                    object.expectingKey = false;
                }
            }
            continue;
        }

        if (value == '"') {
            inString = true;
            stringStart = i;
        } else if (value == '{') {
            contexts.push_back({JsonContext::Kind::Object, true, {}, {}});
        } else if (value == '}') {
            if (!contexts.isEmpty())
                contexts.removeLast();
        } else if (value == '[') {
            contexts.push_back({JsonContext::Kind::Array, false, {}, {}});
        } else if (value == ']') {
            if (!contexts.isEmpty())
                contexts.removeLast();
        } else if (value == ':' && contexts.size() == 1 &&
                   contexts.last().kind == JsonContext::Kind::Object &&
                   contexts.last().currentKey == VersionKey) {
            qsizetype start = i + 1;
            while (start < encoded.size() &&
                   std::isspace(static_cast<unsigned char>(encoded.at(start)))) {
                ++start;
            }
            qsizetype end = start;
            while (end < encoded.size() && encoded.at(end) != ',' && encoded.at(end) != '}')
                ++end;
            result.versionToken = encoded.mid(start, end - start).trimmed();
        } else if (value == ',' && !contexts.isEmpty() &&
                   contexts.last().kind == JsonContext::Kind::Object) {
            contexts.last().expectingKey = true;
            contexts.last().currentKey.clear();
        }
    }
    return result;
}
}

QByteArray ConfigurationPackageCodec::encode(const Package& package)
{
    QJsonObject root;
    root.insert(FormatKey, FormatValue);
    root.insert(VersionKey, SchemaVersion);
    root.insert(PublicKey, package.publicData);
    if (package.sensitive)
        root.insert(SensitiveKey, *package.sensitive);
    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

ConfigurationPackageCodec::DecodeResult ConfigurationPackageCodec::decode(const QByteArray& encoded)
{
    if (encoded.size() > MaxPackageBytes)
        return {Error::TooLarge, std::nullopt};

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(encoded, &parseError);
    if (parseError.error != QJsonParseError::NoError)
        return {Error::MalformedJson, std::nullopt};
    if (!document.isObject())
        return {Error::RootNotObject, std::nullopt};
    const RootScan rootScan = scanRoot(encoded);
    if (rootScan.duplicate)
        return {Error::DuplicateField, std::nullopt};

    const QJsonObject root = document.object();
    const QSet<QString> allowed{FormatKey, VersionKey, PublicKey, SensitiveKey};
    for (const QString& key : root.keys()) {
        if (!allowed.contains(key))
            return {Error::UnknownField, std::nullopt};
    }
    for (const QString& key : {FormatKey, VersionKey, PublicKey}) {
        if (!root.contains(key))
            return {Error::MissingField, std::nullopt};
    }

    const QJsonValue format = root.value(FormatKey);
    if (!format.isString() || format.toString() != FormatValue)
        return {Error::UnsupportedFormat, std::nullopt};

    const QJsonValue versionValue = root.value(VersionKey);
    if (!versionValue.isDouble())
        return {Error::InvalidVersion, std::nullopt};
    const double numericVersion = versionValue.toDouble();
    if (!std::isfinite(numericVersion) || std::floor(numericVersion) != numericVersion || numericVersion < 1.0)
        return {Error::InvalidVersion, std::nullopt};
    if (numericVersion > SchemaVersion)
        return {Error::UnsupportedVersion, std::nullopt};
    if (!rootScan.versionToken || *rootScan.versionToken != QByteArrayLiteral("1"))
        return {Error::InvalidVersion, std::nullopt};

    const QJsonValue publicValue = root.value(PublicKey);
    if (!publicValue.isObject())
        return {Error::InvalidSection, std::nullopt};
    Package package;
    package.sourceSchemaVersion = static_cast<int>(numericVersion);
    package.publicData = publicValue.toObject();
    if (root.contains(SensitiveKey)) {
        const QJsonValue sensitiveValue = root.value(SensitiveKey);
        if (!sensitiveValue.isObject())
            return {Error::InvalidSection, std::nullopt};
        package.sensitive = sensitiveValue.toObject();
    }
    return {Error::None, std::move(package)};
}
