/* InputLeap -- typed portable non-secret preferences. */
#include "ConfigurationPortablePreferences.h"

#include <QSet>
#include <QStringList>

#include <cmath>
#include <utility>

namespace {
const QString PortKey = QStringLiteral("port");
const QString LogLevelKey = QStringLiteral("logLevel");
const QString LanguageKey = QStringLiteral("language");
const QString CryptoEnabledKey = QStringLiteral("cryptoEnabled");
const QString RequireClientCertificateKey = QStringLiteral("requireClientCertificate");
const QString AutoHideKey = QStringLiteral("autoHide");
const QString AutoStartKey = QStringLiteral("autoStart");
const QString MinimizeToTrayKey = QStringLiteral("minimizeToTray");

const QStringList RequiredKeys{
    PortKey, LogLevelKey, LanguageKey, CryptoEnabledKey,
    RequireClientCertificateKey, AutoHideKey, AutoStartKey, MinimizeToTrayKey};

// Keep synchronized with res/lang/Languages.xml. The package codec must also
// work in the small test/helper binary where the GUI qrc is not linked.
const QSet<QString> SupportedLanguages{
    QStringLiteral("en"), QStringLiteral("ca-AD"), QStringLiteral("cs-CZ"),
    QStringLiteral("cy"), QStringLiteral("da"), QStringLiteral("de"),
    QStringLiteral("es"), QStringLiteral("fr"), QStringLiteral("hr-HR"),
    QStringLiteral("id"), QStringLiteral("it"), QStringLiteral("lv"),
    QStringLiteral("lt"), QStringLiteral("hu-HU"), QStringLiteral("nl-NL"),
    QStringLiteral("no"), QStringLiteral("pl-PL"), QStringLiteral("pt-PT"),
    QStringLiteral("pt-BR"), QStringLiteral("ro"), QStringLiteral("sq-AL"),
    QStringLiteral("sl-SI"), QStringLiteral("sk-SK"), QStringLiteral("fi"),
    QStringLiteral("sv"), QStringLiteral("vi"), QStringLiteral("tr-TR"),
    QStringLiteral("bg-BG"), QStringLiteral("ru"), QStringLiteral("sr"),
    QStringLiteral("uk"), QStringLiteral("grk"), QStringLiteral("he"),
    QStringLiteral("ar"), QStringLiteral("pes-IR"), QStringLiteral("ur"),
    QStringLiteral("mr"), QStringLiteral("si"), QStringLiteral("th-TH"),
    QStringLiteral("zh-CN"), QStringLiteral("zh-TW"), QStringLiteral("ja-JP"),
    QStringLiteral("ko")};

bool exactInteger(const QJsonValue& value, int minimum, int maximum, int& output)
{
    if (!value.isDouble())
        return false;
    const double number = value.toDouble();
    if (!std::isfinite(number) || std::floor(number) != number ||
        number < minimum || number > maximum) {
        return false;
    }
    output = static_cast<int>(number);
    return true;
}
}

ConfigurationPortablePreferences::ConfigurationPortablePreferences(
    int port, int logLevel, QString language, bool cryptoEnabled,
    bool requireClientCertificate, bool autoHide, bool autoStart, bool minimizeToTray) :
    port_(port),
    log_level_(logLevel),
    language_(std::move(language)),
    crypto_enabled_(cryptoEnabled),
    require_client_certificate_(requireClientCertificate),
    auto_hide_(autoHide),
    auto_start_(autoStart),
    minimize_to_tray_(minimizeToTray)
{
}

ConfigurationPortablePreferences::ConfigurationPortablePreferences(
    ConfigurationPortablePreferences&& other) :
    ConfigurationPortablePreferences(other.port_, other.log_level_, other.language_,
                                     other.crypto_enabled_, other.require_client_certificate_,
                                     other.auto_hide_, other.auto_start_, other.minimize_to_tray_)
{
}

ConfigurationPortablePreferences& ConfigurationPortablePreferences::operator=(
    ConfigurationPortablePreferences&& other)
{
    if (this != &other) {
        port_ = other.port_;
        log_level_ = other.log_level_;
        language_ = other.language_;
        crypto_enabled_ = other.crypto_enabled_;
        require_client_certificate_ = other.require_client_certificate_;
        auto_hide_ = other.auto_hide_;
        auto_start_ = other.auto_start_;
        minimize_to_tray_ = other.minimize_to_tray_;
    }
    return *this;
}

std::optional<ConfigurationPortablePreferences> ConfigurationPortablePreferences::create(
    int port, int logLevel, const QString& language, bool cryptoEnabled,
    bool requireClientCertificate, bool autoHide, bool autoStart, bool minimizeToTray)
{
    if (port < 1 || port > 65535 || logLevel < 0 || logLevel > 6 ||
        !SupportedLanguages.contains(language) ||
        (requireClientCertificate && !cryptoEnabled)) {
        return std::nullopt;
    }
    return ConfigurationPortablePreferences(port, logLevel, language, cryptoEnabled,
                                            requireClientCertificate, autoHide,
                                            autoStart, minimizeToTray);
}

QJsonObject ConfigurationPortablePreferencesCodec::encode(
    const ConfigurationPortablePreferences& preferences)
{
    return {
        {PortKey, preferences.port()},
        {LogLevelKey, preferences.logLevel()},
        {LanguageKey, preferences.language()},
        {CryptoEnabledKey, preferences.cryptoEnabled()},
        {RequireClientCertificateKey, preferences.requireClientCertificate()},
        {AutoHideKey, preferences.autoHide()},
        {AutoStartKey, preferences.autoStart()},
        {MinimizeToTrayKey, preferences.minimizeToTray()},
    };
}

ConfigurationPortablePreferencesCodec::DecodeResult
ConfigurationPortablePreferencesCodec::decode(const QJsonObject& object)
{
    const QSet<QString> allowed(RequiredKeys.begin(), RequiredKeys.end());
    for (const QString& key : object.keys()) {
        if (!allowed.contains(key))
            return {Error::UnknownField, std::nullopt};
    }
    for (const QString& key : RequiredKeys) {
        if (!object.contains(key))
            return {Error::MissingField, std::nullopt};
    }

    if (!object.value(PortKey).isDouble() || !object.value(LogLevelKey).isDouble() ||
        !object.value(LanguageKey).isString() ||
        !object.value(CryptoEnabledKey).isBool() ||
        !object.value(RequireClientCertificateKey).isBool() ||
        !object.value(AutoHideKey).isBool() ||
        !object.value(AutoStartKey).isBool() ||
        !object.value(MinimizeToTrayKey).isBool()) {
        return {Error::InvalidType, std::nullopt};
    }

    int port = 0;
    int logLevel = 0;
    if (!exactInteger(object.value(PortKey), 1, 65535, port) ||
        !exactInteger(object.value(LogLevelKey), 0, 6, logLevel)) {
        return {Error::InvalidValue, std::nullopt};
    }

    const QString language = object.value(LanguageKey).toString();
    if (!SupportedLanguages.contains(language))
        return {Error::InvalidValue, std::nullopt};

    const bool cryptoEnabled = object.value(CryptoEnabledKey).toBool();
    const bool requireClientCertificate = object.value(RequireClientCertificateKey).toBool();
    if (requireClientCertificate && !cryptoEnabled)
        return {Error::InconsistentSecurity, std::nullopt};

    auto result = ConfigurationPortablePreferences::create(
        port, logLevel, language, cryptoEnabled, requireClientCertificate,
        object.value(AutoHideKey).toBool(), object.value(AutoStartKey).toBool(),
        object.value(MinimizeToTrayKey).toBool());
    if (!result)
        return {Error::InvalidValue, std::nullopt};
    return {Error::None, std::move(result)};
}
