/* InputLeap -- typed portable non-secret preferences. */
#pragma once

#include <QJsonObject>
#include <QString>

#include <optional>

class ConfigurationPortablePreferences
{
public:
    ConfigurationPortablePreferences() = default;
    ConfigurationPortablePreferences(const ConfigurationPortablePreferences&) = default;
    ConfigurationPortablePreferences& operator=(const ConfigurationPortablePreferences&) = default;
    ConfigurationPortablePreferences(ConfigurationPortablePreferences&& other);
    ConfigurationPortablePreferences& operator=(ConfigurationPortablePreferences&& other);

    static std::optional<ConfigurationPortablePreferences> create(
        int port, int logLevel, const QString& language,
        bool cryptoEnabled, bool requireClientCertificate,
        bool autoHide, bool autoStart, bool minimizeToTray);

    int port() const { return port_; }
    int logLevel() const { return log_level_; }
    const QString& language() const { return language_; }
    bool cryptoEnabled() const { return crypto_enabled_; }
    bool requireClientCertificate() const { return require_client_certificate_; }
    bool autoHide() const { return auto_hide_; }
    bool autoStart() const { return auto_start_; }
    bool minimizeToTray() const { return minimize_to_tray_; }

    bool operator==(const ConfigurationPortablePreferences&) const = default;

private:
    ConfigurationPortablePreferences(int port, int logLevel, QString language,
                                     bool cryptoEnabled, bool requireClientCertificate,
                                     bool autoHide, bool autoStart, bool minimizeToTray);

    int port_ = 24800;
    int log_level_ = 3;
    QString language_ = QStringLiteral("pt-BR");
    bool crypto_enabled_ = true;
    bool require_client_certificate_ = false;
    bool auto_hide_ = false;
    bool auto_start_ = false;
    bool minimize_to_tray_ = false;
};

class ConfigurationPortablePreferencesCodec
{
public:
    enum class Error {
        None,
        UnknownField,
        MissingField,
        InvalidType,
        InvalidValue,
        InconsistentSecurity
    };

    struct DecodeResult {
        Error error = Error::InvalidType;
        std::optional<ConfigurationPortablePreferences> preferences;
    };

    static QJsonObject encode(const ConfigurationPortablePreferences& preferences);
    static DecodeResult decode(const QJsonObject& object);
};
