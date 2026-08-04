/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2008 Volker Lanz (vl@fidra.de)
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "AppConfig.h"
#include "AppConfigSettingsJournal.h"
#include "ConfigurationPortablePreferences.h"
#include "ConfigurationTransactionLock.h"
#include "QUtility.h"
#include "StartupSettingsPreflight.h"

#include <QtCore>
#include <QtNetwork>

#include <openssl/crypto.h>

#if defined(Q_OS_WIN)
const char AppConfig::server_name_[] = "input-leaps.exe";
const char AppConfig::client_name_[] = "input-leapc.exe";
const char AppConfig::log_dir_[] = "log/";
#define DEFAULT_PROCESS_MODE Service
#else
const char AppConfig::server_name_[] = "input-leaps";
const char AppConfig::client_name_[] = "input-leapc";
const char AppConfig::log_dir_[] = "/var/log/";
#define DEFAULT_PROCESS_MODE Desktop
#endif

const ElevateMode defaultElevateMode = ElevateAsNeeded;

static const char* logLevelNames[] =
{
    "ERROR",
    "WARNING",
    "NOTE",
    "INFO",
    "DEBUG",
    "DEBUG1",
    "DEBUG2"
};

namespace {
QString portableSettingsLockPath()
{
    return QDir(QDir::tempPath()).filePath(
        QStringLiteral("inputleap-portable-settings.lock"));
}

std::optional<ConfigurationPortablePreferences> readPortablePreferences(QSettings& settings)
{
    settings.sync();
    if (settings.status() != QSettings::NoError)
        return std::nullopt;
    return ConfigurationPortablePreferences::create(
        settings.value(QStringLiteral("port"), 24800).toInt(),
        settings.value(QStringLiteral("logLevel"), 3).toInt(),
        settings.value(QStringLiteral("language"), QStringLiteral("pt-BR")).toString(),
        settings.value(QStringLiteral("cryptoEnabled"), true).toBool(),
        settings.value(QStringLiteral("requireClientCertificate"), false).toBool(),
        settings.value(QStringLiteral("autoHide"), false).toBool(),
        settings.value(QStringLiteral("autoStart"), false).toBool(),
        settings.value(QStringLiteral("minimizeToTray"), false).toBool());
}
}

AppConfig::AppConfig(QSettings* settings) : AppConfig(settings, SecureCredentialStore())
{
}

AppConfig::AppConfig(QSettings* settings, SecureCredentialStore credentialStore) :
    m_pSettings(settings),
    m_CredentialStore(std::move(credentialStore)),
    m_ScreenName(),
    m_Port(24800),
    m_Interface(),
    m_LogLevel(0),
    m_WizardLastRun(0),
    m_ProcessMode(DEFAULT_PROCESS_MODE),
    m_AutoConfig(true),
    m_ElevateMode(defaultElevateMode),
    m_AutoConfigPrompted(false),
    m_CryptoEnabled(false),
    m_AutoHide(false),
    m_AutoStart(false),
    m_MinimizeToTray(false),
    m_SettingsLoadFailed(false)
{
    Q_ASSERT(m_pSettings);
    loadSettings();
}

AppConfig::~AppConfig()
{
    if (!m_FileTransferPairingCode.isEmpty())
        OPENSSL_cleanse(m_FileTransferPairingCode.data(),
                        static_cast<size_t>(m_FileTransferPairingCode.size() * sizeof(QChar)));
}

const QString &AppConfig::screenName() const { return m_ScreenName; }
int AppConfig::port() const { return m_Port; }
const QString &AppConfig::networkInterface() const { return m_Interface; }
int AppConfig::logLevel() const { return m_LogLevel; }
bool AppConfig::logToFile() const { return m_LogToFile; }
const QString &AppConfig::logFilename() const { return m_LogFilename; }
const QString &AppConfig::receiveDirectory() const { return m_ReceiveDirectory; }
const QString& AppConfig::fileTransferPairingCode() const
{
    return m_FileTransferPairingCode;
}
void AppConfig::clearRuntimePairingSecret()
{
    setFileTransferPairingCode({});
    if (m_LoadedPairingSecret) {
        m_LoadedPairingSecret->clear();
        m_LoadedPairingSecret.reset();
    }
}
bool AppConfig::settingsLoadFailed() const { return m_SettingsLoadFailed; }
bool AppConfig::sensitiveSettingsAvailable() const
{
    return m_CredentialStore.available() && !m_SettingsLoadFailed;
}

QString AppConfig::log_dir() const
{
#if defined(Q_OS_WIN)
    return program_dir() + "log/";
#else
    return "/var/log/";
#endif
}

QString AppConfig::program_dir() const
{
    return QCoreApplication::applicationDirPath() + "/";
}

void AppConfig::persistLogDir()
{
    QDir dir = log_dir();
    if (!dir.exists())
        dir.mkpath(dir.path());
}

const QString AppConfig::logFilenameCmd() const
{
    QString filename = m_LogFilename;
#if defined(Q_OS_WIN)
    filename = QString("\"%1\"").arg(filename);
#endif
    return filename;
}

QString AppConfig::logLevelText() const
{
    return logLevelNames[logLevel()];
}

ProcessMode AppConfig::processMode() const { return m_ProcessMode; }
bool AppConfig::wizardShouldRun() const { return m_WizardLastRun < kWizardVersion; }
const QString &AppConfig::language() const { return m_Language; }
bool AppConfig::startedBefore() const { return m_StartedBefore; }
bool AppConfig::autoConfig() const { return m_AutoConfig; }

bool AppConfig::recoverInterruptedSave(
    QSettings& settings, SecureCredentialStore credentialStore)
{
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return false;
    QLockFile settingsLock(portableSettingsLockPath());
    if (!settingsLock.tryLock(5000)) return false;
    AppConfigSettingsJournal journal(settings, credentialStore);
    return journal.recover() !=
        AppConfigSettingsJournal::RecoveryResult::Blocked;
}

void AppConfig::loadSettings()
{
    ConfigurationTransactionLock transactionLock;
    m_SettingsLoadFailed = true;
    if (!transactionLock.isLocked()) {
        setFileTransferPairingCode({});
        return;
    }
    QLockFile settingsLock(portableSettingsLockPath());
    const bool settingsLocked = settingsLock.tryLock(5000);
    if (!settingsLocked) {
        setFileTransferPairingCode({});
        return;
    }

    QSettings authority(settings().fileName(), settings().format());
    authority.sync();
    AppConfigSettingsJournal saveJournal(authority, m_CredentialStore);
    if (saveJournal.recover() ==
        AppConfigSettingsJournal::RecoveryResult::Blocked) {
        setFileTransferPairingCode({});
        return;
    }
    settings().sync();
    auto preflight = StartupSettingsPreflight::inspect(authority);
    if (preflight != StartupSettingsPreflight::Status::Valid &&
        preflight != StartupSettingsPreflight::Status::Missing) {
        setFileTransferPairingCode({});
        return;
    }

    m_ScreenName = authority.value("screenName", QHostInfo::localHostName()).toString();
    m_Port = authority.value("port", 24800).toInt();
    m_Interface = authority.value("interface").toString();
    m_LogLevel = authority.value("logLevel", 3).toInt();
    m_LogToFile = authority.value("logToFile", false).toBool();
    m_LogFilename = authority.value("logFilename", log_dir() + "input-leap.log").toString();
    m_ReceiveDirectory = authority.value("receiveDirectory").toString();

    m_SettingsLoadFailed = false;
    if (!m_CredentialStore.available()) {
        m_SettingsLoadFailed = true;
    } else {
        m_SettingsLoadFailed = !SecureCredentialStore::migrate(
            authority, "fileTransferPairingCode", m_CredentialStore,
            QStringLiteral("InputLeap/file-transfer-pairing-code"), {}, true);
        if (!m_SettingsLoadFailed)
            settings().remove("fileTransferPairingCode");
    }
    if (m_SettingsLoadFailed) {
        setFileTransferPairingCode({});
    } else {
        const auto storedCode = m_CredentialStore.read(
            QStringLiteral("InputLeap/file-transfer-pairing-code"));
        if (storedCode.status == SecureCredentialStore::ReadResult::Status::Error) {
            m_SettingsLoadFailed = true;
            setFileTransferPairingCode({});
        } else {
            QString decodedCode = storedCode
                ? QString::fromUtf8(storedCode->bytes()) : QString();
            const auto cleanseDecoded = qScopeGuard([&decodedCode] {
                if (!decodedCode.isEmpty())
                    OPENSSL_cleanse(decodedCode.data(),
                                    static_cast<size_t>(decodedCode.size() * sizeof(QChar)));
            });
            setFileTransferPairingCode(decodedCode);
            if (storedCode) {
                const QByteArrayView bytes = storedCode->bytes();
                m_LoadedPairingSecret.emplace(
                    QByteArray(bytes.data(), bytes.size()));
            } else {
                m_LoadedPairingSecret.reset();
            }
        }
    }

    m_WizardLastRun = authority.value("wizardLastRun", 0).toInt();
    m_Language = authority.value("language", "pt-BR").toString().replace('_', '-');
    m_StartedBefore = authority.value("startedBefore", false).toBool();
    m_AutoConfig = authority.value("autoConfig", true).toBool();
    QVariant elevateMode = authority.value("elevateModeEnum");
    if (!elevateMode.isValid()) {
        elevateMode = authority.value(
            "elevateMode", QVariant(static_cast<int>(defaultElevateMode)));
    }
    m_ElevateMode = static_cast<ElevateMode>(elevateMode.toInt());
    m_AutoConfigPrompted = authority.value("autoConfigPrompted", false).toBool();
    m_CryptoEnabled = authority.value("cryptoEnabled", true).toBool();
    m_RequireClientCertificate = authority.value("requireClientCertificate", false).toBool();
    m_AutoHide = authority.value("autoHide", false).toBool();
    m_AutoStart = authority.value("autoStart", false).toBool();
    m_MinimizeToTray = authority.value("minimizeToTray", false).toBool();
    m_LoadedPublicState = AppConfigSettingsJournal::capture(authority);
}

bool AppConfig::saveSettings()
{
    return saveSettingsWithResult() == SaveSettingsResult::Success;
}

AppConfig::SaveSettingsResult AppConfig::saveSettingsWithResult()
{
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return SaveSettingsResult::Failed;
    const QString& account = AppConfigSettingsJournal::PairingAccount;
    if (!m_CredentialStore.available() || m_SettingsLoadFailed)
        return SaveSettingsResult::Failed;

    QLockFile portableLock(portableSettingsLockPath());
    if (!portableLock.tryLock(5000))
        return SaveSettingsResult::Failed;

    QSettings authority(settings().fileName(), settings().format());
    const QJsonObject original = AppConfigSettingsJournal::capture(authority);
    if (authority.status() != QSettings::NoError)
        return SaveSettingsResult::Failed;
    if (original != m_LoadedPublicState)
        return SaveSettingsResult::ConcurrentModification;
    const auto oldSecret = m_CredentialStore.read(account);
    if (oldSecret.status == SecureCredentialStore::ReadResult::Status::Error)
        return SaveSettingsResult::Failed;
    if (oldSecret.has_value() != m_LoadedPairingSecret.has_value() ||
        (oldSecret && !oldSecret->securelyEquals(
             m_LoadedPairingSecret->bytes()))) {
        return SaveSettingsResult::ConcurrentModification;
    }

    QByteArray desiredSecret = m_FileTransferPairingCode.toUtf8();
    const auto cleanseDesired = qScopeGuard([&desiredSecret] {
        if (!desiredSecret.isEmpty())
            OPENSSL_cleanse(desiredSecret.data(), static_cast<size_t>(desiredSecret.size()));
    });
    std::optional<QByteArrayView> expectedView;
    if (m_LoadedPairingSecret)
        expectedView = m_LoadedPairingSecret->bytes();
    std::optional<QByteArrayView> candidateView;
    if (!desiredSecret.isEmpty())
        candidateView = QByteArrayView(desiredSecret);

    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("screenName"), m_ScreenName);
    candidate.insert(QStringLiteral("port"), m_Port);
    candidate.insert(QStringLiteral("interface"), m_Interface);
    candidate.insert(QStringLiteral("logLevel"), m_LogLevel);
    candidate.insert(QStringLiteral("logToFile"), m_LogToFile);
    candidate.insert(QStringLiteral("logFilename"), m_LogFilename);
    candidate.insert(QStringLiteral("receiveDirectory"), m_ReceiveDirectory);
    candidate.insert(QStringLiteral("wizardLastRun"), kWizardVersion);
    candidate.insert(QStringLiteral("language"), m_Language);
    candidate.insert(QStringLiteral("startedBefore"), m_StartedBefore);
    candidate.insert(QStringLiteral("autoConfig"), m_AutoConfig);
    candidate.insert(QStringLiteral("elevateMode"),
                     m_ElevateMode == ElevateAlways);
    candidate.insert(QStringLiteral("elevateModeEnum"),
                     static_cast<int>(m_ElevateMode));
    candidate.insert(QStringLiteral("autoConfigPrompted"), m_AutoConfigPrompted);
    candidate.insert(QStringLiteral("cryptoEnabled"), m_CryptoEnabled);
    candidate.insert(QStringLiteral("requireClientCertificate"),
                     m_RequireClientCertificate);
    candidate.insert(QStringLiteral("autoHide"), m_AutoHide);
    candidate.insert(QStringLiteral("autoStart"), m_AutoStart);
    candidate.insert(QStringLiteral("minimizeToTray"), m_MinimizeToTray);
    std::optional<SensitiveBytes> stagedSecret;
    if (!desiredSecret.isEmpty())
        stagedSecret.emplace(QByteArray(desiredSecret));
    AppConfigSettingsJournal journal(authority, m_CredentialStore);
    if (!journal.begin(original, candidate, stagedSecret) ||
        !AppConfigSettingsJournal::apply(authority, candidate) ||
        !journal.markPublicApplied()) {
        const auto recovered = journal.recover();
        if (recovered == AppConfigSettingsJournal::RecoveryResult::Blocked)
            m_SettingsLoadFailed = true;
        return SaveSettingsResult::Failed;
    }

    const auto updateResult = m_CredentialStore.compareAndSwap(
        account, expectedView, candidateView);
    const auto acceptCandidate = [&] {
        m_LoadedPublicState = candidate;
        if (desiredSecret.isEmpty()) {
            m_LoadedPairingSecret.reset();
        } else {
            m_LoadedPairingSecret.emplace(QByteArray(desiredSecret));
        }
        settings().sync();
        return SaveSettingsResult::Success;
    };
    if (updateResult == SecureCredentialStore::CompareAndSwapResult::Success) {
        if (journal.commit()) return acceptCandidate();
        m_SettingsLoadFailed = true;
        return SaveSettingsResult::Failed;
    }
    const auto recovered = journal.recover();
    if (recovered ==
        AppConfigSettingsJournal::RecoveryResult::RecoveredCandidate) {
        return acceptCandidate();
    }
    m_SettingsLoadFailed = true;
    return SaveSettingsResult::Failed;
}

bool AppConfig::savePortableSettings()
{
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return false;
    QLockFile lock(portableSettingsLockPath());
    if (!lock.tryLock(5000))
        return false;

    const QStringList keys = {
        QStringLiteral("port"), QStringLiteral("logLevel"),
        QStringLiteral("language"), QStringLiteral("cryptoEnabled"),
        QStringLiteral("requireClientCertificate"), QStringLiteral("autoHide"),
        QStringLiteral("autoStart"), QStringLiteral("minimizeToTray")};
    QHash<QString, QVariant> oldValues;
    QSet<QString> oldPresent;
    for (const QString& key : keys) {
        if (settings().contains(key)) {
            oldPresent.insert(key);
            oldValues.insert(key, settings().value(key));
        }
    }
    const auto restore = [&]() {
        for (const QString& key : keys) {
            if (oldPresent.contains(key))
                settings().setValue(key, oldValues.value(key));
            else
                settings().remove(key);
        }
        settings().sync();
    };

    settings().setValue(QStringLiteral("port"), m_Port);
    settings().setValue(QStringLiteral("logLevel"), m_LogLevel);
    settings().setValue(QStringLiteral("language"), m_Language);
    settings().setValue(QStringLiteral("cryptoEnabled"), m_CryptoEnabled);
    settings().setValue(QStringLiteral("requireClientCertificate"), m_RequireClientCertificate);
    settings().setValue(QStringLiteral("autoHide"), m_AutoHide);
    settings().setValue(QStringLiteral("autoStart"), m_AutoStart);
    settings().setValue(QStringLiteral("minimizeToTray"), m_MinimizeToTray);
    settings().sync();
    if (settings().status() == QSettings::NoError) {
        m_LoadedPublicState = AppConfigSettingsJournal::capture(settings());
        return true;
    }
    restore();
    return false;
}

AppConfig::PortableSaveResult AppConfig::savePortableSettingsIfUnchanged(
    const ConfigurationPortablePreferences& expected)
{
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return PortableSaveResult::Failed;
    QLockFile lock(portableSettingsLockPath());
    if (!lock.tryLock(5000))
        return PortableSaveResult::Failed;
    const auto current = readPortablePreferences(settings());
    if (!current)
        return PortableSaveResult::Failed;
    if (!(*current == expected))
        return PortableSaveResult::ConcurrentModification;

    const QStringList keys = {
        QStringLiteral("port"), QStringLiteral("logLevel"),
        QStringLiteral("language"), QStringLiteral("cryptoEnabled"),
        QStringLiteral("requireClientCertificate"), QStringLiteral("autoHide"),
        QStringLiteral("autoStart"), QStringLiteral("minimizeToTray")};
    QHash<QString, QVariant> oldValues;
    QSet<QString> oldPresent;
    for (const QString& key : keys) {
        if (settings().contains(key)) {
            oldPresent.insert(key);
            oldValues.insert(key, settings().value(key));
        }
    }
    const auto restore = [&]() {
        for (const QString& key : keys) {
            if (oldPresent.contains(key))
                settings().setValue(key, oldValues.value(key));
            else
                settings().remove(key);
        }
        settings().sync();
    };

    settings().setValue(QStringLiteral("port"), m_Port);
    settings().setValue(QStringLiteral("logLevel"), m_LogLevel);
    settings().setValue(QStringLiteral("language"), m_Language);
    settings().setValue(QStringLiteral("cryptoEnabled"), m_CryptoEnabled);
    settings().setValue(QStringLiteral("requireClientCertificate"), m_RequireClientCertificate);
    settings().setValue(QStringLiteral("autoHide"), m_AutoHide);
    settings().setValue(QStringLiteral("autoStart"), m_AutoStart);
    settings().setValue(QStringLiteral("minimizeToTray"), m_MinimizeToTray);
    settings().sync();
    if (settings().status() == QSettings::NoError) {
        m_LoadedPublicState = AppConfigSettingsJournal::capture(settings());
        return PortableSaveResult::Success;
    }
    restore();
    return PortableSaveResult::Failed;
}

bool AppConfig::saveFileTransferPairingCode()
{
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return false;
    const QString account = QStringLiteral("InputLeap/file-transfer-pairing-code");
    if (!m_CredentialStore.available())
        return false;
    if (m_FileTransferPairingCode.isEmpty()) {
        if (!m_CredentialStore.remove(account))
            return false;
        return !m_CredentialStore.read(account).has_value();
    }

    QByteArray encoded = m_FileTransferPairingCode.toUtf8();
    const auto cleanseEncoded = qScopeGuard([&encoded] {
        if (!encoded.isEmpty())
            OPENSSL_cleanse(encoded.data(), static_cast<size_t>(encoded.size()));
    });
    if (!m_CredentialStore.write(account, encoded))
        return false;
    auto verified = m_CredentialStore.read(account);
    return verified && verified->securelyEquals(encoded);
}

QSettings &AppConfig::settings() { return *m_pSettings; }
void AppConfig::setScreenName(const QString &s) { m_ScreenName = s; }
void AppConfig::setPort(int i) { m_Port = i; }
void AppConfig::setNetworkInterface(const QString &s) { m_Interface = s; }
void AppConfig::setLogLevel(int i) { m_LogLevel = i; }
void AppConfig::setLogToFile(bool b) { m_LogToFile = b; }
void AppConfig::setLogFilename(const QString &s) { m_LogFilename = s; }
void AppConfig::setReceiveDirectory(const QString &s) { m_ReceiveDirectory = s; }

void AppConfig::setFileTransferPairingCode(const QString &s)
{
    QString replacement = s.trimmed();
    replacement.detach();
    if (!m_FileTransferPairingCode.isEmpty())
        OPENSSL_cleanse(m_FileTransferPairingCode.data(),
                        static_cast<size_t>(m_FileTransferPairingCode.size() * sizeof(QChar)));
    m_FileTransferPairingCode = std::move(replacement);
}

void AppConfig::setWizardHasRun() { m_WizardLastRun = kWizardVersion; }
void AppConfig::setLanguage(const QString language) { m_Language = language; }
void AppConfig::setStartedBefore(bool b) { m_StartedBefore = b; }
void AppConfig::setElevateMode(ElevateMode em) { m_ElevateMode = em; }
void AppConfig::setAutoConfig(bool autoConfig) { m_AutoConfig = autoConfig; }
bool AppConfig::autoConfigPrompted() { return m_AutoConfigPrompted; }
void AppConfig::setAutoConfigPrompted(bool prompted) { m_AutoConfigPrompted = prompted; }
QString AppConfig::server_name() const { return server_name_; }
QString AppConfig::client_name() const { return client_name_; }
ElevateMode AppConfig::elevateMode() { return m_ElevateMode; }
void AppConfig::setCryptoEnabled(bool e) { m_CryptoEnabled = e; }
bool AppConfig::getCryptoEnabled() const { return m_CryptoEnabled; }
void AppConfig::setRequireClientCertificate(bool e) { m_RequireClientCertificate = e; }
bool AppConfig::getRequireClientCertificate() const { return m_RequireClientCertificate; }
void AppConfig::setAutoHide(bool b) { m_AutoHide = b; }
bool AppConfig::getAutoHide() { return m_AutoHide; }
void AppConfig::setAutoStart(bool b) { m_AutoStart = b; }
bool AppConfig::getAutoStart() { return m_AutoStart; }
void AppConfig::setMinimizeToTray(bool b) { m_MinimizeToTray = b; }
bool AppConfig::getMinimizeToTray() { return m_MinimizeToTray; }
