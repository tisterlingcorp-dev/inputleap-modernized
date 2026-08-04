/* InputLeap -- read-only startup gate for persistent settings. */
#include "StartupSettingsPreflight.h"

#include "Action.h"
#include "AppConfig.h"
#include "BaseConfig.h"
#include "ConfigurationPortablePreferences.h"
#include "ConfigurationTransactionLock.h"
#include "ElevateMode.h"

#include <QMetaType>
#include <QFileInfo>
#include <QSettings>

#include <limits>

#ifdef Q_OS_WIN
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace {
#ifdef Q_OS_WIN
bool emptyNativeStorePhysicallyExists(const QSettings& settings)
{
    QString path = settings.fileName();
    path.replace(QLatin1Char('/'), QLatin1Char('\\'));
    struct RootPrefix { const wchar_t* text; HKEY root; };
    static const RootPrefix roots[] = {
        {L"HKEY_CURRENT_USER", HKEY_CURRENT_USER},
        {L"HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE},
    };
    for (const auto& candidate : roots) {
        const QString prefix = QString::fromWCharArray(candidate.text);
        int offset = path.startsWith(QLatin1Char('\\')) ? 1 : 0;
        if (path.mid(offset, prefix.size()).compare(prefix, Qt::CaseInsensitive) != 0)
            continue;
        offset += prefix.size();
        while (offset < path.size() && path.at(offset) == QLatin1Char('\\'))
            ++offset;
        const QString subkey = path.mid(offset);
        if (subkey.isEmpty())
            return true;
        HKEY opened = nullptr;
        const LONG status = RegOpenKeyExW(
            candidate.root, reinterpret_cast<LPCWSTR>(subkey.utf16()),
            0, KEY_READ, &opened);
        if (opened != nullptr)
            RegCloseKey(opened);
        return status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND;
    }
    return true;
}
#endif

bool strictInt(QSettings& settings, const QString& key, int fallback, int& output)
{
    if (!settings.contains(key)) {
        output = fallback;
        return true;
    }
    const QVariant value = settings.value(key);
    if (value.metaType().id() == QMetaType::Int) {
        output = value.toInt();
        return true;
    }
    if (value.metaType().id() != QMetaType::LongLong)
        return false;
    const qlonglong number = value.toLongLong();
    if (number < std::numeric_limits<int>::min() ||
        number > std::numeric_limits<int>::max()) {
        return false;
    }
    output = static_cast<int>(number);
    return true;
}

bool strictBool(QSettings& settings, const QString& key, bool fallback, bool& output)
{
    if (!settings.contains(key)) {
        output = fallback;
        return true;
    }
    const QVariant value = settings.value(key);
    if (value.metaType().id() == QMetaType::Bool) {
        output = value.toBool();
        return true;
    }
    if (value.metaType().id() != QMetaType::QString)
        return false;
    const QString text = value.toString();
    if (text == QStringLiteral("true")) {
        output = true;
        return true;
    }
    if (text == QStringLiteral("false")) {
        output = false;
        return true;
    }
    return false;
}

bool strictString(QSettings& settings, const QString& key,
                  const QString& fallback, QString& output)
{
    if (!settings.contains(key)) {
        output = fallback;
        return true;
    }
    const QVariant value = settings.value(key);
    if (value.metaType().id() != QMetaType::QString)
        return false;
    output = value.toString();
    return true;
}

bool boundedArraySize(QSettings& settings, const QString& prefix,
                      int maximum, int& output)
{
    return strictInt(settings, prefix + QStringLiteral("/size"), 0, output) &&
           output >= 0 && output <= maximum;
}

bool strictUnsignedLongLong(QSettings& settings, const QString& key,
                            qulonglong fallback, qulonglong& output)
{
    if (!settings.contains(key)) {
        output = fallback;
        return true;
    }
    const QVariant value = settings.value(key);
    if (value.metaType().id() == QMetaType::ULongLong) {
        output = value.toULongLong();
        return true;
    }
    if (value.metaType().id() == QMetaType::UInt) {
        output = value.toUInt();
        return true;
    }
    if (value.metaType().id() == QMetaType::LongLong && value.toLongLong() >= 0) {
        output = static_cast<qulonglong>(value.toLongLong());
        return true;
    }
    if (value.metaType().id() == QMetaType::Int && value.toInt() >= 0) {
        output = static_cast<qulonglong>(value.toInt());
        return true;
    }
    return false;
}

bool validateKeySequence(QSettings& settings, const QString& prefix)
{
    int count = 0;
    if (!boundedArraySize(settings, prefix + QStringLiteral("/keys"), 4, count))
        return false;
    for (int i = 1; i <= count; ++i) {
        int key = 0;
        if (!strictInt(settings, prefix + QStringLiteral("/keys/") +
                       QString::number(i) + QStringLiteral("/key"), 0, key))
            return false;
    }
    return true;
}

bool validateInternalConfig(QSettings& settings)
{
    constexpr int MaxColumns = 5;
    constexpr int MaxRows = 3;
    constexpr int MaxAliasesPerScreen = 128;
    constexpr int MaxHotkeys = 1024;
    constexpr int MaxActionsPerHotkey = 64;
    const QString root = QStringLiteral("internalConfig/");
    int columns = MaxColumns;
    int rows = MaxRows;
    int screens = 0;
    int integer = 0;
    bool boolean = false;
    qulonglong clipboardSize = 0;

    if (!strictInt(settings, root + QStringLiteral("numColumns"), MaxColumns, columns) ||
        !strictInt(settings, root + QStringLiteral("numRows"), MaxRows, rows) ||
        columns < 1 || columns > MaxColumns || rows < 1 || rows > MaxRows ||
        !boundedArraySize(settings, root + QStringLiteral("screens"), columns * rows, screens) ||
        !strictBool(settings, root + QStringLiteral("hasHeartbeat"), false, boolean) ||
        !strictInt(settings, root + QStringLiteral("heartbeat"), 5000, integer) ||
        integer < 0 || integer > 3'600'000 ||
        !strictBool(settings, root + QStringLiteral("relativeMouseMoves"), false, boolean) ||
        !strictBool(settings, root + QStringLiteral("screenSaverSync"), true, boolean) ||
        !strictBool(settings, root + QStringLiteral("win32KeepForeground"), false, boolean) ||
        !strictBool(settings, root + QStringLiteral("hasSwitchDelay"), false, boolean) ||
        !strictInt(settings, root + QStringLiteral("switchDelay"), 250, integer) ||
        integer < 0 || integer > 60'000 ||
        !strictBool(settings, root + QStringLiteral("hasSwitchDoubleTap"), false, boolean) ||
        !strictInt(settings, root + QStringLiteral("switchDoubleTap"), 250, integer) ||
        integer < 0 || integer > 60'000 ||
        !strictInt(settings, root + QStringLiteral("switchCornerSize"), 0, integer) ||
        integer < 0 || integer > 100'000 ||
        !strictBool(settings, root + QStringLiteral("ignoreAutoConfigClient"), false, boolean) ||
        !strictBool(settings, root + QStringLiteral("enableDragAndDrop"), true, boolean) ||
        !strictBool(settings, root + QStringLiteral("clipboardSharing"), true, boolean) ||
        !strictUnsignedLongLong(settings, root + QStringLiteral("clipboardSharingSize"),
                                0, clipboardSize))
        return false;

    for (int i = 1; i <= static_cast<int>(BaseConfig::SwitchCorner::Count); ++i) {
        if (!strictBool(settings, root + QStringLiteral("switchCornerArray/") +
                        QString::number(i) + QStringLiteral("/switchCorner"), false, boolean))
            return false;
    }

    for (int screen = 1; screen <= screens; ++screen) {
        const QString prefix = root + QStringLiteral("screens/") + QString::number(screen);
        QString text;
        if (!strictString(settings, prefix + QStringLiteral("/name"), QString(), text) ||
            !strictInt(settings, prefix + QStringLiteral("/switchCornerSize"), 0, integer) ||
            integer < 0 || integer > 100'000)
            return false;
        int aliases = 0;
        if (!boundedArraySize(settings, prefix + QStringLiteral("/aliasArray"),
                              MaxAliasesPerScreen, aliases))
            return false;
        for (int i = 1; i <= aliases; ++i) {
            if (!strictString(settings, prefix + QStringLiteral("/aliasArray/") +
                              QString::number(i) + QStringLiteral("/alias"), QString(), text))
                return false;
        }
        for (int i = 1; i <= static_cast<int>(BaseConfig::Modifier::Count); ++i) {
            if (!strictInt(settings, prefix + QStringLiteral("/modifierArray/") +
                           QString::number(i) + QStringLiteral("/modifier"),
                           static_cast<int>(BaseConfig::Modifier::DefaultMod), integer) ||
                integer < static_cast<int>(BaseConfig::Modifier::DefaultMod) ||
                integer >= static_cast<int>(BaseConfig::Modifier::Count))
                return false;
        }
        for (int i = 1; i <= static_cast<int>(BaseConfig::SwitchCorner::Count); ++i) {
            if (!strictBool(settings, prefix + QStringLiteral("/switchCornerArray/") +
                            QString::number(i) + QStringLiteral("/switchCorner"), false, boolean))
                return false;
        }
        for (int i = 1; i <= static_cast<int>(BaseConfig::Fix::Count); ++i) {
            if (!strictBool(settings, prefix + QStringLiteral("/fixArray/") +
                            QString::number(i) + QStringLiteral("/fix"), false, boolean))
                return false;
        }
    }

    int hotkeys = 0;
    if (!boundedArraySize(settings, root + QStringLiteral("hotkeys"), MaxHotkeys, hotkeys))
        return false;
    for (int hotkey = 1; hotkey <= hotkeys; ++hotkey) {
        const QString prefix = root + QStringLiteral("hotkeys/") + QString::number(hotkey);
        if (!validateKeySequence(settings, prefix))
            return false;
        int actions = 0;
        if (!boundedArraySize(settings, prefix + QStringLiteral("/actions"),
                              MaxActionsPerHotkey, actions))
            return false;
        for (int action = 1; action <= actions; ++action) {
            const QString actionPrefix = prefix + QStringLiteral("/actions/") + QString::number(action);
            if (!validateKeySequence(settings, actionPrefix) ||
                !strictInt(settings, actionPrefix + QStringLiteral("/type"),
                           static_cast<int>(Action::keyDown), integer) ||
                integer < static_cast<int>(Action::keyDown) ||
                integer > static_cast<int>(Action::mousebutton))
                return false;
            int names = 0;
            if (!boundedArraySize(settings, actionPrefix + QStringLiteral("/typeScreenNames"),
                                  MaxColumns * MaxRows, names))
                return false;
            QString text;
            for (int i = 1; i <= names; ++i) {
                if (!strictString(settings, actionPrefix + QStringLiteral("/typeScreenNames/") +
                                  QString::number(i) + QStringLiteral("/screenName"), QString(), text))
                    return false;
            }
            if (!strictString(settings, actionPrefix + QStringLiteral("/switchToScreen"), QString(), text) ||
                !strictInt(settings, actionPrefix + QStringLiteral("/switchDirection"),
                           static_cast<int>(Action::switchLeft), integer) ||
                integer < static_cast<int>(Action::switchLeft) ||
                integer > static_cast<int>(Action::switchDown) ||
                !strictInt(settings, actionPrefix + QStringLiteral("/lockToScreen"),
                           static_cast<int>(Action::lockCursorToggle), integer) ||
                integer < static_cast<int>(Action::lockCursorToggle) ||
                integer > static_cast<int>(Action::lockCursorOff) ||
                !strictBool(settings, actionPrefix + QStringLiteral("/activeOnRelease"), false, boolean) ||
                !strictBool(settings, actionPrefix + QStringLiteral("/hasScreens"), false, boolean))
                return false;
        }
    }
    const QString layoutRoot = root + QStringLiteral("screenLayoutExtension/");
    bool hasLayoutMetadata = false;
    for (const QString& key : settings.allKeys()) {
        if (key.startsWith(layoutRoot)) {
            hasLayoutMetadata = true;
            break;
        }
    }
    if (hasLayoutMetadata) {
        int schemaVersion = 0;
        const QString schemaKey = layoutRoot + QStringLiteral("schemaVersion");
        if (!settings.contains(schemaKey) ||
            !strictInt(settings, schemaKey, 0, schemaVersion) ||
            schemaVersion < 1 || schemaVersion > 2)
            return false;
    }
    return true;
}

bool validateStartupConsumerArrays(QSettings& settings)
{
    constexpr int MaxRegistryDevices = 4096;
    constexpr int MaxRecentDestinations = 1024;
    constexpr int MaxTransferHistory = 100;
    int count = 0;
    const auto validSize = [&](const QString& key, int maximum) {
        return !settings.contains(key) ||
               (strictInt(settings, key, 0, count) && count >= 0 && count <= maximum);
    };
    if (!validSize(QStringLiteral("recentDestinations/size"), MaxRecentDestinations) ||
        !validSize(QStringLiteral("transferHistory/size"), MaxTransferHistory))
        return false;
    for (const QString& key : settings.allKeys()) {
        if (key.startsWith(QStringLiteral("deviceRegistry/")) &&
            key.endsWith(QStringLiteral("/devices/size")) &&
            !validSize(key, MaxRegistryDevices))
            return false;
    }
    return validSize(QStringLiteral("deviceRegistry/devices/size"), MaxRegistryDevices);
}

StartupSettingsPreflight::Status backendStatus(const QSettings& settings)
{
    if (settings.status() == QSettings::FormatError)
        return StartupSettingsPreflight::Status::FormatError;
    if (settings.status() == QSettings::AccessError)
        return StartupSettingsPreflight::Status::AccessError;
    return StartupSettingsPreflight::Status::Valid;
}
}

StartupSettingsPreflight::Status StartupSettingsPreflight::inspect(QSettings& settings)
{
    if (!settings.group().isEmpty())
        return Status::AccessError;

#ifdef Q_OS_WIN
    const bool nativeStoreExistedBeforeSync =
        settings.format() == QSettings::NativeFormat &&
        emptyNativeStorePhysicallyExists(settings);
#endif
    settings.sync();
    if (const auto status = backendStatus(settings); status != Status::Valid)
        return status;
    if (settings.allKeys().isEmpty()) {
        if (settings.format() == QSettings::IniFormat) {
            const QFileInfo file(settings.fileName());
            if (file.exists())
                return Status::FormatError;
        }
#ifdef Q_OS_WIN
        else if (settings.format() == QSettings::NativeFormat &&
                 nativeStoreExistedBeforeSync) {
            return Status::FormatError;
        }
#endif
        return Status::Missing;
    }

    int port = 0;
    int logLevel = 0;
    QString language;
    bool cryptoEnabled = false;
    bool requireClientCertificate = false;
    bool autoHide = false;
    bool autoStart = false;
    bool minimizeToTray = false;
    QString screenName;
    QString networkInterface;
    bool logToFile = false;
    QString logFilename;
    QString receiveDirectory;
    int wizardLastRun = 0;
    bool startedBefore = false;
    bool autoConfig = true;
    bool legacyElevateMode = false;
    int elevateMode = static_cast<int>(ElevateAsNeeded);
    bool autoConfigPrompted = false;
    QString legacyPairingCode;
    if (!strictInt(settings, QStringLiteral("port"), 24800, port) ||
        !strictInt(settings, QStringLiteral("logLevel"), 3, logLevel) ||
        !strictString(settings, QStringLiteral("language"), QStringLiteral("pt-BR"), language) ||
        !strictBool(settings, QStringLiteral("cryptoEnabled"), true, cryptoEnabled) ||
        !strictBool(settings, QStringLiteral("requireClientCertificate"), false,
                    requireClientCertificate) ||
        !strictBool(settings, QStringLiteral("autoHide"), false, autoHide) ||
        !strictBool(settings, QStringLiteral("autoStart"), false, autoStart) ||
        !strictBool(settings, QStringLiteral("minimizeToTray"), false, minimizeToTray) ||
        !strictString(settings, QStringLiteral("screenName"), QString(), screenName) ||
        !strictString(settings, QStringLiteral("interface"), QString(), networkInterface) ||
        !strictBool(settings, QStringLiteral("logToFile"), false, logToFile) ||
        !strictString(settings, QStringLiteral("logFilename"), QString(), logFilename) ||
        !strictString(settings, QStringLiteral("receiveDirectory"), QString(), receiveDirectory) ||
        !strictInt(settings, QStringLiteral("wizardLastRun"), 0, wizardLastRun) ||
        !strictBool(settings, QStringLiteral("startedBefore"), false, startedBefore) ||
        !strictBool(settings, QStringLiteral("autoConfig"), true, autoConfig) ||
        !strictBool(settings, QStringLiteral("elevateMode"), false, legacyElevateMode) ||
        !strictInt(settings, QStringLiteral("elevateModeEnum"),
                   static_cast<int>(ElevateAsNeeded), elevateMode) ||
        !strictBool(settings, QStringLiteral("autoConfigPrompted"), false,
                    autoConfigPrompted) ||
        !strictString(settings, QStringLiteral("fileTransferPairingCode"),
                      QString(), legacyPairingCode) ||
        legacyPairingCode.size() > 4096 ||
        legacyPairingCode.contains(QChar::Null)) {
        return Status::InvalidValue;
    }
    if (wizardLastRun < 0 || wizardLastRun > kWizardVersion ||
        elevateMode < static_cast<int>(ElevateAsNeeded) ||
        elevateMode > static_cast<int>(ElevateNever)) {
        return Status::InvalidValue;
    }
    if (!validateInternalConfig(settings) || !validateStartupConsumerArrays(settings)) {
        return Status::InvalidValue;
    }
    language.replace(QLatin1Char('_'), QLatin1Char('-'));
    if (!ConfigurationPortablePreferences::create(
            port, logLevel, language, cryptoEnabled, requireClientCertificate,
            autoHide, autoStart, minimizeToTray)) {
        return Status::InvalidValue;
    }
    return backendStatus(settings);
}

qsizetype StartupSettingsPreflight::copyLegacyPublicSettings(
    const QSettings& source, QSettings& destination)
{
    ConfigurationTransactionLock transaction;
    if (!transaction.isLocked())
        return -1;
    const Status destinationStatus = inspect(destination);
    if (destinationStatus == Status::Valid)
        return 0;
    if (destinationStatus != Status::Missing)
        return -1;

    static const QStringList PublicKeys{
        QStringLiteral("screenName"), QStringLiteral("port"),
        QStringLiteral("interface"), QStringLiteral("logLevel"),
        QStringLiteral("logToFile"), QStringLiteral("logFilename"),
        QStringLiteral("receiveDirectory"), QStringLiteral("wizardLastRun"),
        QStringLiteral("language"), QStringLiteral("startedBefore"),
        QStringLiteral("autoConfig"), QStringLiteral("elevateMode"),
        QStringLiteral("elevateModeEnum"), QStringLiteral("autoConfigPrompted"),
        QStringLiteral("cryptoEnabled"), QStringLiteral("requireClientCertificate"),
        QStringLiteral("autoHide"), QStringLiteral("autoStart"),
        QStringLiteral("minimizeToTray")
    };
    QList<QPair<QString, QVariant>> values;
    values.reserve(PublicKeys.size());
    for (const QString& key : PublicKeys) {
        if (source.contains(key))
            values.push_back({key, source.value(key)});
    }
    if (source.status() != QSettings::NoError)
        return -1;
    for (const auto& value : values)
        destination.setValue(value.first, value.second);
    destination.sync();
    if (destination.status() != QSettings::NoError || inspect(destination) != Status::Valid)
        return -1;
    return values.size();
}
