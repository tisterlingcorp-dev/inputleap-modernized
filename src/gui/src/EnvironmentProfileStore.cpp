/* InputLeap -- atomic environment profile persistence. */
#include "EnvironmentProfileStore.h"
#include "ConfigurationTransactionLock.h"
#include "EnvironmentProfileJsonCodec.h"
#include "RecoveryArtifactAuthenticator.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QLockFile>
#include <QMetaType>
#include <QScopeGuard>
#include <QSettings>
#include <QStandardPaths>
#include <QUuid>

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <limits>
#include <utility>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include <openssl/crypto.h>
#include <openssl/rand.h>

namespace {
constexpr auto RootGroup = "environmentProfiles";
constexpr auto ActiveGenerationKey = "environmentProfiles/activeGeneration";
constexpr auto RecoveryGenerationKey = "environmentProfiles/recoveryGeneration";
constexpr auto ManifestKey = "environmentProfiles/manifest";
constexpr auto GenerationsGroup = "environmentProfiles/generations";
constexpr int LockTimeoutMs = 5000;

bool canonicalGeneration(const QString& value);
constexpr qsizetype AuthenticationSize = 32;

struct RootManifest {
    int schema = 0;
    QString active;
    QString recovery;
    QByteArray activeTag;
    QByteArray recoveryTag;
};

std::optional<QByteArray> encodeManifest(
    const RootManifest& manifest,
    const EnvironmentProfileStore::AuthenticationFunction& authenticate,
    bool createKey)
{
    if (!authenticate || manifest.activeTag.size() != AuthenticationSize ||
        (manifest.recovery.isEmpty() != manifest.recoveryTag.isEmpty()) ||
        (!manifest.recovery.isEmpty() &&
         manifest.recoveryTag.size() != AuthenticationSize)) {
        return std::nullopt;
    }
    QByteArray encoded = QByteArrayLiteral("ILEPM2");
    encoded.append(static_cast<char>(manifest.schema));
    encoded.append(manifest.active.toUtf8());
    encoded.append(manifest.recovery.isEmpty() ? '\0' : '\1');
    if (!manifest.recovery.isEmpty()) encoded.append(manifest.recovery.toUtf8());
    encoded.append(manifest.activeTag);
    if (!manifest.recovery.isEmpty()) encoded.append(manifest.recoveryTag);
    const auto mac = authenticate(QByteArrayView(encoded), createKey);
    if (!mac || mac->size() != AuthenticationSize) return std::nullopt;
    encoded.append(*mac);
    return encoded;
}

std::optional<RootManifest> decodeManifest(
    const QVariant& value,
    const EnvironmentProfileStore::AuthenticationFunction& authenticate)
{
    if (!authenticate || value.metaType().id() != QMetaType::QByteArray)
        return std::nullopt;
    const QByteArray encoded = value.toByteArray();
    constexpr qsizetype PrefixSize = 6;
    constexpr qsizetype GenerationSize = 36;
    constexpr qsizetype BaseSize = PrefixSize + 1 + GenerationSize + 1 +
        AuthenticationSize + AuthenticationSize;
    constexpr qsizetype RecoverySize = BaseSize + GenerationSize + AuthenticationSize;
    if ((encoded.size() != BaseSize && encoded.size() != RecoverySize) ||
        !encoded.startsWith(QByteArrayLiteral("ILEPM2"))) return std::nullopt;
    const QByteArrayView payload(encoded.constData(), encoded.size() - AuthenticationSize);
    const auto expectedMac = authenticate(payload, false);
    if (!expectedMac || expectedMac->size() != AuthenticationSize ||
        CRYPTO_memcmp(expectedMac->constData(),
                      encoded.constData() + encoded.size() - AuthenticationSize,
                      AuthenticationSize) != 0) {
        return std::nullopt;
    }

    RootManifest result;
    qsizetype offset = PrefixSize;
    result.schema = static_cast<unsigned char>(encoded[offset++]);
    result.active = QString::fromUtf8(encoded.mid(offset, GenerationSize));
    offset += GenerationSize;
    const char hasRecovery = encoded[offset++];
    if (hasRecovery == '\1') {
        if (encoded.size() != RecoverySize) return std::nullopt;
        result.recovery = QString::fromUtf8(encoded.mid(offset, GenerationSize));
        offset += GenerationSize;
    }
    else if (hasRecovery != '\0' || encoded.size() != BaseSize) {
        return std::nullopt;
    }
    result.activeTag = encoded.mid(offset, AuthenticationSize);
    offset += AuthenticationSize;
    if (!result.recovery.isEmpty()) {
        result.recoveryTag = encoded.mid(offset, AuthenticationSize);
        offset += AuthenticationSize;
    }
    if (offset != encoded.size() - AuthenticationSize ||
        !canonicalGeneration(result.active) ||
        (!result.recovery.isEmpty() &&
         (!canonicalGeneration(result.recovery) || result.recovery == result.active))) {
        return std::nullopt;
    }
    return result;
}

QString generationGroup(const QString& generation)
{
    return QString::fromLatin1(GenerationsGroup) + QLatin1Char('/') + generation;
}

bool canonicalGeneration(const QString& value)
{
    if (value.size() != 36) return false;
    const QUuid uuid(value);
    return !uuid.isNull() && uuid.toString(QUuid::WithoutBraces) == value;
}

bool validProfileCollection(const QList<EnvironmentProfile>& profiles,
                            EnvironmentProfile::Kind activeKind)
{
    if (profiles.size() != EnvironmentProfile::canonicalKinds().size() ||
        !EnvironmentProfile::canonicalKinds().contains(activeKind)) {
        return false;
    }
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        const auto count = std::count_if(profiles.cbegin(), profiles.cend(),
                                         [kind](const EnvironmentProfile& profile) {
            return profile.kind == kind && profile.isValid();
        });
        if (count != 1)
            return false;
    }
    return true;
}

QByteArray generationTag(const QList<EnvironmentProfile>& profiles,
                         EnvironmentProfile::Kind activeKind)
{
    const auto object = EnvironmentProfileJsonCodec::encode({profiles, activeKind});
    return QCryptographicHash::hash(
        QJsonDocument(object).toJson(QJsonDocument::Compact),
        QCryptographicHash::Sha256);
}

EnvironmentProfileStore::AuthenticationFunction ephemeralAuthentication()
{
    return [](QByteArrayView payload, bool) -> std::optional<QByteArray> {
        static const QByteArray key = [] {
            QByteArray value(RecoveryArtifactAuthenticator::KeySize,
                             Qt::Uninitialized);
            if (RAND_bytes(reinterpret_cast<unsigned char*>(value.data()),
                           static_cast<int>(value.size())) != 1) {
                value.clear();
            }
            return value;
        }();
        if (key.size() != RecoveryArtifactAuthenticator::KeySize)
            return std::nullopt;
        const QByteArray domain =
            QByteArrayLiteral("inputleap-environment-profile-manifest-v2");
        const QByteArray mac = RecoveryArtifactAuthenticator::authenticate(
            QByteArrayView(key), QByteArrayView(domain), {payload});
        return mac.isEmpty() ? std::nullopt
                             : std::optional<QByteArray>(mac);
    };
}

bool strictInt(const QSettings& settings, const QString& key, int& result)
{
    if (!settings.contains(key)) return false;
    const QVariant value = settings.value(key);
    if (value.metaType().id() == QMetaType::Int) {
        result = value.toInt();
        return true;
    }
    if (value.metaType().id() != QMetaType::LongLong) return false;
    const qlonglong number = value.toLongLong();
    if (number < std::numeric_limits<int>::min() || number > std::numeric_limits<int>::max()) return false;
    result = static_cast<int>(number);
    return true;
}

bool strictUnsigned(const QSettings& settings, const QString& key, quint32& result)
{
    if (!settings.contains(key)) return false;
    const QVariant value = settings.value(key);
    qulonglong number = 0;
    if (value.metaType().id() == QMetaType::UInt) number = value.toUInt();
    else if (value.metaType().id() == QMetaType::ULongLong) number = value.toULongLong();
    else if (value.metaType().id() == QMetaType::LongLong) {
        const qlonglong signedNumber = value.toLongLong();
        if (signedNumber < 0) return false;
        number = static_cast<qulonglong>(signedNumber);
    }
    else return false;
    if (number > std::numeric_limits<quint32>::max()) return false;
    result = static_cast<quint32>(number);
    return true;
}

bool strictDouble(const QSettings& settings, const QString& key, double& result)
{
    if (!settings.contains(key)) return false;
    const QVariant value = settings.value(key);
    if (value.metaType().id() == QMetaType::Double) {
        result = value.toDouble();
        return std::isfinite(result);
    }
    if (value.metaType().id() != QMetaType::QString) return false;
    const QString text = value.toString();
    bool ok = false;
    const double parsed = text.toDouble(&ok);
    if (!ok || !std::isfinite(parsed) ||
        QString::number(parsed, 'g', 17) != text) return false;
    result = parsed;
    return true;
}

bool strictBool(const QSettings& settings, const QString& key, bool& result)
{
    if (!settings.contains(key)) return false;
    const QVariant value = settings.value(key);
    if (value.metaType().id() == QMetaType::Bool) {
        result = value.toBool();
        return true;
    }
    if (value.metaType().id() == QMetaType::Int) {
        const int integer = value.toInt();
        if (integer != 0 && integer != 1) return false;
        result = integer == 1;
        return true;
    }
    if (value.metaType().id() != QMetaType::QString) return false;
    const QString text = value.toString();
    if (text == QStringLiteral("true")) { result = true; return true; }
    if (text == QStringLiteral("false")) { result = false; return true; }
    return false;
}

bool hasType(const QSettings& settings, const QString& key, QMetaType::Type type)
{
    return settings.contains(key) && settings.value(key).metaType().id() == type;
}

bool directShape(QSettings& settings, const QString& group,
                 QStringList expectedKeys, QStringList expectedGroups)
{
    settings.beginGroup(group);
    QStringList keys = settings.childKeys();
    QStringList groups = settings.childGroups();
    settings.endGroup();
    keys.sort(); groups.sort(); expectedKeys.sort(); expectedGroups.sort();
    return keys == expectedKeys && groups == expectedGroups;
}

QStringList indexes(int count)
{
    QStringList result;
    for (int i = 1; i <= count; ++i) result.append(QString::number(i));
    return result;
}

bool strictLayoutShape(QSettings& settings, const QString& group)
{
    int schema = 0, devices = 0;
    if (!strictInt(settings, group + QStringLiteral("/schemaVersion"), schema) || schema != 2 ||
        !strictInt(settings, group + QStringLiteral("/devices/size"), devices) ||
        devices < 0 || devices > ScreenLayout::MaxDevices ||
        !directShape(settings, group, {QStringLiteral("schemaVersion")}, {QStringLiteral("devices")}) ||
        !directShape(settings, group + QStringLiteral("/devices"), {QStringLiteral("size")}, indexes(devices))) return false;
    for (int i = 1; i <= devices; ++i) {
        const QString device = group + QStringLiteral("/devices/") + QString::number(i);
        if (!directShape(settings, device,
                         {QStringLiteral("geometry"), QStringLiteral("technicalName"), QStringLiteral("uuid")},
                         {QStringLiteral("monitors")}) ||
            !hasType(settings, device + QStringLiteral("/uuid"), QMetaType::QString) ||
            !canonicalGeneration(settings.value(device + QStringLiteral("/uuid")).toString()) ||
            !hasType(settings, device + QStringLiteral("/technicalName"), QMetaType::QString) ||
            !hasType(settings, device + QStringLiteral("/geometry"), QMetaType::QRect)) return false;
        int monitors = 0;
        if (!strictInt(settings, device + QStringLiteral("/monitors/size"), monitors) ||
            monitors < 0 || monitors > ScreenLayout::MaxMonitorsPerDevice ||
            !directShape(settings, device + QStringLiteral("/monitors"), {QStringLiteral("size")}, indexes(monitors))) return false;
        for (int j = 1; j <= monitors; ++j) {
            const QString monitor = device + QStringLiteral("/monitors/") + QString::number(j);
            int orientation = 0;
            double devicePixelRatio = 0.0;
            bool stableIdentity = false;
            if (!directShape(settings, monitor,
                             {QStringLiteral("devicePixelRatio"), QStringLiteral("geometry"), QStringLiteral("id"),
                              QStringLiteral("orientation"), QStringLiteral("stableIdentity")}, {}) ||
                !hasType(settings, monitor + QStringLiteral("/id"), QMetaType::QString) ||
                !hasType(settings, monitor + QStringLiteral("/geometry"), QMetaType::QRect) ||
                !strictDouble(settings, monitor + QStringLiteral("/devicePixelRatio"),
                              devicePixelRatio) ||
                !strictInt(settings, monitor + QStringLiteral("/orientation"), orientation) ||
                !strictBool(settings, monitor + QStringLiteral("/stableIdentity"),
                            stableIdentity)) return false;
        }
    }
    return true;
}

bool sameLayout(const ScreenLayout& first, const ScreenLayout& second)
{
    const auto& a = first.devices(); const auto& b = second.devices();
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i].uuid != b[i].uuid || a[i].technicalName != b[i].technicalName ||
            a[i].geometry != b[i].geometry || a[i].monitors.size() != b[i].monitors.size()) return false;
        for (size_t j = 0; j < a[i].monitors.size(); ++j) {
            const auto& x = a[i].monitors[j]; const auto& y = b[i].monitors[j];
            if (x.id != y.id || x.geometry != y.geometry || x.devicePixelRatio != y.devicePixelRatio ||
                x.orientation != y.orientation || x.stableIdentity != y.stableIdentity) return false;
        }
    }
    return true;
}

bool sameProfile(const EnvironmentProfile& first, const EnvironmentProfile& second)
{
    return first.kind == second.kind && first.layout.columns == second.layout.columns &&
           first.layout.rows == second.layout.rows && first.layout.gridTechnicalNames == second.layout.gridTechnicalNames &&
           first.devices == second.devices && sameLayout(first.layout.extension, second.layout.extension);
}

#ifdef Q_OS_WIN
QString resolveCanonicalPathWithFinalHandle(const QString& path)
{
    if (path.isEmpty()) return {};
    if (!QFileInfo(path).exists()) return {};

    const QString nativePath = QDir::toNativeSeparators(path);
    HANDLE handle = CreateFileW(
        reinterpret_cast<LPCWSTR>(nativePath.utf16()),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return {};
    }

    constexpr int kMaxPathLength = 4096;
    wchar_t resolvedPath[kMaxPathLength] = {};
    const DWORD length = GetFinalPathNameByHandleW(handle, resolvedPath, kMaxPathLength,
                                                  FILE_NAME_NORMALIZED | FILE_NAME_OPENED);
    CloseHandle(handle);

    if (length == 0 || length >= kMaxPathLength) return {};

    QString result = QString::fromWCharArray(resolvedPath, static_cast<int>(length));
    const QString nativePrefix = QStringLiteral(R"(\\?\\)" );
    if (result.startsWith(nativePrefix)) {
        result.remove(0, nativePrefix.size());
    }
    return result;
}
#endif

bool sameProfiles(const QList<EnvironmentProfile>& first, const QList<EnvironmentProfile>& second)
{
    if (first.size() != second.size()) return false;
    for (int i = 0; i < first.size(); ++i) if (!sameProfile(first[i], second[i])) return false;
    return true;
}

QString normalizedSettingsPath(const QString& fileName)
{
    const QFileInfo info(fileName);
    QString result = info.canonicalFilePath();
    if (result.isEmpty() || !QFileInfo(result).exists()) {
#ifdef Q_OS_WIN
        std::error_code error;
        const auto canonical = std::filesystem::weakly_canonical(
            std::filesystem::path(info.absoluteFilePath().toStdWString()), error);
        if (!error)
            result = QString::fromStdWString(canonical.native());

        if (result.isEmpty() || !QFileInfo(result).exists()) {
            const auto canonicalParent = std::filesystem::weakly_canonical(
                std::filesystem::path(info.absolutePath().toStdWString()), error);
            if (!error && !canonicalParent.empty()) {
                result = QString::fromStdWString(canonicalParent.native());
                result = QDir(result).filePath(info.fileName());
            }
        }
#endif
    }
    if (result.isEmpty() || !QFileInfo(result).exists()) {
        QString parentPath = info.absolutePath();
        QStringList unresolved{info.fileName()};
        while (result.isEmpty() || !QFileInfo(result).exists()) {
            const QFileInfo parent(parentPath);
            QString canonicalParent;
#ifdef Q_OS_WIN
            canonicalParent = resolveCanonicalPathWithFinalHandle(parent.absolutePath());
#endif
            if (canonicalParent.isEmpty()) {
                canonicalParent = parent.canonicalFilePath();
            }
            if (!canonicalParent.isEmpty()) {
                result = QDir(canonicalParent).filePath(unresolved.join(QLatin1Char('/')));
                break;
            }
            const QString nextParent = parent.absolutePath();
            if (nextParent == parentPath)
                break;
            unresolved.prepend(parent.fileName());
            parentPath = nextParent;
        }
    }
    if (result.isEmpty()) {
        result = QDir(info.absolutePath()).canonicalPath();
        if (!result.isEmpty()) {
            result = QDir(result).filePath(info.fileName());
        }
    }
    if (result.isEmpty()) result = QDir::cleanPath(info.absoluteFilePath());
#ifdef Q_OS_WIN
    result = result.toLower();
#endif
    return QDir::toNativeSeparators(result);
}
}

EnvironmentProfileStore::EnvironmentProfileStore(
    QSettings& settings, SyncFunction sync,
    AuthenticationFunction authentication,
    AuthenticationKeyPresentFunction authenticationKeyPresent) :
    settings_(settings),
    sync_(sync ? std::move(sync) : [](QSettings& value) {
        value.sync();
        return value.status() == QSettings::NoError;
    }),
    authentication_(authentication ? std::move(authentication)
                                   : ephemeralAuthentication()),
    authenticationKeyPresent_(authenticationKeyPresent
        ? std::move(authenticationKeyPresent) : [] { return false; })
{
    load();
}

bool EnvironmentProfileStore::sync() { return sync_(settings_); }

bool EnvironmentProfileStore::mutationsAllowed() const
{
    return loadStatus_ == LoadStatus::Loaded && !saveFailed_;
}

QString EnvironmentProfileStore::lockFilePath() const
{
    return lockFilePathForSettings(settings_);
}

QString EnvironmentProfileStore::lockFilePathForSettings(const QSettings& settings)
{
    const QString normalized = normalizedSettingsPath(settings.fileName());
    if (settings.format() == QSettings::IniFormat) {
        const QFileInfo file(normalized);
        if (!QDir().mkpath(file.absolutePath())) return {};
        return normalized + QStringLiteral(".environmentProfiles.lock");
    }

    QByteArray identity = normalized.toUtf8();
    identity.append('\0');
    identity.append(QByteArray::number(static_cast<int>(settings.format())));
    const QString digest = QString::fromLatin1(QCryptographicHash::hash(identity, QCryptographicHash::Sha256).toHex());
    QString directory = QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation);
    if (directory.isEmpty()) directory = QDir::tempPath() + QStringLiteral("/inputleap");
    else directory += QStringLiteral("/inputleap");
    directory += QStringLiteral("/environment-profile-locks");
    if (!QDir().mkpath(directory)) return {};
    return directory + QLatin1Char('/') + digest + QStringLiteral(".lock");
}

EnvironmentProfileStore::LoadStatus EnvironmentProfileStore::load()
{
    profiles_.clear(); activeKind_.reset(); generation_.reset();
    if (!settings_.group().isEmpty() || settings_.status() != QSettings::NoError)
        return loadStatus_ = LoadStatus::SettingsError;

    settings_.beginGroup(QString::fromLatin1(RootGroup));
    const QStringList namespaceKeys = settings_.childKeys();
    const QStringList namespaceGroups = settings_.childGroups();
    settings_.endGroup();
    bool namespacePresent = !namespaceKeys.isEmpty() ||
        std::any_of(namespaceGroups.cbegin(), namespaceGroups.cend(), [](const QString& group) {
            return group != QStringLiteral("generations");
        });
    if (!namespacePresent && namespaceGroups.contains(QStringLiteral("generations"))) {
        settings_.beginGroup(QString::fromLatin1(GenerationsGroup));
        namespacePresent = !settings_.childKeys().isEmpty() ||
            !settings_.childGroups().isEmpty();
        settings_.endGroup();
    }
    if (!namespacePresent) return loadStatus_ = LoadStatus::Missing;

    const QString schemaKey = QString::fromLatin1(RootGroup) + QStringLiteral("/schemaVersion");
    const bool hasManifest = settings_.contains(QString::fromLatin1(ManifestKey));
    const auto manifest = hasManifest
        ? decodeManifest(settings_.value(QString::fromLatin1(ManifestKey)),
                         authentication_)
        : std::optional<RootManifest>{};
    if (hasManifest && !manifest)
        return loadStatus_ = LoadStatus::InvalidSchema;
    int physicalSchema = 0;
    if (!strictInt(settings_, schemaKey, physicalSchema))
        return loadStatus_ = LoadStatus::InvalidSchema;
    if (physicalSchema > SchemaVersion)
        return loadStatus_ = LoadStatus::FutureSchema;
    int schema = manifest ? manifest->schema : physicalSchema;
    if ((manifest && physicalSchema != schema) ||
        schema < OldestSupportedSchemaVersion) {
        return loadStatus_ = LoadStatus::InvalidSchema;
    }
    if (schema > SchemaVersion)
        return loadStatus_ = LoadStatus::FutureSchema;
    if (schema < SchemaVersion) {
        try {
            if (authenticationKeyPresent_())
                return loadStatus_ = LoadStatus::InvalidSchema;
        }
        catch (...) {
            return loadStatus_ = LoadStatus::InvalidSchema;
        }
    }
    if (schema == SchemaVersion && !manifest)
        return loadStatus_ = LoadStatus::InvalidSchema;

    QStringList rootKeys = schema == 1
        ? QStringList{QStringLiteral("activeGeneration"), QStringLiteral("schemaVersion")}
        : QStringList{QStringLiteral("activeGeneration"), QStringLiteral("recoveryGeneration"),
                      QStringLiteral("schemaVersion")};
    if (hasManifest) rootKeys.append(QStringLiteral("manifest"));
    if (!directShape(settings_, QString::fromLatin1(RootGroup), rootKeys,
                     {QStringLiteral("generations")}) ||
        !hasType(settings_, QString::fromLatin1(ActiveGenerationKey), QMetaType::QString) ||
        (schema == 2 &&
         !hasType(settings_, QString::fromLatin1(RecoveryGenerationKey), QMetaType::QString))) {
        return loadStatus_ = LoadStatus::InvalidSchema;
    }

    const QString physicalGeneration =
        settings_.value(QString::fromLatin1(ActiveGenerationKey)).toString();
    if (!canonicalGeneration(physicalGeneration))
        return loadStatus_ = LoadStatus::InvalidSchema;
    const QString generation = manifest ? manifest->active : physicalGeneration;
    if ((manifest && physicalGeneration != generation) ||
        !canonicalGeneration(generation)) {
        return loadStatus_ = LoadStatus::InvalidSchema;
    }
    const QString physicalRecovery = schema == 2
        ? settings_.value(QString::fromLatin1(RecoveryGenerationKey)).toString()
        : QString();
    if (schema == 2 && !physicalRecovery.isEmpty() &&
        !canonicalGeneration(physicalRecovery)) {
        return loadStatus_ = LoadStatus::InvalidSchema;
    }
    const QString recovery = manifest ? manifest->recovery : physicalRecovery;
    if ((manifest && physicalRecovery != recovery) ||
        (schema == 2 && !recovery.isEmpty() &&
         (!canonicalGeneration(recovery) || recovery == generation))) {
        return loadStatus_ = LoadStatus::InvalidSchema;
    }

    settings_.beginGroup(QString::fromLatin1(GenerationsGroup));
    const QStringList generations = settings_.childGroups();
    const QStringList generationKeys = settings_.childKeys();
    settings_.endGroup();
    if (!generationKeys.isEmpty() || generations.isEmpty() ||
        !generations.contains(generation) ||
        (!recovery.isEmpty() && !generations.contains(recovery)) ||
        std::any_of(generations.cbegin(), generations.cend(), [](const QString& value) { return !canonicalGeneration(value); }))
        return loadStatus_ = LoadStatus::InvalidSchema;

    int activeGenerationSchema = 0;
    if (strictInt(settings_, generationGroup(generation) + QStringLiteral("/schemaVersion"),
                  activeGenerationSchema) &&
        activeGenerationSchema > SchemaVersion) {
        return loadStatus_ = LoadStatus::FutureSchema;
    }

    QList<EnvironmentProfile> loaded;
    EnvironmentProfile::Kind active = EnvironmentProfile::Kind::Home;
    if (!readGeneration(generationGroup(generation), loaded, active))
        return loadStatus_ = settings_.status() == QSettings::NoError ? LoadStatus::InvalidSchema : LoadStatus::SettingsError;
    if (manifest && generationTag(loaded, active) != manifest->activeTag)
        return loadStatus_ = LoadStatus::InvalidSchema;
    profiles_ = std::move(loaded); activeKind_ = active; generation_ = generation;
    return loadStatus_ = LoadStatus::Loaded;
}

EnvironmentProfileStore::LoadStatus EnvironmentProfileStore::loadStatus() const { return loadStatus_; }
QList<EnvironmentProfile> EnvironmentProfileStore::profiles() const { return profiles_; }

std::optional<EnvironmentProfile> EnvironmentProfileStore::profile(EnvironmentProfile::Kind kind) const
{
    const auto found = std::find_if(profiles_.cbegin(), profiles_.cend(),
                                    [kind](const EnvironmentProfile& value) { return value.kind == kind; });
    if (found == profiles_.cend()) return std::nullopt;
    return *found;
}

std::optional<EnvironmentProfile::Kind> EnvironmentProfileStore::activeKind() const { return activeKind_; }
std::optional<QString> EnvironmentProfileStore::currentGeneration() const { return generation_; }

EnvironmentProfileStore::SaveResult EnvironmentProfileStore::initializeFromLegacy(const EnvironmentProfile& current)
{
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return SaveResult::SettingsError;
    if (!current.isValid()) return SaveResult::InvalidProfile;
    if (saveFailed_ || mutationInProgress_) return SaveResult::SettingsError;
    mutationInProgress_ = true;
    const auto mutationGuard = qScopeGuard([this] { mutationInProgress_ = false; });
    const QString path = lockFilePath();
    if (path.isEmpty()) return SaveResult::SettingsError;
    QLockFile fileLock(path); fileLock.setStaleLockTime(30000);
    if (!fileLock.tryLock(LockTimeoutMs)) return SaveResult::SettingsError;
    if (!sync()) return SaveResult::SettingsError;
    load();
    if (loadStatus_ == LoadStatus::FutureSchema) return SaveResult::ReadOnlyFutureSchema;
    if (loadStatus_ == LoadStatus::Loaded) return SaveResult::AlreadyInitialized;
    if (loadStatus_ != LoadStatus::Missing) return SaveResult::SettingsError;
    QList<EnvironmentProfile> initialized;
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        EnvironmentProfile clone = current; clone.kind = kind; initialized.append(std::move(clone));
    }
    return persist(initialized, EnvironmentProfile::Kind::Home);
}

EnvironmentProfileStore::SaveResult EnvironmentProfileStore::replaceProfile(const EnvironmentProfile& replacement)
{
    return replaceProfileImpl(replacement, std::nullopt).result;
}

EnvironmentProfileStore::Mutation EnvironmentProfileStore::replaceProfileIfGeneration(
    const EnvironmentProfile& replacement, const QString& expectedGeneration,
    const std::optional<QString>& recoveryGenerationOverride)
{
    return replaceProfileImpl(replacement, expectedGeneration, recoveryGenerationOverride);
}

EnvironmentProfileStore::Mutation EnvironmentProfileStore::replaceAllIfGeneration(
    const QList<EnvironmentProfile>& replacements, EnvironmentProfile::Kind activeKind,
    const QString& expectedGeneration,
    const std::optional<QString>& recoveryGenerationOverride)
{
    Mutation mutation;
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return mutation;
    if (!validProfileCollection(replacements, activeKind)) {
        mutation.result = SaveResult::InvalidProfile;
        return mutation;
    }
    if (mutationInProgress_)
        return mutation;
    mutationInProgress_ = true;
    const auto mutationGuard = qScopeGuard([this] { mutationInProgress_ = false; });
    const QString path = lockFilePath();
    if (path.isEmpty())
        return mutation;
    QLockFile fileLock(path);
    fileLock.setStaleLockTime(30000);
    if (!fileLock.tryLock(LockTimeoutMs) || !sync())
        return mutation;
    load();
    mutation.resultingGeneration = generation_.value_or(QString());
    if (loadStatus_ == LoadStatus::FutureSchema) {
        mutation.result = SaveResult::ReadOnlyFutureSchema;
        return mutation;
    }
    if (!mutationsAllowed())
        return mutation;
    if (generation_ != expectedGeneration) {
        mutation.result = SaveResult::ConcurrentModification;
        mutation.previousGeneration = expectedGeneration;
        return mutation;
    }
    mutation.previousGeneration = *generation_;
    mutation.result = persist(replacements, activeKind, recoveryGenerationOverride);
    mutation.resultingGeneration = generation_.value_or(QString());
    return mutation;
}

EnvironmentProfileStore::Mutation EnvironmentProfileStore::replaceProfileImpl(
    const EnvironmentProfile& replacement, const std::optional<QString>& expectedGeneration,
    const std::optional<QString>& recoveryGenerationOverride)
{
    Mutation mutation;
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return mutation;
    if (!replacement.isValid()) { mutation.result = SaveResult::InvalidProfile; return mutation; }
    if (mutationInProgress_) return mutation;
    mutationInProgress_ = true;
    const auto mutationGuard = qScopeGuard([this] { mutationInProgress_ = false; });
    const QString path = lockFilePath();
    if (path.isEmpty()) return mutation;
    QLockFile fileLock(path); fileLock.setStaleLockTime(30000);
    if (!fileLock.tryLock(LockTimeoutMs) || !sync()) return mutation;
    load();
    mutation.resultingGeneration = generation_.value_or(QString());
    if (loadStatus_ == LoadStatus::FutureSchema) { mutation.result = SaveResult::ReadOnlyFutureSchema; return mutation; }
    if (!mutationsAllowed()) return mutation;
    if (expectedGeneration && generation_ != expectedGeneration) {
        mutation.result = SaveResult::ConcurrentModification;
        mutation.previousGeneration = *expectedGeneration;
        return mutation;
    }
    mutation.previousGeneration = *generation_;
    QList<EnvironmentProfile> changed = profiles_;
    const auto found = std::find_if(changed.begin(), changed.end(), [&](const EnvironmentProfile& value) {
        return value.kind == replacement.kind;
    });
    if (found == changed.end()) { mutation.result = SaveResult::InvalidProfile; return mutation; }
    *found = replacement;
    mutation.result = persist(changed, *activeKind_, recoveryGenerationOverride);
    mutation.resultingGeneration = generation_.value_or(QString());
    if (mutation.result == SaveResult::Success) mutation.promotedProfile = profile(replacement.kind);
    return mutation;
}

EnvironmentProfileStore::SaveResult EnvironmentProfileStore::setActive(EnvironmentProfile::Kind kind)
{
    return setActiveImpl(kind, std::nullopt).result;
}

EnvironmentProfileStore::Mutation EnvironmentProfileStore::setActiveIfGeneration(
    EnvironmentProfile::Kind kind, const QString& expectedGeneration,
    const std::optional<QString>& recoveryGenerationOverride)
{
    return setActiveImpl(kind, expectedGeneration, recoveryGenerationOverride);
}

EnvironmentProfileStore::Mutation EnvironmentProfileStore::setActiveImpl(
    EnvironmentProfile::Kind kind, const std::optional<QString>& expectedGeneration,
    const std::optional<QString>& recoveryGenerationOverride)
{
    Mutation mutation;
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return mutation;
    if (!EnvironmentProfile::canonicalKinds().contains(kind)) { mutation.result = SaveResult::InvalidProfile; return mutation; }
    if (mutationInProgress_) return mutation;
    mutationInProgress_ = true;
    const auto mutationGuard = qScopeGuard([this] { mutationInProgress_ = false; });
    const QString path = lockFilePath();
    if (path.isEmpty()) return mutation;
    QLockFile fileLock(path); fileLock.setStaleLockTime(30000);
    if (!fileLock.tryLock(LockTimeoutMs) || !sync()) return mutation;
    load();
    mutation.resultingGeneration = generation_.value_or(QString());
    if (loadStatus_ == LoadStatus::FutureSchema) { mutation.result = SaveResult::ReadOnlyFutureSchema; return mutation; }
    if (!mutationsAllowed() || !profile(kind).has_value()) return mutation;
    if (expectedGeneration && generation_ != expectedGeneration) {
        mutation.result = SaveResult::ConcurrentModification;
        mutation.previousGeneration = *expectedGeneration;
        return mutation;
    }
    mutation.previousGeneration = *generation_;
    mutation.result = persist(profiles_, kind, recoveryGenerationOverride);
    mutation.resultingGeneration = generation_.value_or(QString());
    if (mutation.result == SaveResult::Success) mutation.promotedProfile = profile(kind);
    return mutation;
}

EnvironmentProfileStore::SaveResult EnvironmentProfileStore::verifyGeneration(const QString& expectedGeneration)
{
    if (mutationInProgress_) return SaveResult::SettingsError;
    mutationInProgress_ = true;
    const auto mutationGuard = qScopeGuard([this] { mutationInProgress_ = false; });
    const QString path = lockFilePath();
    if (path.isEmpty()) return SaveResult::SettingsError;
    QLockFile fileLock(path); fileLock.setStaleLockTime(30000);
    if (!fileLock.tryLock(LockTimeoutMs) || !sync()) return SaveResult::SettingsError;
    load();
    if (loadStatus_ == LoadStatus::FutureSchema) return SaveResult::ReadOnlyFutureSchema;
    if (!mutationsAllowed()) return SaveResult::SettingsError;
    return generation_ == expectedGeneration ? SaveResult::Success : SaveResult::ConcurrentModification;
}

EnvironmentProfileStore::SaveResult EnvironmentProfileStore::consumeVerifiedGeneration(
    const QString& expectedGeneration, const VerifiedConsumer& consumer)
{
    if (!consumer || mutationInProgress_) return SaveResult::SettingsError;
    mutationInProgress_ = true;
    const auto mutationGuard = qScopeGuard([this] { mutationInProgress_ = false; });
    const QString path = lockFilePath();
    if (path.isEmpty()) return SaveResult::SettingsError;
    QLockFile fileLock(path);
    fileLock.setStaleLockTime(30000);
    if (!fileLock.tryLock(LockTimeoutMs) || !sync()) return SaveResult::SettingsError;
    load();
    if (loadStatus_ == LoadStatus::FutureSchema) return SaveResult::ReadOnlyFutureSchema;
    if (!mutationsAllowed()) return SaveResult::SettingsError;
    if (generation_ != expectedGeneration) return SaveResult::ConcurrentModification;
    if (!activeKind_ || !generation_) return SaveResult::SettingsError;
    const auto activeProfile = profile(*activeKind_);
    if (!activeProfile || !activeProfile->isValid()) return SaveResult::InvalidProfile;
    return consumer({*activeKind_, *generation_, *activeProfile})
        ? SaveResult::Success : SaveResult::InvalidProfile;
}

EnvironmentProfileStore::RecoveryResult
EnvironmentProfileStore::recoverLastValidGeneration()
{
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked())
        return RecoveryResult::SettingsError;
    if (mutationInProgress_)
        return RecoveryResult::SettingsError;
    mutationInProgress_ = true;
    const auto mutationGuard = qScopeGuard([this] { mutationInProgress_ = false; });

    const QString path = lockFilePath();
    if (path.isEmpty())
        return RecoveryResult::SettingsError;
    QLockFile fileLock(path);
    fileLock.setStaleLockTime(30000);
    if (!fileLock.tryLock(LockTimeoutMs) || !sync())
        return RecoveryResult::SettingsError;

    const auto status = load();
    if (status == LoadStatus::Loaded) {
        // A caller that explicitly entered recovery has re-read a coherent
        // durable generation while holding both transaction locks. Only this
        // path may clear a prior indeterminate-write latch; ordinary load()
        // calls must not silently re-enable mutations.
        saveFailed_ = false;
        return RecoveryResult::NotNeeded;
    }
    if (status == LoadStatus::FutureSchema)
        return RecoveryResult::ReadOnlyFutureSchema;
    if (status != LoadStatus::InvalidSchema)
        return RecoveryResult::Unavailable;

    const QString root = QString::fromLatin1(RootGroup);
    const bool hasManifest = settings_.contains(QString::fromLatin1(ManifestKey));
    const QVariant originalManifestValue = settings_.value(QString::fromLatin1(ManifestKey));
    const auto manifest = hasManifest
        ? decodeManifest(originalManifestValue, authentication_) : std::optional<RootManifest>{};
    int schema = manifest ? manifest->schema : 0;
    QStringList expectedRootKeys{
        QStringLiteral("activeGeneration"), QStringLiteral("recoveryGeneration"),
        QStringLiteral("schemaVersion")};
    if (hasManifest) expectedRootKeys.append(QStringLiteral("manifest"));
    if (!manifest ||
        schema != SchemaVersion ||
        !directShape(settings_, root, expectedRootKeys,
                     {QStringLiteral("generations")}) ||
        !hasType(settings_, QString::fromLatin1(ActiveGenerationKey), QMetaType::QString) ||
        !hasType(settings_, QString::fromLatin1(RecoveryGenerationKey), QMetaType::QString)) {
        return RecoveryResult::Unavailable;
    }
    int physicalSchema = 0;
    const QString physicalActive =
        settings_.value(QString::fromLatin1(ActiveGenerationKey)).toString();
    const QString physicalRecovery =
        settings_.value(QString::fromLatin1(RecoveryGenerationKey)).toString();
    if (!strictInt(settings_, root + QStringLiteral("/schemaVersion"), physicalSchema))
        return RecoveryResult::Unavailable;
    const bool physicalMatchesManifest =
        physicalSchema == manifest->schema &&
        canonicalGeneration(physicalActive) &&
        (physicalRecovery.isEmpty() || canonicalGeneration(physicalRecovery)) &&
        physicalActive == manifest->active &&
        physicalRecovery == manifest->recovery;
    if (!physicalMatchesManifest) {
        // recoverLastValidGeneration() durably publishes the authenticated
        // recovery pointer before replacing the manifest. If that exact
        // transition is torn, finish it only when the failed generation is no
        // longer authenticated and the promoted recovery generation still is.
        QList<EnvironmentProfile> failedProfiles;
        EnvironmentProfile::Kind failedActive = EnvironmentProfile::Kind::Home;
        QList<EnvironmentProfile> recoveryProfiles;
        EnvironmentProfile::Kind recoveryActive = EnvironmentProfile::Kind::Home;
        int failedSchema = 0;
        if (strictInt(settings_,
                      generationGroup(manifest->active) + QStringLiteral("/schemaVersion"),
                      failedSchema) &&
            failedSchema > SchemaVersion) {
            return RecoveryResult::ReadOnlyFutureSchema;
        }
        const bool failedStillAuthenticated =
            readGeneration(generationGroup(manifest->active), failedProfiles, failedActive) &&
            generationTag(failedProfiles, failedActive) == manifest->activeTag;
        const bool tornRecoveryManifestCommit =
            canonicalGeneration(manifest->recovery) &&
            physicalActive == manifest->recovery &&
            physicalRecovery.isEmpty() &&
            !failedStillAuthenticated &&
            readGeneration(generationGroup(manifest->recovery),
                           recoveryProfiles, recoveryActive) &&
            generationTag(recoveryProfiles, recoveryActive) == manifest->recoveryTag;
        if (tornRecoveryManifestCommit) {
            const QByteArray recoveryTag = generationTag(recoveryProfiles, recoveryActive);
            const auto recoveredManifest = encodeManifest(
                {SchemaVersion, manifest->recovery, QString(), recoveryTag, {}},
                authentication_, false);
            if (!recoveredManifest)
                return RecoveryResult::Unavailable;
            settings_.setValue(QString::fromLatin1(ManifestKey), *recoveredManifest);
            if (!sync()) {
                markIndeterminate();
                return RecoveryResult::IndeterminateState;
            }
            if (load() != LoadStatus::Loaded) {
                markIndeterminate();
                return RecoveryResult::IndeterminateState;
            }
            saveFailed_ = false;
            return RecoveryResult::Recovered;
        }

        // persist() durably publishes the new physical pointers before its
        // authenticated manifest. A process death at that boundary leaves the
        // previous manifest authoritative and the exact shape
        // new.active / recovery=manifest.active. Roll back only that shape;
        // arbitrary pointer edits still fail closed.
        QList<EnvironmentProfile> committedProfiles;
        EnvironmentProfile::Kind committedActive = EnvironmentProfile::Kind::Home;
        QList<EnvironmentProfile> pendingProfiles;
        EnvironmentProfile::Kind pendingActive = EnvironmentProfile::Kind::Home;
        const bool tornBeforeManifestCommit =
            physicalSchema == manifest->schema &&
            canonicalGeneration(manifest->active) &&
            canonicalGeneration(physicalActive) &&
            physicalActive != manifest->active &&
            physicalRecovery == manifest->active &&
            readGeneration(generationGroup(manifest->active),
                           committedProfiles, committedActive) &&
            generationTag(committedProfiles, committedActive) == manifest->activeTag &&
            readGeneration(generationGroup(physicalActive), pendingProfiles, pendingActive);
        if (!tornBeforeManifestCommit)
            return RecoveryResult::Unavailable;

        settings_.setValue(QString::fromLatin1(ActiveGenerationKey), manifest->active);
        settings_.setValue(QString::fromLatin1(RecoveryGenerationKey), manifest->recovery);
        if (!sync()) {
            markIndeterminate();
            return RecoveryResult::IndeterminateState;
        }
        if (load() != LoadStatus::Loaded) {
            markIndeterminate();
            return RecoveryResult::IndeterminateState;
        }
        saveFailed_ = false;
        return RecoveryResult::NotNeeded;
    }

    const QString failedGeneration = manifest->active;
    const QString candidateGeneration = manifest->recovery;
    if (!canonicalGeneration(failedGeneration) ||
        !canonicalGeneration(candidateGeneration) ||
        candidateGeneration == failedGeneration) {
        return RecoveryResult::Unavailable;
    }

    settings_.beginGroup(QString::fromLatin1(GenerationsGroup));
    const QStringList generations = settings_.childGroups();
    const QStringList generationKeys = settings_.childKeys();
    settings_.endGroup();
    if (!generationKeys.isEmpty() || !generations.contains(failedGeneration) ||
        !generations.contains(candidateGeneration) ||
        std::any_of(generations.cbegin(), generations.cend(),
                    [](const QString& value) { return !canonicalGeneration(value); })) {
        return RecoveryResult::Unavailable;
    }

    QList<EnvironmentProfile> failedProfiles;
    EnvironmentProfile::Kind failedActive = EnvironmentProfile::Kind::Home;
    if (readGeneration(generationGroup(failedGeneration), failedProfiles, failedActive) &&
        generationTag(failedProfiles, failedActive) == manifest->activeTag) {
        return RecoveryResult::Unavailable;
    }

    int candidateSchema = 0;
    if (strictInt(settings_,
                  generationGroup(candidateGeneration) + QStringLiteral("/schemaVersion"),
                  candidateSchema) &&
        candidateSchema > SchemaVersion) {
        return RecoveryResult::ReadOnlyFutureSchema;
    }

    QList<EnvironmentProfile> candidateProfiles;
    EnvironmentProfile::Kind candidateActive = EnvironmentProfile::Kind::Home;
    if (!readGeneration(generationGroup(candidateGeneration),
                        candidateProfiles, candidateActive)) {
        return RecoveryResult::Unavailable;
    }
    const QByteArray candidateTag = generationTag(candidateProfiles, candidateActive);
    if (candidateTag != manifest->recoveryTag)
        return RecoveryResult::Unavailable;

    const bool lineageUnchanged = hasManifest
        ? settings_.value(QString::fromLatin1(ManifestKey)) == originalManifestValue
        : settings_.value(QString::fromLatin1(ActiveGenerationKey)).toString() ==
              failedGeneration &&
          settings_.value(QString::fromLatin1(RecoveryGenerationKey)).toString() ==
              candidateGeneration;
    if (!lineageUnchanged)
        return RecoveryResult::ConcurrentModification;

    const auto restoreLineage = [&]() -> RecoveryResult {
        settings_.setValue(QString::fromLatin1(ActiveGenerationKey), failedGeneration);
        settings_.setValue(QString::fromLatin1(RecoveryGenerationKey), candidateGeneration);
        if (hasManifest)
            settings_.setValue(QString::fromLatin1(ManifestKey), originalManifestValue);
        else
            settings_.remove(QString::fromLatin1(ManifestKey));
        if (sync()) return RecoveryResult::SettingsError;
        markIndeterminate();
        return RecoveryResult::IndeterminateState;
    };

    settings_.setValue(QString::fromLatin1(ActiveGenerationKey), candidateGeneration);
    settings_.setValue(QString::fromLatin1(RecoveryGenerationKey), QString());
    if (!sync()) return restoreLineage();
    const auto promotedManifest = encodeManifest(
        {SchemaVersion, candidateGeneration, QString(), candidateTag, {}},
        authentication_, false);
    if (!promotedManifest) return restoreLineage();
    settings_.setValue(QString::fromLatin1(ManifestKey), *promotedManifest);
    if (!sync()) return restoreLineage();

    if (load() == LoadStatus::Loaded && generation_ == candidateGeneration &&
        activeKind_ == candidateActive && sameProfiles(profiles_, candidateProfiles)) {
        return RecoveryResult::Recovered;
    }

    return restoreLineage();
}

bool EnvironmentProfileStore::writeGeneration(const QString& group,
                                               const QList<EnvironmentProfile>& profiles,
                                               EnvironmentProfile::Kind activeKind)
{
    settings_.remove(group);
    settings_.setValue(group + QStringLiteral("/schemaVersion"), SchemaVersion);
    settings_.setValue(group + QStringLiteral("/activeKind"), EnvironmentProfile::key(activeKind));
    settings_.beginWriteArray(group + QStringLiteral("/profiles"));
    for (int i = 0; i < profiles.size(); ++i) {
        settings_.setArrayIndex(i);
        const auto& profile = profiles[i];
        settings_.setValue(QStringLiteral("kind"), EnvironmentProfile::key(profile.kind));
        settings_.setValue(QStringLiteral("columns"), profile.layout.columns);
        settings_.setValue(QStringLiteral("rows"), profile.layout.rows);
        settings_.setValue(QStringLiteral("gridTechnicalNames"), profile.layout.gridTechnicalNames);
        settings_.beginWriteArray(QStringLiteral("devices"));
        for (int j = 0; j < profile.devices.size(); ++j) {
            settings_.setArrayIndex(j);
            settings_.setValue(QStringLiteral("uuid"), profile.devices[j].uuid.toString(QUuid::WithoutBraces));
            settings_.setValue(QStringLiteral("technicalName"), profile.devices[j].technicalName);
            settings_.setValue(QStringLiteral("requestedResources"),
                               static_cast<qlonglong>(profile.devices[j].requestedResources));
        }
        settings_.endArray();
    }
    settings_.endArray();
    for (int i = 0; i < profiles.size(); ++i) {
        const QString extension = group + QStringLiteral("/profiles/") + QString::number(i + 1) + QStringLiteral("/layout/extension");
        if (!profiles[i].layout.extension.saveMetadata(settings_, extension, false)) return false;
    }
    return settings_.status() == QSettings::NoError;
}

bool EnvironmentProfileStore::readGeneration(const QString& group,
                                              QList<EnvironmentProfile>& profiles,
                                              EnvironmentProfile::Kind& activeKind) const
{
    profiles.clear();
    int schema = 0, count = 0;
    if (!directShape(settings_, group, {QStringLiteral("activeKind"), QStringLiteral("schemaVersion")}, {QStringLiteral("profiles")}) ||
        !strictInt(settings_, group + QStringLiteral("/schemaVersion"), schema) ||
        schema < OldestSupportedSchemaVersion || schema > SchemaVersion ||
        !hasType(settings_, group + QStringLiteral("/activeKind"), QMetaType::QString) ||
        !strictInt(settings_, group + QStringLiteral("/profiles/size"), count) || count != 4 ||
        !directShape(settings_, group + QStringLiteral("/profiles"), {QStringLiteral("size")}, indexes(count))) return false;
    const auto parsedActive = EnvironmentProfile::fromKey(settings_.value(group + QStringLiteral("/activeKind")).toString());
    if (!parsedActive) return false;
    activeKind = *parsedActive;

    for (int i = 1; i <= count; ++i) {
        const QString profileGroup = group + QStringLiteral("/profiles/") + QString::number(i);
        if (!directShape(settings_, profileGroup,
                         {QStringLiteral("columns"), QStringLiteral("gridTechnicalNames"), QStringLiteral("kind"), QStringLiteral("rows")},
                         {QStringLiteral("devices"), QStringLiteral("layout")}) ||
            !directShape(settings_, profileGroup + QStringLiteral("/layout"), {}, {QStringLiteral("extension")}) ||
            !hasType(settings_, profileGroup + QStringLiteral("/kind"), QMetaType::QString) ||
            !hasType(settings_, profileGroup + QStringLiteral("/gridTechnicalNames"), QMetaType::QStringList)) return false;
        const auto kind = EnvironmentProfile::fromKey(settings_.value(profileGroup + QStringLiteral("/kind")).toString());
        int columns = 0, rows = 0, deviceCount = 0;
        if (!kind || !strictInt(settings_, profileGroup + QStringLiteral("/columns"), columns) ||
            !strictInt(settings_, profileGroup + QStringLiteral("/rows"), rows) ||
            !strictInt(settings_, profileGroup + QStringLiteral("/devices/size"), deviceCount) ||
            deviceCount < 0 || deviceCount > ScreenLayout::MaxDevices ||
            !directShape(settings_, profileGroup + QStringLiteral("/devices"), {QStringLiteral("size")}, indexes(deviceCount))) return false;
        EnvironmentProfile result; result.kind = *kind; result.layout.columns = columns; result.layout.rows = rows;
        result.layout.gridTechnicalNames = settings_.value(profileGroup + QStringLiteral("/gridTechnicalNames")).toStringList();
        for (int j = 1; j <= deviceCount; ++j) {
            const QString device = profileGroup + QStringLiteral("/devices/") + QString::number(j);
            quint32 resources = 0;
            if (!directShape(settings_, device,
                             {QStringLiteral("requestedResources"), QStringLiteral("technicalName"), QStringLiteral("uuid")}, {}) ||
                !hasType(settings_, device + QStringLiteral("/uuid"), QMetaType::QString) ||
                !canonicalGeneration(settings_.value(device + QStringLiteral("/uuid")).toString()) ||
                !hasType(settings_, device + QStringLiteral("/technicalName"), QMetaType::QString) ||
                !strictUnsigned(settings_, device + QStringLiteral("/requestedResources"), resources) ||
                (resources & ~EnvironmentProfile::ManagedResources) != 0) return false;
            result.devices.append({QUuid(settings_.value(device + QStringLiteral("/uuid")).toString()),
                                   settings_.value(device + QStringLiteral("/technicalName")).toString(), resources});
        }
        const QString extension = profileGroup + QStringLiteral("/layout/extension");
        if (!strictLayoutShape(settings_, extension)) return false;
        const auto layout = ScreenLayout::loadMetadata(settings_, extension);
        if (!layout) return false;
        result.layout.extension = *layout;
        if (!result.isValid()) return false;
        if (std::any_of(profiles.cbegin(), profiles.cend(), [&](const EnvironmentProfile& existing) { return existing.kind == result.kind; }))
            return false;
        profiles.append(std::move(result));
    }
    const auto canonicalKinds = EnvironmentProfile::canonicalKinds();
    if (!std::all_of(canonicalKinds.cbegin(), canonicalKinds.cend(), [&](EnvironmentProfile::Kind kind) {
            return std::any_of(profiles.cbegin(), profiles.cend(), [kind](const EnvironmentProfile& value) { return value.kind == kind; });
        })) return false;
    return std::any_of(profiles.cbegin(), profiles.cend(), [activeKind](const EnvironmentProfile& value) { return value.kind == activeKind; });
}

void EnvironmentProfileStore::markIndeterminate()
{
    profiles_.clear();
    activeKind_.reset();
    generation_.reset();
    loadStatus_ = LoadStatus::SettingsError;
    saveFailed_ = true;
}

EnvironmentProfileStore::SaveResult EnvironmentProfileStore::persist(
    const QList<EnvironmentProfile>& profiles, EnvironmentProfile::Kind activeKind,
    const std::optional<QString>& recoveryGenerationOverride)
{
    if (!validProfileCollection(profiles, activeKind))
        return SaveResult::InvalidProfile;

    const bool hadManifest = settings_.contains(QString::fromLatin1(ManifestKey));
    const QVariant previousManifestValue = settings_.value(QString::fromLatin1(ManifestKey));
    const auto previousManifest = hadManifest
        ? decodeManifest(previousManifestValue, authentication_) : std::optional<RootManifest>{};
    if (hadManifest && !previousManifest)
        return SaveResult::SettingsError;
    const QString previous = generation_.value_or(
        settings_.value(QString::fromLatin1(ActiveGenerationKey)).toString());
    int previousSchema = previousManifest ? previousManifest->schema : 0;
    if (!previousManifest) {
        strictInt(settings_, QString::fromLatin1(RootGroup) + QStringLiteral("/schemaVersion"),
                  previousSchema);
    }
    const QString previousRecovery = previousManifest
        ? previousManifest->recovery
        : previousSchema == SchemaVersion
            ? settings_.value(QString::fromLatin1(RecoveryGenerationKey)).toString()
            : QString();
    QString recovery = previous;
    QByteArray recoveryTag;
    if (recoveryGenerationOverride) {
        QList<EnvironmentProfile> recoveryProfiles;
        EnvironmentProfile::Kind recoveryActive = EnvironmentProfile::Kind::Home;
        if (!canonicalGeneration(*recoveryGenerationOverride) ||
            !readGeneration(generationGroup(*recoveryGenerationOverride),
                            recoveryProfiles, recoveryActive)) {
            return SaveResult::InvalidProfile;
        }
        recovery = *recoveryGenerationOverride;
        recoveryTag = generationTag(recoveryProfiles, recoveryActive);
    }
    else if (!recovery.isEmpty()) {
        if (previousManifest && previousManifest->active == recovery) {
            recoveryTag = previousManifest->activeTag;
        }
        else {
            QList<EnvironmentProfile> recoveryProfiles;
            EnvironmentProfile::Kind recoveryActive = EnvironmentProfile::Kind::Home;
            if (!readGeneration(generationGroup(recovery),
                                recoveryProfiles, recoveryActive)) {
                return SaveResult::SettingsError;
            }
            recoveryTag = generationTag(recoveryProfiles, recoveryActive);
        }
    }
    const QString generation = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const QString group = generationGroup(generation);
    if (!writeGeneration(group, profiles, activeKind) || !sync()) {
        settings_.remove(group);
        if (sync()) return SaveResult::SettingsError;
        markIndeterminate();
        return SaveResult::IndeterminateState;
    }

    QList<EnvironmentProfile> verified; EnvironmentProfile::Kind verifiedActive = EnvironmentProfile::Kind::Home;
    if (!readGeneration(group, verified, verifiedActive) || verifiedActive != activeKind || !sameProfiles(verified, profiles)) {
        settings_.remove(group);
        if (sync()) return SaveResult::SettingsError;
        markIndeterminate();
        return SaveResult::IndeterminateState;
    }
    const QByteArray activeTag = generationTag(verified, verifiedActive);

    const auto restoreRoot = [&]() -> SaveResult {
        if (previous.isEmpty()) {
            settings_.remove(QString::fromLatin1(ActiveGenerationKey));
            settings_.remove(QString::fromLatin1(RecoveryGenerationKey));
            settings_.remove(QString::fromLatin1(RootGroup) + QStringLiteral("/schemaVersion"));
        } else {
            settings_.setValue(QString::fromLatin1(ActiveGenerationKey), previous);
            settings_.setValue(QString::fromLatin1(RootGroup) + QStringLiteral("/schemaVersion"),
                               previousSchema);
            if (previousSchema == SchemaVersion)
                settings_.setValue(QString::fromLatin1(RecoveryGenerationKey), previousRecovery);
            else
                settings_.remove(QString::fromLatin1(RecoveryGenerationKey));
        }
        if (hadManifest)
            settings_.setValue(QString::fromLatin1(ManifestKey), previousManifestValue);
        else
            settings_.remove(QString::fromLatin1(ManifestKey));
        settings_.remove(group);
        if (sync()) return SaveResult::SettingsError;
        markIndeterminate();
        return SaveResult::IndeterminateState;
    };

    settings_.setValue(QString::fromLatin1(RootGroup) + QStringLiteral("/schemaVersion"), SchemaVersion);
    settings_.setValue(QString::fromLatin1(ActiveGenerationKey), generation);
    settings_.setValue(QString::fromLatin1(RecoveryGenerationKey), recovery);
    if (!sync()) return restoreRoot();

    const auto manifest = encodeManifest(
        {SchemaVersion, generation, recovery, activeTag, recoveryTag},
        authentication_, !hadManifest);
    if (!manifest) return restoreRoot();
    settings_.setValue(QString::fromLatin1(ManifestKey), *manifest);
    if (!sync()) return restoreRoot();

    profiles_ = profiles; activeKind_ = activeKind; generation_ = generation;
    loadStatus_ = LoadStatus::Loaded; saveFailed_ = false;

    // The promotion callback is the durability boundary. With the QLockFile
    // still held, revalidate the pointer in this same QSettings object and
    // retain the current and explicitly selected known-good recovery generation.
    if (settings_.value(QString::fromLatin1(ActiveGenerationKey)).toString() != generation)
        return SaveResult::Success;
    settings_.beginGroup(QString::fromLatin1(GenerationsGroup));
    const QStringList generations = settings_.childGroups(); settings_.endGroup();
    for (const QString& old : generations) {
        if (old == generation || old == recovery) continue;
        if (settings_.value(QString::fromLatin1(ActiveGenerationKey)).toString() != generation) break;
        settings_.remove(generationGroup(old));
        if (!sync()) break;
    }
    return SaveResult::Success;
}
