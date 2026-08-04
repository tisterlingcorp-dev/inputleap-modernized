/* InputLeap -- real AppConfig/environment-profile target for transactional imports. */
#include "ConfigurationAppTarget.h"
#include "ConfigurationTransactionLock.h"
#include "RecoveryArtifactAuthenticator.h"

#include "AppConfig.h"
#include "ConfigurationPublicSnapshot.h"
#include "EnvironmentProfileController.h"

#include <QJsonDocument>
#include <QJsonParseError>
#include <QCryptographicHash>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLockFile>
#include <QSettings>
#include <QScopeGuard>
#include <QUuid>

#if defined(Q_OS_WIN)
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include <openssl/crypto.h>

#include <utility>

namespace {
constexpr auto JournalRoot = "configurationImportJournal";
constexpr auto OldCapsuleAccount = "InputLeap/import-recovery/old";
constexpr auto NewCapsuleAccount = "InputLeap/import-recovery/new";
constexpr auto CommitMarkerAccount = "InputLeap/import-recovery/commit";
constexpr auto PrepareMarkerAccount = "InputLeap/import-recovery/prepare";
constexpr auto AuthenticationKeyAccount = "InputLeap/import-recovery/auth-key";
constexpr qsizetype MaxPublicSnapshotBytes = 1024 * 1024;

QString importJournalLockPath()
{
    return QDir(QDir::tempPath()).filePath(
        QStringLiteral("inputleap-import-journal.lock"));
}

bool durableSync(QSettings& settings)
{
    settings.sync();
    if (settings.status() != QSettings::NoError) return false;
#if defined(Q_OS_WIN)
    if (settings.format() == QSettings::NativeFormat) {
        QString path = settings.fileName();
        path.replace(QLatin1Char('/'), QLatin1Char('\\'));
        while (path.startsWith(QLatin1Char('\\'))) path.remove(0, 1);
        constexpr auto Prefix = "HKEY_CURRENT_USER\\";
        const QString prefix = QString::fromLatin1(Prefix);
        if (!path.startsWith(prefix, Qt::CaseInsensitive))
            return false;
        const QString subkey = path.mid(prefix.size());
        HKEY key = nullptr;
        const LONG opened = RegOpenKeyExW(
            HKEY_CURRENT_USER, reinterpret_cast<LPCWSTR>(subkey.utf16()),
            0, KEY_READ, &key);
        if (opened != ERROR_SUCCESS) return false;
        const LONG flushed = RegFlushKey(key);
        RegCloseKey(key);
        return flushed == ERROR_SUCCESS;
    }
    const QString path = settings.fileName();
    HANDLE file = CreateFileW(
        reinterpret_cast<LPCWSTR>(path.utf16()), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    const bool flushed = FlushFileBuffers(file) != FALSE;
    CloseHandle(file);
    return flushed;
#else
    QFile file(settings.fileName());
    if (!file.open(QIODevice::ReadOnly)) return false;
    if (::fsync(file.handle()) != 0) return false;
    const QByteArray directory = QFile::encodeName(
        QFileInfo(settings.fileName()).absolutePath());
#if defined(O_DIRECTORY)
    const int directoryHandle = ::open(directory.constData(), O_RDONLY | O_DIRECTORY);
#else
    const int directoryHandle = ::open(directory.constData(), O_RDONLY);
#endif
    if (directoryHandle < 0) return false;
    const bool directoryDurable = ::fsync(directoryHandle) == 0;
    ::close(directoryHandle);
    return directoryDurable;
#endif
}

bool sameSnapshot(const ConfigurationPublicSnapshot& first,
                  const ConfigurationPublicSnapshot& second)
{
    return ConfigurationPublicSnapshotCodec::encode(first) ==
           ConfigurationPublicSnapshotCodec::encode(second);
}

bool fieldsBelongToTransaction(const QJsonObject& current,
                               const QJsonObject& original,
                               const QJsonObject& candidate)
{
    if (current.keys() != original.keys() || current.keys() != candidate.keys())
        return false;
    for (auto it = current.constBegin(); it != current.constEnd(); ++it) {
        if (it.value() != original.value(it.key()) &&
            it.value() != candidate.value(it.key()))
            return false;
    }
    return true;
}

bool sameSensitive(const std::optional<SensitiveBytes>& first,
                   const std::optional<SensitiveBytes>& second)
{
    if (first.has_value() != second.has_value()) return false;
    return !first || first->securelyEquals(second->bytes());
}

QByteArray encodePublicSnapshot(const ConfigurationPublicSnapshot& snapshot)
{
    return QJsonDocument(ConfigurationPublicSnapshotCodec::encode(snapshot))
        .toJson(QJsonDocument::Compact);
}

std::optional<ConfigurationPublicSnapshot> decodePublicSnapshot(const QByteArray& encoded)
{
    if (encoded.isEmpty() || encoded.size() > MaxPublicSnapshotBytes)
        return std::nullopt;
    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(encoded, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject())
        return std::nullopt;
    auto decoded = ConfigurationPublicSnapshotCodec::decode(document.object());
    if (decoded.error != ConfigurationPublicSnapshotCodec::Error::None ||
        !decoded.snapshot) {
        return std::nullopt;
    }
    return std::move(decoded.snapshot);
}

QByteArray journalBinding(QByteArrayView authenticationKey,
                          const QString& transactionId,
                          const ConfigurationPublicSnapshot& original,
                          const ConfigurationPublicSnapshot& candidate)
{
    const QByteArray domain = QByteArrayLiteral("inputleap-import-journal-v3");
    const QByteArray id = transactionId.toUtf8();
    const QByteArray originalBytes = encodePublicSnapshot(original);
    const QByteArray candidateBytes = encodePublicSnapshot(candidate);
    return RecoveryArtifactAuthenticator::authenticate(
        authenticationKey, QByteArrayView(domain),
        {QByteArrayView(id), QByteArrayView(originalBytes),
         QByteArrayView(candidateBytes)});
}

enum class CapsuleRole : char { Old = 'O', New = 'N' };

void appendLength(QByteArray& output, quint32 value)
{
    output.append(static_cast<char>((value >> 24) & 0xff));
    output.append(static_cast<char>((value >> 16) & 0xff));
    output.append(static_cast<char>((value >> 8) & 0xff));
    output.append(static_cast<char>(value & 0xff));
}

bool readLength(QByteArrayView input, qsizetype& offset, quint32& value)
{
    if (offset < 0 || input.size() - offset < 4) return false;
    const auto* bytes = reinterpret_cast<const unsigned char*>(input.data() + offset);
    value = (quint32(bytes[0]) << 24) | (quint32(bytes[1]) << 16) |
            (quint32(bytes[2]) << 8) | quint32(bytes[3]);
    offset += 4;
    return value <= MaxPublicSnapshotBytes && input.size() - offset >= value;
}

QByteArray capsuleBinding(QByteArrayView authenticationKey,
                          const QByteArray& commonBinding, CapsuleRole role,
                          const QByteArray& snapshot,
                          const std::optional<SensitiveBytes>& value)
{
    const QByteArray domain = QByteArrayLiteral("inputleap-import-capsule-v4");
    const char roleByte = static_cast<char>(role);
    const char state = value ? '\1' : '\0';
    QVector<QByteArrayView> parts{
        QByteArrayView(commonBinding), QByteArrayView(&roleByte, 1),
        QByteArrayView(snapshot), QByteArrayView(&state, 1)};
    if (value) parts.append(value->bytes());
    return RecoveryArtifactAuthenticator::authenticate(
        authenticationKey, QByteArrayView(domain), parts);
}

QByteArray encodeCapsule(QByteArrayView authenticationKey,
                         const QString& transactionId,
                         const QByteArray& commonBinding,
                         CapsuleRole role,
                         const ConfigurationPublicSnapshot& snapshot,
                         const std::optional<SensitiveBytes>& value)
{
    const QByteArray snapshotBytes = encodePublicSnapshot(snapshot);
    const QByteArray digest = capsuleBinding(
        authenticationKey, commonBinding, role, snapshotBytes, value);
    QByteArray encoded = QByteArrayLiteral("ILIMJ4");
    encoded.append(transactionId.toUtf8());
    encoded.append(commonBinding);
    encoded.append(static_cast<char>(role));
    encoded.append(digest);
    appendLength(encoded, static_cast<quint32>(snapshotBytes.size()));
    encoded.append(snapshotBytes);
    encoded.append(value ? '\1' : '\0');
    if (value) {
        const auto bytes = value->bytes();
        encoded.append(bytes.data(), bytes.size());
    }
    return encoded;
}

struct DecodedCapsule
{
    bool valid = false;
    QString transactionId;
    QByteArray commonBinding;
    CapsuleRole role = CapsuleRole::Old;
    std::optional<ConfigurationPublicSnapshot> snapshot;
    std::optional<SensitiveBytes> value;
};

DecodedCapsule decodeCapsule(const SensitiveBytes& encoded,
                             CapsuleRole expectedRole,
                             QByteArrayView authenticationKey)
{
    const auto bytes = encoded.bytes();
    const QByteArray magic = QByteArrayLiteral("ILIMJ4");
    constexpr qsizetype UuidSize = 36;
    const qsizetype digestSize = QCryptographicHash::hashLength(
        QCryptographicHash::Sha256);
    qsizetype offset = magic.size();
    if (bytes.size() < offset + UuidSize + digestSize + 1 + digestSize + 4 + 1 ||
        CRYPTO_memcmp(bytes.data(), magic.constData(),
                      static_cast<size_t>(magic.size())) != 0) return {};
    const QString transactionId = QString::fromUtf8(bytes.data() + offset, UuidSize);
    const QUuid uuid(transactionId);
    if (uuid.isNull() || uuid.toString(QUuid::WithoutBraces) != transactionId)
        return {};
    offset += UuidSize;
    const QByteArray commonBinding(bytes.data() + offset, digestSize);
    offset += digestSize;
    const auto role = static_cast<CapsuleRole>(bytes[offset++]);
    if (role != expectedRole) return {};
    const QByteArray storedDigest(bytes.data() + offset, digestSize);
    offset += digestSize;
    quint32 snapshotSize = 0;
    if (!readLength(bytes, offset, snapshotSize)) return {};
    const QByteArray snapshotBytes(bytes.data() + offset, snapshotSize);
    offset += snapshotSize;
    auto snapshot = decodePublicSnapshot(snapshotBytes);
    if (!snapshot || bytes.size() < offset + 1) return {};
    const char state = bytes[offset];
    std::optional<SensitiveBytes> value;
    if (state == '\0') {
        if (bytes.size() != offset + 1) return {};
    } else if (state == '\1') {
        value.emplace(QByteArray(bytes.data() + offset + 1,
                                 bytes.size() - offset - 1));
    } else {
        return {};
    }
    const QByteArray expectedDigest = capsuleBinding(
        authenticationKey, commonBinding, role, snapshotBytes, value);
    if (storedDigest.size() != expectedDigest.size() ||
        CRYPTO_memcmp(storedDigest.constData(), expectedDigest.constData(),
                      static_cast<size_t>(expectedDigest.size())) != 0) return {};
    return {true, transactionId, commonBinding, role,
            std::move(snapshot), std::move(value)};
}

bool validCapsulePair(const DecodedCapsule& oldCapsule,
                      const DecodedCapsule& newCapsule,
                      QByteArrayView authenticationKey)
{
    if (!oldCapsule.valid || !newCapsule.valid ||
        !oldCapsule.snapshot || !newCapsule.snapshot ||
        oldCapsule.transactionId != newCapsule.transactionId ||
        oldCapsule.commonBinding != newCapsule.commonBinding) {
        return false;
    }
    const QByteArray expected = journalBinding(
        authenticationKey, oldCapsule.transactionId,
        *oldCapsule.snapshot, *newCapsule.snapshot);
    return expected.size() == oldCapsule.commonBinding.size() &&
        CRYPTO_memcmp(expected.constData(), oldCapsule.commonBinding.constData(),
                      static_cast<size_t>(expected.size())) == 0;
}

QByteArray commitMarkerDigest(QByteArrayView authenticationKey,
                              const QString& transactionId,
                              const QByteArray& commonBinding)
{
    const QByteArray domain = QByteArrayLiteral("inputleap-import-commit-v2");
    const QByteArray id = transactionId.toUtf8();
    return RecoveryArtifactAuthenticator::authenticate(
        authenticationKey, QByteArrayView(domain),
        {QByteArrayView(id), QByteArrayView(commonBinding)});
}

QByteArray encodeCommitMarker(QByteArrayView authenticationKey,
                              const QString& transactionId,
                              const QByteArray& commonBinding)
{
    QByteArray encoded = QByteArrayLiteral("ILIMC1");
    encoded.append(transactionId.toUtf8());
    encoded.append(commonBinding);
    encoded.append(commitMarkerDigest(authenticationKey, transactionId, commonBinding));
    return encoded;
}

struct DecodedCommitMarker
{
    bool valid = false;
    QString transactionId;
    QByteArray commonBinding;
};

DecodedCommitMarker decodeCommitMarker(const SensitiveBytes& encoded,
                                       QByteArrayView authenticationKey)
{
    const auto bytes = encoded.bytes();
    const QByteArray magic = QByteArrayLiteral("ILIMC1");
    constexpr qsizetype UuidSize = 36;
    const qsizetype digestSize = QCryptographicHash::hashLength(
        QCryptographicHash::Sha256);
    if (bytes.size() != magic.size() + UuidSize + digestSize + digestSize ||
        CRYPTO_memcmp(bytes.data(), magic.constData(),
                      static_cast<size_t>(magic.size())) != 0) return {};
    qsizetype offset = magic.size();
    const QString transactionId = QString::fromUtf8(bytes.data() + offset, UuidSize);
    const QUuid uuid(transactionId);
    if (uuid.isNull() || uuid.toString(QUuid::WithoutBraces) != transactionId)
        return {};
    offset += UuidSize;
    const QByteArray commonBinding(bytes.data() + offset, digestSize);
    offset += digestSize;
    const QByteArray expected = commitMarkerDigest(
        authenticationKey, transactionId, commonBinding);
    if (CRYPTO_memcmp(bytes.data() + offset, expected.constData(),
                      static_cast<size_t>(expected.size())) != 0) return {};
    return {true, transactionId, commonBinding};
}

QByteArray prepareMarkerDigest(QByteArrayView authenticationKey,
                               const QString& transactionId,
                               const QByteArray& commonBinding)
{
    const QByteArray domain = QByteArrayLiteral("inputleap-import-prepare-v2");
    const QByteArray id = transactionId.toUtf8();
    return RecoveryArtifactAuthenticator::authenticate(
        authenticationKey, QByteArrayView(domain),
        {QByteArrayView(id), QByteArrayView(commonBinding)});
}

QByteArray encodePrepareMarker(QByteArrayView authenticationKey,
                               const QString& transactionId,
                               const QByteArray& commonBinding)
{
    QByteArray encoded = QByteArrayLiteral("ILIMP1");
    encoded.append(transactionId.toUtf8());
    encoded.append(commonBinding);
    encoded.append(prepareMarkerDigest(authenticationKey, transactionId, commonBinding));
    return encoded;
}

DecodedCommitMarker decodePrepareMarker(const SensitiveBytes& encoded,
                                        QByteArrayView authenticationKey)
{
    const auto bytes = encoded.bytes();
    const QByteArray magic = QByteArrayLiteral("ILIMP1");
    constexpr qsizetype UuidSize = 36;
    const qsizetype digestSize = QCryptographicHash::hashLength(
        QCryptographicHash::Sha256);
    if (bytes.size() != magic.size() + UuidSize + digestSize + digestSize ||
        CRYPTO_memcmp(bytes.data(), magic.constData(),
                      static_cast<size_t>(magic.size())) != 0) return {};
    qsizetype offset = magic.size();
    const QString transactionId = QString::fromUtf8(bytes.data() + offset, UuidSize);
    const QUuid uuid(transactionId);
    if (uuid.isNull() || uuid.toString(QUuid::WithoutBraces) != transactionId)
        return {};
    offset += UuidSize;
    const QByteArray commonBinding(bytes.data() + offset, digestSize);
    offset += digestSize;
    const QByteArray expected = prepareMarkerDigest(
        authenticationKey, transactionId, commonBinding);
    if (CRYPTO_memcmp(bytes.data() + offset, expected.constData(),
                      static_cast<size_t>(expected.size())) != 0) return {};
    return {true, transactionId, commonBinding};
}

struct PendingJournal
{
    enum class Status { None, Valid, Invalid } status = Status::None;
    QString transactionId;
    std::optional<ConfigurationPublicSnapshot> original;
    std::optional<ConfigurationPublicSnapshot> candidate;
};

PendingJournal loadJournal(QSettings& settings)
{
    settings.sync();
    if (settings.status() != QSettings::NoError)
        return {PendingJournal::Status::Invalid, {}, {}, {}};
    settings.beginGroup(QString::fromLatin1(JournalRoot));
    const auto keys = settings.childKeys();
    const auto groups = settings.childGroups();
    if (keys.isEmpty() && groups.isEmpty()) {
        settings.endGroup();
        return {};
    }
    const QStringList expected{
        QStringLiteral("candidatePublic"), QStringLiteral("originalPublic"),
        QStringLiteral("schemaVersion"), QStringLiteral("state"),
        QStringLiteral("transactionId")};
    if (!groups.isEmpty() || keys != expected) {
        settings.endGroup();
        return {PendingJournal::Status::Invalid, {}, {}, {}};
    }
    const QVariant schema = settings.value(QStringLiteral("schemaVersion"));
    const QVariant state = settings.value(QStringLiteral("state"));
    const QVariant id = settings.value(QStringLiteral("transactionId"));
    const QVariant original = settings.value(QStringLiteral("originalPublic"));
    const QVariant candidate = settings.value(QStringLiteral("candidatePublic"));
    settings.endGroup();
    if (schema.metaType().id() != QMetaType::Int || schema.toInt() != 2 ||
        state.metaType().id() != QMetaType::QString ||
        state.toString() != QStringLiteral("pending") ||
        id.metaType().id() != QMetaType::QString ||
        original.metaType().id() != QMetaType::QByteArray ||
        candidate.metaType().id() != QMetaType::QByteArray) {
        return {PendingJournal::Status::Invalid, {}, {}, {}};
    }
    const QString transactionId = id.toString();
    const QUuid uuid(transactionId);
    if (uuid.isNull() || uuid.toString(QUuid::WithoutBraces) != transactionId)
        return {PendingJournal::Status::Invalid, {}, {}, {}};
    auto originalSnapshot = decodePublicSnapshot(original.toByteArray());
    auto candidateSnapshot = decodePublicSnapshot(candidate.toByteArray());
    if (!originalSnapshot || !candidateSnapshot)
        return {PendingJournal::Status::Invalid, {}, {}, {}};
    return {PendingJournal::Status::Valid, transactionId,
            std::move(originalSnapshot), std::move(candidateSnapshot)};
}

std::optional<ConfigurationAppTarget::PendingRecoveryResult>
recoverPreparingTransaction(
    QSettings& settings, SecureCredentialStore& credentials,
    QByteArrayView authenticationKey,
    const PendingJournal& journal,
    const SecureCredentialStore::ReadResult& oldStored,
    const SecureCredentialStore::ReadResult& newStored,
    const SecureCredentialStore::ReadResult& commitStored,
    const SecureCredentialStore::ReadResult& prepareStored)
{
    using RecoveryResult = ConfigurationAppTarget::PendingRecoveryResult;
    using ReadStatus = SecureCredentialStore::ReadResult::Status;
    if (prepareStored.status == ReadStatus::NotFound)
        return std::nullopt;
    if (prepareStored.status == ReadStatus::Error ||
        commitStored.status != ReadStatus::NotFound ||
        journal.status == PendingJournal::Status::Invalid) {
        return RecoveryResult::Blocked;
    }
    const auto prepare = decodePrepareMarker(prepareStored.value, authenticationKey);
    if (!prepare.valid) return RecoveryResult::Blocked;

    DecodedCapsule oldDecoded;
    DecodedCapsule newDecoded;
    if (oldStored.status == ReadStatus::Error ||
        newStored.status == ReadStatus::Error) {
        return RecoveryResult::Blocked;
    }
    if (oldStored.status == ReadStatus::Found) {
        oldDecoded = decodeCapsule(
            oldStored.value, CapsuleRole::Old, authenticationKey);
        if (!oldDecoded.valid || oldDecoded.transactionId != prepare.transactionId ||
            oldDecoded.commonBinding != prepare.commonBinding) {
            return RecoveryResult::Blocked;
        }
    }
    if (newStored.status == ReadStatus::Found) {
        newDecoded = decodeCapsule(
            newStored.value, CapsuleRole::New, authenticationKey);
        if (!newDecoded.valid || newDecoded.transactionId != prepare.transactionId ||
            newDecoded.commonBinding != prepare.commonBinding) {
            return RecoveryResult::Blocked;
        }
    }
    if (oldDecoded.valid && newDecoded.valid &&
        !validCapsulePair(oldDecoded, newDecoded, authenticationKey)) {
        return RecoveryResult::Blocked;
    }
    if (journal.status == PendingJournal::Status::Valid) {
        if (!journal.original || !journal.candidate ||
            journal.transactionId != prepare.transactionId ||
            journalBinding(authenticationKey, journal.transactionId, *journal.original,
                           *journal.candidate) != prepare.commonBinding ||
            (oldDecoded.valid && !sameSnapshot(*oldDecoded.snapshot, *journal.original)) ||
            (newDecoded.valid && !sameSnapshot(*newDecoded.snapshot, *journal.candidate))) {
            return RecoveryResult::Blocked;
        }
        settings.remove(QString::fromLatin1(JournalRoot));
        if (!durableSync(settings) ||
            loadJournal(settings).status != PendingJournal::Status::None) {
            return RecoveryResult::Blocked;
        }
    }
    const bool oldRemoved = oldStored.status == ReadStatus::NotFound ||
        credentials.remove(QString::fromLatin1(OldCapsuleAccount));
    const bool newRemoved = newStored.status == ReadStatus::NotFound ||
        credentials.remove(QString::fromLatin1(NewCapsuleAccount));
    const bool prepareRemoved = oldRemoved && newRemoved && credentials.remove(
        QString::fromLatin1(PrepareMarkerAccount));
    return oldRemoved && newRemoved && prepareRemoved
        ? RecoveryResult::NotNeeded : RecoveryResult::Blocked;
}

ConfigurationImportService::MutationResult controllerResult(
    EnvironmentProfileController::Result result)
{
    using ControllerResult = EnvironmentProfileController::Result;
    using MutationResult = ConfigurationImportService::MutationResult;
    if (result == ControllerResult::Success)
        return MutationResult::Success;
    if (result == ControllerResult::ConcurrentModification)
        return MutationResult::ConcurrentModification;
    if (result == ControllerResult::IndeterminateState)
        return MutationResult::Indeterminate;
    return MutationResult::Failed;
}
}

ConfigurationAppTarget::ConfigurationAppTarget(
    AppConfig& appConfig, EnvironmentProfileController& profileController) :
    app_config_(appConfig),
    profile_controller_(profileController)
{
}

ConfigurationAppTarget::~ConfigurationAppTarget() = default;

bool ConfigurationAppTarget::recoverStartupStateBeforePreflight(
    QSettings& settings, SecureCredentialStore credentials)
{
    if (!AppConfig::recoverInterruptedSave(settings, credentials))
        return false;
    return recoverPortablePreferencesBeforePreflight(
               settings, std::move(credentials)) != PendingRecoveryResult::Blocked;
}

ConfigurationAppTarget::PendingRecoveryResult
ConfigurationAppTarget::recoverPortablePreferencesBeforePreflight(
    QSettings& settings, SecureCredentialStore credentials)
{
    QLockFile journalLock(importJournalLockPath());
    if (!journalLock.tryLock(5000)) return PendingRecoveryResult::Blocked;
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return PendingRecoveryResult::Blocked;
    auto journal = loadJournal(settings);
    auto oldStored = credentials.read(QString::fromLatin1(OldCapsuleAccount));
    auto newStored = credentials.read(QString::fromLatin1(NewCapsuleAccount));
    auto markerStored = credentials.read(QString::fromLatin1(CommitMarkerAccount));
    auto prepareStored = credentials.read(QString::fromLatin1(PrepareMarkerAccount));
    const bool oldAbsent = oldStored.status ==
        SecureCredentialStore::ReadResult::Status::NotFound;
    const bool newAbsent = newStored.status ==
        SecureCredentialStore::ReadResult::Status::NotFound;
    const bool markerAbsent = markerStored.status ==
        SecureCredentialStore::ReadResult::Status::NotFound;
    const bool prepareAbsent = prepareStored.status ==
        SecureCredentialStore::ReadResult::Status::NotFound;
    if (journal.status == PendingJournal::Status::None &&
        oldAbsent && newAbsent && markerAbsent && prepareAbsent) {
        return PendingRecoveryResult::NotNeeded;
    }
    const auto authenticationKey = RecoveryArtifactAuthenticator::loadKey(
        credentials, QString::fromLatin1(AuthenticationKeyAccount));
    if (!authenticationKey) return PendingRecoveryResult::Blocked;
    if (const auto prepared = recoverPreparingTransaction(
            settings, credentials, authenticationKey->bytes(), journal,
            oldStored, newStored, markerStored, prepareStored)) {
        return *prepared;
    }
    if (journal.status == PendingJournal::Status::Invalid ||
        markerStored.status == SecureCredentialStore::ReadResult::Status::Error) {
        return PendingRecoveryResult::Blocked;
    }

    std::optional<ConfigurationPublicSnapshot> original;
    std::optional<ConfigurationPublicSnapshot> candidate;
    bool committed = false;
    if (!markerAbsent) {
        const auto marker = decodeCommitMarker(
            markerStored.value, authenticationKey->bytes());
        if (!marker.valid) return PendingRecoveryResult::Blocked;
        committed = true;
        if (journal.status == PendingJournal::Status::Valid) {
            if (!journal.original || !journal.candidate ||
                marker.transactionId != journal.transactionId ||
                marker.commonBinding != journalBinding(
                    authenticationKey->bytes(), journal.transactionId,
                    *journal.original, *journal.candidate)) {
                return PendingRecoveryResult::Blocked;
            }
            original = *journal.original;
            candidate = *journal.candidate;
        } else if (!oldAbsent && !newAbsent && oldStored && newStored) {
            auto oldDecoded = decodeCapsule(oldStored.value, CapsuleRole::Old,
                                      authenticationKey->bytes());
            auto newDecoded = decodeCapsule(newStored.value, CapsuleRole::New,
                                      authenticationKey->bytes());
            if (!validCapsulePair(oldDecoded, newDecoded,
                                  authenticationKey->bytes()) ||
                marker.transactionId != oldDecoded.transactionId ||
                marker.commonBinding != oldDecoded.commonBinding) {
                return PendingRecoveryResult::Blocked;
            }
            original = *oldDecoded.snapshot;
            candidate = *newDecoded.snapshot;
        }
    } else {
        if (!oldStored || !newStored) return PendingRecoveryResult::Blocked;
        auto oldDecoded = decodeCapsule(oldStored.value, CapsuleRole::Old,
                                      authenticationKey->bytes());
        auto newDecoded = decodeCapsule(newStored.value, CapsuleRole::New,
                                      authenticationKey->bytes());
        if (!validCapsulePair(oldDecoded, newDecoded,
                              authenticationKey->bytes()))
            return PendingRecoveryResult::Blocked;
        if (journal.status == PendingJournal::Status::None) {
            journal.status = PendingJournal::Status::Valid;
            journal.transactionId = oldDecoded.transactionId;
            journal.original = *oldDecoded.snapshot;
            journal.candidate = *newDecoded.snapshot;
        } else if (!journal.original || !journal.candidate ||
                   journal.transactionId != oldDecoded.transactionId ||
                   !sameSnapshot(*journal.original, *oldDecoded.snapshot) ||
                   !sameSnapshot(*journal.candidate, *newDecoded.snapshot)) {
            return PendingRecoveryResult::Blocked;
        }
        original = *journal.original;
        candidate = *journal.candidate;
    }

    if (!committed && original && candidate) {
        const QJsonObject currentPreferences{
            {QStringLiteral("port"), settings.value(QStringLiteral("port"), 24800).toInt()},
            {QStringLiteral("logLevel"), settings.value(QStringLiteral("logLevel"), 3).toInt()},
            {QStringLiteral("language"), settings.value(
                 QStringLiteral("language"), QStringLiteral("pt-BR")).toString()},
            {QStringLiteral("cryptoEnabled"), settings.value(
                 QStringLiteral("cryptoEnabled"), true).toBool()},
            {QStringLiteral("requireClientCertificate"), settings.value(
                 QStringLiteral("requireClientCertificate"), false).toBool()},
            {QStringLiteral("autoHide"), settings.value(
                 QStringLiteral("autoHide"), false).toBool()},
            {QStringLiteral("autoStart"), settings.value(
                 QStringLiteral("autoStart"), false).toBool()},
            {QStringLiteral("minimizeToTray"), settings.value(
                 QStringLiteral("minimizeToTray"), false).toBool()},
        };
        const QJsonObject originalPreferences =
            ConfigurationPortablePreferencesCodec::encode(original->preferences);
        const QJsonObject candidatePreferences =
            ConfigurationPortablePreferencesCodec::encode(candidate->preferences);
        if (!fieldsBelongToTransaction(
                currentPreferences, originalPreferences, candidatePreferences)) {
            return PendingRecoveryResult::Blocked;
        }
        const auto& selected = original->preferences;
        settings.setValue(QStringLiteral("port"), selected.port());
        settings.setValue(QStringLiteral("logLevel"), selected.logLevel());
        settings.setValue(QStringLiteral("language"), selected.language());
        settings.setValue(QStringLiteral("cryptoEnabled"), selected.cryptoEnabled());
        settings.setValue(QStringLiteral("requireClientCertificate"),
                          selected.requireClientCertificate());
        settings.setValue(QStringLiteral("autoHide"), selected.autoHide());
        settings.setValue(QStringLiteral("autoStart"), selected.autoStart());
        settings.setValue(QStringLiteral("minimizeToTray"), selected.minimizeToTray());
        if (!durableSync(settings)) return PendingRecoveryResult::Blocked;
    }
    if (!committed) return PendingRecoveryResult::Recovered;

    if (journal.status == PendingJournal::Status::Valid) {
        settings.remove(QString::fromLatin1(JournalRoot));
        if (!durableSync(settings) ||
            loadJournal(settings).status != PendingJournal::Status::None) {
            return PendingRecoveryResult::Blocked;
        }
    }
    const bool oldRemoved = credentials.remove(QString::fromLatin1(OldCapsuleAccount));
    const bool newRemoved = credentials.remove(QString::fromLatin1(NewCapsuleAccount));
    const bool markerRemoved = oldRemoved && newRemoved &&
        credentials.remove(QString::fromLatin1(CommitMarkerAccount));
    return oldRemoved && newRemoved && markerRemoved
        ? PendingRecoveryResult::NotNeeded : PendingRecoveryResult::Blocked;
}

std::optional<ConfigurationPublicSnapshot> ConfigurationAppTarget::snapshot() const
{
    QSettings& settings = app_config_.settings();
    settings.sync();
    if (settings.status() != QSettings::NoError)
        return std::nullopt;
    auto preferences = ConfigurationPortablePreferences::create(
        settings.value(QStringLiteral("port"), 24800).toInt(),
        settings.value(QStringLiteral("logLevel"), 3).toInt(),
        settings.value(QStringLiteral("language"), QStringLiteral("pt-BR")).toString(),
        settings.value(QStringLiteral("cryptoEnabled"), true).toBool(),
        settings.value(QStringLiteral("requireClientCertificate"), false).toBool(),
        settings.value(QStringLiteral("autoHide"), false).toBool(),
        settings.value(QStringLiteral("autoStart"), false).toBool(),
        settings.value(QStringLiteral("minimizeToTray"), false).toBool());
    const auto profiles = profile_controller_.collectionSnapshot();
    if (!preferences || !profiles)
        return std::nullopt;

    ConfigurationPublicSnapshot result;
    result.preferences = std::move(*preferences);
    result.environmentProfiles.profiles = profiles->profiles;
    result.environmentProfiles.activeKind = profiles->activeKind;
    return result;
}

ConfigurationImportService::Target ConfigurationAppTarget::target()
{
    return {
        [this] { return snapshot(); },
        [this] { return readPairingCode(); },
        [this](const ConfigurationPublicSnapshot& candidate,
               const ConfigurationPublicSnapshot& expected) {
            return compareAndApply(candidate, expected);
        },
        [this](const std::optional<SensitiveBytes>& pairingCode,
               const std::optional<SensitiveBytes>& expected) {
            return writePairingCode(pairingCode, expected);
        },
        [this](const ConfigurationPublicSnapshot& original,
               const ConfigurationPublicSnapshot& candidate,
               const std::optional<SensitiveBytes>& oldPairingCode,
               const std::optional<SensitiveBytes>& newPairingCode) {
            return beginPending(original, candidate, oldPairingCode, newPairingCode);
        },
        [this] {
            return commitPending();
        },
        [this] {
            return abortPending();
        }};
}

void ConfigurationAppTarget::assignPreferencesToCache(
    const ConfigurationPortablePreferences& preferences)
{
    app_config_.setPort(preferences.port());
    app_config_.setLogLevel(preferences.logLevel());
    app_config_.setLanguage(preferences.language());
    app_config_.setCryptoEnabled(preferences.cryptoEnabled());
    app_config_.setRequireClientCertificate(preferences.requireClientCertificate());
    app_config_.setAutoHide(preferences.autoHide());
    app_config_.setAutoStart(preferences.autoStart());
    app_config_.setMinimizeToTray(preferences.minimizeToTray());
}

ConfigurationImportService::MutationResult ConfigurationAppTarget::assignPreferences(
    const ConfigurationPortablePreferences& preferences,
    const ConfigurationPortablePreferences& expected)
{
    using MutationResult = ConfigurationImportService::MutationResult;
    assignPreferencesToCache(preferences);
    const auto result = app_config_.savePortableSettingsIfUnchanged(expected);
    if (result == AppConfig::PortableSaveResult::Success)
        return MutationResult::Success;
    if (result == AppConfig::PortableSaveResult::ConcurrentModification)
        return MutationResult::ConcurrentModification;
    return MutationResult::Failed;
}

ConfigurationImportService::MutationResult ConfigurationAppTarget::compareAndApply(
    const ConfigurationPublicSnapshot& candidate,
    const ConfigurationPublicSnapshot& expected)
{
    using MutationResult = ConfigurationImportService::MutationResult;
    const auto current = snapshot();
    if (!current)
        return MutationResult::Indeterminate;
    if (!sameSnapshot(*current, expected))
        return MutationResult::ConcurrentModification;

    const auto profileResult = profile_controller_.replaceAll(
        candidate.environmentProfiles.profiles,
        candidate.environmentProfiles.activeKind);
    const MutationResult mapped = controllerResult(profileResult);
    if (mapped != MutationResult::Success)
        return mapped;

    const ConfigurationPortablePreferences previousPreferences = current->preferences;
    const MutationResult preferencesResult = assignPreferences(
        candidate.preferences, previousPreferences);
    if (preferencesResult == MutationResult::Success) {
        const auto journal = loadJournal(app_config_.settings());
        if (journal.status == PendingJournal::Status::Valid && journal.candidate)
            pending_candidate_applied_ = sameSnapshot(candidate, *journal.candidate);
        return MutationResult::Success;
    }

    app_config_.loadSettings();
    const MutationResult profilesRestored = controllerResult(
        profile_controller_.replaceAll(current->environmentProfiles.profiles,
                                       current->environmentProfiles.activeKind));
    return profilesRestored == MutationResult::Success
        ? preferencesResult : MutationResult::Indeterminate;
}

ConfigurationImportService::SensitiveReadResult
ConfigurationAppTarget::readPairingCode() const
{
    if (!app_config_.sensitiveSettingsAvailable())
        return {false, std::nullopt};
    auto stored = app_config_.m_CredentialStore.read(
        QStringLiteral("InputLeap/file-transfer-pairing-code"));
    if (stored.status == SecureCredentialStore::ReadResult::Status::Error)
        return {false, std::nullopt};
    if (!stored)
        return {true, std::nullopt};
    return {true, SensitiveBytes(std::move(stored.value))};
}

ConfigurationImportService::MutationResult ConfigurationAppTarget::writePairingCode(
    const std::optional<SensitiveBytes>& pairingCode,
    const std::optional<SensitiveBytes>& expected)
{
    using MutationResult = ConfigurationImportService::MutationResult;
    if (!app_config_.sensitiveSettingsAvailable())
        return MutationResult::Failed;

    std::optional<QByteArrayView> expectedView;
    if (expected)
        expectedView = expected->bytes();
    std::optional<QByteArrayView> candidateView;
    if (pairingCode)
        candidateView = pairingCode->bytes();
    const auto result = app_config_.m_CredentialStore.compareAndSwap(
        QStringLiteral("InputLeap/file-transfer-pairing-code"),
        expectedView, candidateView);
    if (result == SecureCredentialStore::CompareAndSwapResult::Mismatch)
        return MutationResult::ConcurrentModification;
    if (result == SecureCredentialStore::CompareAndSwapResult::Indeterminate)
        return MutationResult::Indeterminate;
    if (result != SecureCredentialStore::CompareAndSwapResult::Success)
        return MutationResult::Failed;

    if (!app_config_.m_FileTransferPairingCode.isEmpty())
        OPENSSL_cleanse(app_config_.m_FileTransferPairingCode.data(),
                        static_cast<size_t>(app_config_.m_FileTransferPairingCode.size() * sizeof(QChar)));
    app_config_.m_FileTransferPairingCode = pairingCode
        ? QString::fromUtf8(pairingCode->bytes()) : QString();
    app_config_.m_FileTransferPairingCode.detach();
    if (pairingCode) {
        const QByteArrayView bytes = pairingCode->bytes();
        app_config_.m_LoadedPairingSecret.emplace(
            QByteArray(bytes.data(), bytes.size()));
    } else {
        app_config_.m_LoadedPairingSecret.reset();
    }
    return MutationResult::Success;
}

ConfigurationImportService::MutationResult ConfigurationAppTarget::beginPending(
    const ConfigurationPublicSnapshot& original,
    const ConfigurationPublicSnapshot& candidate,
    const std::optional<SensitiveBytes>& oldPairingCode,
    const std::optional<SensitiveBytes>& newPairingCode)
{
    using MutationResult = ConfigurationImportService::MutationResult;
    if (pending_journal_lock_ || pending_transaction_lock_)
        return MutationResult::ConcurrentModification;
    pending_candidate_applied_ = false;
    auto journalLock = std::make_unique<QLockFile>(importJournalLockPath());
    if (!journalLock->tryLock(5000))
        return MutationResult::ConcurrentModification;
    auto transactionLock = std::make_unique<ConfigurationTransactionLock>();
    if (!transactionLock->isLocked())
        return MutationResult::ConcurrentModification;
    QSettings& settings = app_config_.settings();
    if (loadJournal(settings).status != PendingJournal::Status::None)
        return MutationResult::ConcurrentModification;
    auto& credentials = app_config_.m_CredentialStore;
    const auto existingOld = credentials.read(QString::fromLatin1(OldCapsuleAccount));
    const auto existingNew = credentials.read(QString::fromLatin1(NewCapsuleAccount));
    const auto existingCommit = credentials.read(
        QString::fromLatin1(CommitMarkerAccount));
    const auto existingPrepare = credentials.read(
        QString::fromLatin1(PrepareMarkerAccount));
    if (existingOld.status != SecureCredentialStore::ReadResult::Status::NotFound ||
        existingNew.status != SecureCredentialStore::ReadResult::Status::NotFound ||
        existingCommit.status != SecureCredentialStore::ReadResult::Status::NotFound ||
        existingPrepare.status != SecureCredentialStore::ReadResult::Status::NotFound)
        return MutationResult::ConcurrentModification;

    const QByteArray originalEncoded = encodePublicSnapshot(original);
    const QByteArray candidateEncoded = encodePublicSnapshot(candidate);
    if (originalEncoded.size() > MaxPublicSnapshotBytes ||
        candidateEncoded.size() > MaxPublicSnapshotBytes)
        return MutationResult::Failed;

    const auto authenticationKey = RecoveryArtifactAuthenticator::loadOrCreateKey(
        credentials, QString::fromLatin1(AuthenticationKeyAccount));
    if (!authenticationKey) return MutationResult::Failed;

    const QString transactionId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const QByteArray binding = journalBinding(
        authenticationKey->bytes(), transactionId, original, candidate);
    const QByteArray prepareMarker = encodePrepareMarker(
        authenticationKey->bytes(), transactionId, binding);
    const bool prepareWritten = credentials.write(
        QString::fromLatin1(PrepareMarkerAccount), prepareMarker);
    const auto prepareStored = credentials.read(
        QString::fromLatin1(PrepareMarkerAccount));
    const auto prepareDecoded = prepareStored
        ? decodePrepareMarker(prepareStored.value, authenticationKey->bytes())
        : DecodedCommitMarker{};
    if (!prepareWritten || !prepareDecoded.valid ||
        prepareDecoded.transactionId != transactionId ||
        prepareDecoded.commonBinding != binding) {
        return MutationResult::Failed;
    }
    const auto writeCapsule = [&](const char* account, CapsuleRole role,
                                  const ConfigurationPublicSnapshot& snapshot,
                                  const std::optional<SensitiveBytes>& value) {
        QByteArray encoded = encodeCapsule(
            authenticationKey->bytes(), transactionId,
            binding, role, snapshot, value);
        const auto cleanseEncoded = qScopeGuard([&encoded] {
            if (!encoded.isEmpty())
                OPENSSL_cleanse(encoded.data(), static_cast<size_t>(encoded.size()));
        });
        const bool written = credentials.write(QString::fromLatin1(account), encoded);
        return written;
    };
    if (!writeCapsule(OldCapsuleAccount, CapsuleRole::Old, original, oldPairingCode) ||
        !writeCapsule(NewCapsuleAccount, CapsuleRole::New, candidate, newPairingCode)) {
        const bool oldRemoved = credentials.remove(QString::fromLatin1(OldCapsuleAccount));
        const bool newRemoved = credentials.remove(QString::fromLatin1(NewCapsuleAccount));
        if (oldRemoved && newRemoved)
            credentials.remove(QString::fromLatin1(PrepareMarkerAccount));
        return MutationResult::Failed;
    }
    auto oldStored = credentials.read(QString::fromLatin1(OldCapsuleAccount));
    auto newStored = credentials.read(QString::fromLatin1(NewCapsuleAccount));
    if (!oldStored || !newStored) {
        const bool oldRemoved = credentials.remove(QString::fromLatin1(OldCapsuleAccount));
        const bool newRemoved = credentials.remove(QString::fromLatin1(NewCapsuleAccount));
        if (oldRemoved && newRemoved)
            credentials.remove(QString::fromLatin1(PrepareMarkerAccount));
        return MutationResult::Failed;
    }
    auto oldDecoded = decodeCapsule(oldStored.value, CapsuleRole::Old,
                                      authenticationKey->bytes());
    auto newDecoded = decodeCapsule(newStored.value, CapsuleRole::New,
                                      authenticationKey->bytes());
    if (!validCapsulePair(oldDecoded, newDecoded, authenticationKey->bytes()) ||
        oldDecoded.transactionId != transactionId ||
        oldDecoded.commonBinding != binding ||
        !sameSnapshot(*oldDecoded.snapshot, original) ||
        !sameSnapshot(*newDecoded.snapshot, candidate) ||
        !sameSensitive(oldDecoded.value, oldPairingCode) ||
        !sameSensitive(newDecoded.value, newPairingCode)) {
        const bool oldRemoved = credentials.remove(QString::fromLatin1(OldCapsuleAccount));
        const bool newRemoved = credentials.remove(QString::fromLatin1(NewCapsuleAccount));
        if (oldRemoved && newRemoved)
            credentials.remove(QString::fromLatin1(PrepareMarkerAccount));
        return MutationResult::Failed;
    }

    settings.beginGroup(QString::fromLatin1(JournalRoot));
    settings.setValue(QStringLiteral("schemaVersion"), 2);
    settings.setValue(QStringLiteral("state"), QStringLiteral("pending"));
    settings.setValue(QStringLiteral("transactionId"), transactionId);
    settings.setValue(QStringLiteral("originalPublic"), originalEncoded);
    settings.setValue(QStringLiteral("candidatePublic"), candidateEncoded);
    settings.endGroup();
    const bool journalDurable = durableSync(settings);
    const auto verified = loadJournal(settings);
    if (!journalDurable ||
        verified.status != PendingJournal::Status::Valid ||
        verified.transactionId != transactionId || !verified.original ||
        !verified.candidate || !sameSnapshot(*verified.original, original) ||
        !sameSnapshot(*verified.candidate, candidate)) {
        settings.remove(QString::fromLatin1(JournalRoot));
        const bool journalRemoved = durableSync(settings) &&
            loadJournal(settings).status == PendingJournal::Status::None;
        if (journalRemoved) {
            const bool oldRemoved = credentials.remove(
                QString::fromLatin1(OldCapsuleAccount));
            const bool newRemoved = credentials.remove(
                QString::fromLatin1(NewCapsuleAccount));
            if (oldRemoved && newRemoved)
                credentials.remove(QString::fromLatin1(PrepareMarkerAccount));
        }
        return MutationResult::Failed;
    }
    if (!credentials.remove(QString::fromLatin1(PrepareMarkerAccount)))
        return MutationResult::Indeterminate;
    pending_journal_lock_ = std::move(journalLock);
    pending_transaction_lock_ = std::move(transactionLock);
    pending_owner_thread_ = std::this_thread::get_id();
    return MutationResult::Success;
}

ConfigurationImportService::MutationResult ConfigurationAppTarget::commitPending()
{
    using MutationResult = ConfigurationImportService::MutationResult;
    if (pending_journal_lock_) {
        if (!pending_transaction_lock_)
            return MutationResult::Indeterminate;
        if (pending_owner_thread_ != std::this_thread::get_id())
            return MutationResult::Indeterminate;
        const MutationResult result = commitPendingUnlocked();
        pending_transaction_lock_.reset();
        pending_journal_lock_.reset();
        pending_candidate_applied_ = false;
        pending_owner_thread_ = {};
        return result;
    }
    QLockFile journalLock(importJournalLockPath());
    if (!journalLock.tryLock(5000)) return MutationResult::Indeterminate;
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return MutationResult::Indeterminate;
    return commitPendingUnlocked();
}

ConfigurationImportService::MutationResult ConfigurationAppTarget::commitPendingUnlocked()
{
    using MutationResult = ConfigurationImportService::MutationResult;
    QSettings& settings = app_config_.settings();
    const auto journal = loadJournal(settings);
    if (journal.status != PendingJournal::Status::Valid ||
        !journal.original || !journal.candidate)
        return MutationResult::Indeterminate;
    auto& credentials = app_config_.m_CredentialStore;
    const auto authenticationKey = RecoveryArtifactAuthenticator::loadKey(
        credentials, QString::fromLatin1(AuthenticationKeyAccount));
    if (!authenticationKey) return MutationResult::Indeterminate;
    auto oldStored = credentials.read(QString::fromLatin1(OldCapsuleAccount));
    auto newStored = credentials.read(QString::fromLatin1(NewCapsuleAccount));
    auto prepareStored = credentials.read(QString::fromLatin1(PrepareMarkerAccount));
    if (!oldStored || !newStored ||
        prepareStored.status != SecureCredentialStore::ReadResult::Status::NotFound) {
        return MutationResult::Indeterminate;
    }
    auto oldDecoded = decodeCapsule(oldStored.value, CapsuleRole::Old,
                                      authenticationKey->bytes());
    auto newDecoded = decodeCapsule(newStored.value, CapsuleRole::New,
                                      authenticationKey->bytes());
    if (!validCapsulePair(oldDecoded, newDecoded, authenticationKey->bytes()) ||
        oldDecoded.transactionId != journal.transactionId ||
        !sameSnapshot(*oldDecoded.snapshot, *journal.original) ||
        !sameSnapshot(*newDecoded.snapshot, *journal.candidate)) {
        return MutationResult::Indeterminate;
    }
    const auto current = snapshot();
    const auto sensitive = readPairingCode();
    if (!sensitive.readable || !current)
        return MutationResult::Indeterminate;
    const bool appliedCandidate = current &&
        sameSnapshot(*current, *journal.candidate) &&
        sameSensitive(sensitive.value, newDecoded.value);
    if (!appliedCandidate)
        return MutationResult::ConcurrentModification;
    // Flush public/profile state while the pending journal is still durable.
    if (!durableSync(settings)) return MutationResult::Indeterminate;

    QByteArray marker = encodeCommitMarker(
        authenticationKey->bytes(), journal.transactionId,
        oldDecoded.commonBinding);
    const bool markerWritten = credentials.write(
        QString::fromLatin1(CommitMarkerAccount), marker);
    auto markerStored = credentials.read(QString::fromLatin1(CommitMarkerAccount));
    const auto markerDecoded = markerStored
        ? decodeCommitMarker(markerStored.value, authenticationKey->bytes())
        : DecodedCommitMarker{};
    if (!markerWritten || !markerDecoded.valid ||
        markerDecoded.transactionId != journal.transactionId ||
        markerDecoded.commonBinding != oldDecoded.commonBinding) {
        return MutationResult::Indeterminate;
    }

    // The candidate has a verified secure commit marker; everything below is cleanup.
    settings.remove(QString::fromLatin1(JournalRoot));
    if (!durableSync(settings) ||
        loadJournal(settings).status != PendingJournal::Status::None)
        return MutationResult::Indeterminate;
    const bool oldRemoved = credentials.remove(
        QString::fromLatin1(OldCapsuleAccount));
    const bool newRemoved = credentials.remove(
        QString::fromLatin1(NewCapsuleAccount));
    const bool markerRemoved = oldRemoved && newRemoved && credentials.remove(
        QString::fromLatin1(CommitMarkerAccount));
    return oldRemoved && newRemoved && markerRemoved
        ? MutationResult::Success : MutationResult::Indeterminate;
}

ConfigurationImportService::MutationResult ConfigurationAppTarget::abortPending()
{
    using MutationResult = ConfigurationImportService::MutationResult;
    if (pending_journal_lock_) {
        if (!pending_transaction_lock_)
            return MutationResult::Indeterminate;
        if (pending_owner_thread_ != std::this_thread::get_id())
            return MutationResult::Indeterminate;
        const MutationResult result = abortPendingUnlocked();
        pending_transaction_lock_.reset();
        pending_journal_lock_.reset();
        pending_candidate_applied_ = false;
        pending_owner_thread_ = {};
        return result;
    }
    QLockFile journalLock(importJournalLockPath());
    if (!journalLock.tryLock(5000)) return MutationResult::Indeterminate;
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return MutationResult::Indeterminate;
    return abortPendingUnlocked();
}

ConfigurationImportService::MutationResult ConfigurationAppTarget::abortPendingUnlocked()
{
    using MutationResult = ConfigurationImportService::MutationResult;
    QSettings& settings = app_config_.settings();
    const auto journal = loadJournal(settings);
    if (journal.status != PendingJournal::Status::Valid ||
        !journal.original || !journal.candidate) {
        return MutationResult::Indeterminate;
    }
    auto& credentials = app_config_.m_CredentialStore;
    const auto authenticationKey = RecoveryArtifactAuthenticator::loadKey(
        credentials, QString::fromLatin1(AuthenticationKeyAccount));
    if (!authenticationKey) return MutationResult::Indeterminate;
    auto oldStored = credentials.read(QString::fromLatin1(OldCapsuleAccount));
    auto newStored = credentials.read(QString::fromLatin1(NewCapsuleAccount));
    auto markerStored = credentials.read(QString::fromLatin1(CommitMarkerAccount));
    auto prepareStored = credentials.read(QString::fromLatin1(PrepareMarkerAccount));
    if (!oldStored || !newStored ||
        markerStored.status != SecureCredentialStore::ReadResult::Status::NotFound ||
        prepareStored.status != SecureCredentialStore::ReadResult::Status::NotFound) {
        return MutationResult::Indeterminate;
    }
    const auto oldDecoded = decodeCapsule(oldStored.value, CapsuleRole::Old,
                                      authenticationKey->bytes());
    const auto newDecoded = decodeCapsule(newStored.value, CapsuleRole::New,
                                      authenticationKey->bytes());
    if (!validCapsulePair(oldDecoded, newDecoded, authenticationKey->bytes()) ||
        oldDecoded.transactionId != journal.transactionId ||
        !sameSnapshot(*oldDecoded.snapshot, *journal.original) ||
        !sameSnapshot(*newDecoded.snapshot, *journal.candidate)) {
        return MutationResult::Indeterminate;
    }
    const QByteArray cleanupMarker = encodePrepareMarker(
        authenticationKey->bytes(), journal.transactionId,
        oldDecoded.commonBinding);
    const bool cleanupMarkerWritten = credentials.write(
        QString::fromLatin1(PrepareMarkerAccount), cleanupMarker);
    prepareStored = credentials.read(QString::fromLatin1(PrepareMarkerAccount));
    const auto cleanupMarkerDecoded = prepareStored
        ? decodePrepareMarker(prepareStored.value, authenticationKey->bytes())
        : DecodedCommitMarker{};
    if (!cleanupMarkerWritten || !cleanupMarkerDecoded.valid ||
        cleanupMarkerDecoded.transactionId != journal.transactionId ||
        cleanupMarkerDecoded.commonBinding != oldDecoded.commonBinding) {
        return MutationResult::Indeterminate;
    }
    settings.remove(QString::fromLatin1(JournalRoot));
    if (!durableSync(settings) ||
        loadJournal(settings).status != PendingJournal::Status::None) {
        return MutationResult::Indeterminate;
    }
    const bool oldRemoved = credentials.remove(
        QString::fromLatin1(OldCapsuleAccount));
    const bool newRemoved = credentials.remove(
        QString::fromLatin1(NewCapsuleAccount));
    const bool prepareRemoved = oldRemoved && newRemoved && credentials.remove(
        QString::fromLatin1(PrepareMarkerAccount));
    return oldRemoved && newRemoved && prepareRemoved
        ? MutationResult::Success : MutationResult::Indeterminate;
}

ConfigurationAppTarget::PendingRecoveryResult
ConfigurationAppTarget::recoverPendingImport()
{
    if (pending_journal_lock_ || pending_transaction_lock_)
        return PendingRecoveryResult::Blocked;
    QLockFile journalLock(importJournalLockPath());
    if (!journalLock.tryLock(5000)) return PendingRecoveryResult::Blocked;
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return PendingRecoveryResult::Blocked;
    QSettings& settings = app_config_.settings();
    auto journal = loadJournal(settings);
    auto& credentials = app_config_.m_CredentialStore;
    auto oldStored = credentials.read(QString::fromLatin1(OldCapsuleAccount));
    auto newStored = credentials.read(QString::fromLatin1(NewCapsuleAccount));
    auto markerStored = credentials.read(QString::fromLatin1(CommitMarkerAccount));
    auto prepareStored = credentials.read(QString::fromLatin1(PrepareMarkerAccount));
    const bool oldAbsent = oldStored.status ==
        SecureCredentialStore::ReadResult::Status::NotFound;
    const bool newAbsent = newStored.status ==
        SecureCredentialStore::ReadResult::Status::NotFound;
    const bool markerAbsent = markerStored.status ==
        SecureCredentialStore::ReadResult::Status::NotFound;
    const bool prepareAbsent = prepareStored.status ==
        SecureCredentialStore::ReadResult::Status::NotFound;
    if (journal.status == PendingJournal::Status::None &&
        oldAbsent && newAbsent && markerAbsent && prepareAbsent) {
        return PendingRecoveryResult::NotNeeded;
    }
    const auto authenticationKey = RecoveryArtifactAuthenticator::loadKey(
        credentials, QString::fromLatin1(AuthenticationKeyAccount));
    if (!authenticationKey) return PendingRecoveryResult::Blocked;
    if (const auto prepared = recoverPreparingTransaction(
            settings, credentials, authenticationKey->bytes(), journal,
            oldStored, newStored, markerStored, prepareStored)) {
        return *prepared;
    }
    if (markerStored.status == SecureCredentialStore::ReadResult::Status::Error)
        return PendingRecoveryResult::Blocked;
    if (!markerAbsent) {
        const auto marker = decodeCommitMarker(
            markerStored.value, authenticationKey->bytes());
        if (!marker.valid || journal.status == PendingJournal::Status::Invalid)
            return PendingRecoveryResult::Blocked;
        if (journal.status == PendingJournal::Status::Valid) {
            if (!journal.original || !journal.candidate ||
                marker.transactionId != journal.transactionId ||
                marker.commonBinding != journalBinding(
                    authenticationKey->bytes(), journal.transactionId,
                    *journal.original, *journal.candidate)) {
                return PendingRecoveryResult::Blocked;
            }
            settings.remove(QString::fromLatin1(JournalRoot));
            if (!durableSync(settings) ||
                loadJournal(settings).status != PendingJournal::Status::None) {
                return PendingRecoveryResult::Blocked;
            }
        } else if (!oldAbsent && !newAbsent) {
            const auto oldDecoded = decodeCapsule(oldStored.value, CapsuleRole::Old,
                                      authenticationKey->bytes());
            const auto newDecoded = decodeCapsule(newStored.value, CapsuleRole::New,
                                      authenticationKey->bytes());
            if (!validCapsulePair(oldDecoded, newDecoded,
                                  authenticationKey->bytes()) ||
                marker.transactionId != oldDecoded.transactionId ||
                marker.commonBinding != oldDecoded.commonBinding) {
                return PendingRecoveryResult::Blocked;
            }
        }
        const bool oldRemoved = credentials.remove(
            QString::fromLatin1(OldCapsuleAccount));
        const bool newRemoved = credentials.remove(
            QString::fromLatin1(NewCapsuleAccount));
        const bool markerRemoved = oldRemoved && newRemoved && credentials.remove(
            QString::fromLatin1(CommitMarkerAccount));
        return oldRemoved && newRemoved && markerRemoved
            ? PendingRecoveryResult::NotNeeded : PendingRecoveryResult::Blocked;
    }
    if (journal.status == PendingJournal::Status::None && oldAbsent && newAbsent)
        return PendingRecoveryResult::NotNeeded;
    if (journal.status == PendingJournal::Status::Invalid ||
        !oldStored || !newStored) {
        qWarning("Import recovery blocked: journal or capsule unavailable");
        return PendingRecoveryResult::Blocked;
    }
    auto oldDecoded = decodeCapsule(oldStored.value, CapsuleRole::Old,
                                      authenticationKey->bytes());
    auto newDecoded = decodeCapsule(newStored.value, CapsuleRole::New,
                                      authenticationKey->bytes());
    if (!validCapsulePair(oldDecoded, newDecoded,
                          authenticationKey->bytes())) {
        qWarning("Import recovery blocked: capsule invalid");
        return PendingRecoveryResult::Blocked;
    }
    const bool reconstructedJournal =
        journal.status == PendingJournal::Status::None;
    if (reconstructedJournal) {
        journal.status = PendingJournal::Status::Valid;
        journal.transactionId = oldDecoded.transactionId;
        journal.original = *oldDecoded.snapshot;
        journal.candidate = *newDecoded.snapshot;
    } else if (!journal.original || !journal.candidate ||
               journal.transactionId != oldDecoded.transactionId ||
               !sameSnapshot(*journal.original, *oldDecoded.snapshot) ||
               !sameSnapshot(*journal.candidate, *newDecoded.snapshot)) {
        qWarning("Import recovery blocked: journal does not match capsules");
        return PendingRecoveryResult::Blocked;
    }

    const auto current = snapshot();
    const auto sensitive = readPairingCode();
    if (!current || !sensitive.readable) return PendingRecoveryResult::Blocked;
    const auto currentPreferences = ConfigurationPortablePreferencesCodec::encode(
        current->preferences);
    const bool preferencesRecognized = fieldsBelongToTransaction(
        currentPreferences,
        ConfigurationPortablePreferencesCodec::encode(journal.original->preferences),
        ConfigurationPortablePreferencesCodec::encode(journal.candidate->preferences));
    const auto currentProfiles = EnvironmentProfileJsonCodec::encode(
        current->environmentProfiles);
    const bool profilesRecognized = currentProfiles ==
            EnvironmentProfileJsonCodec::encode(journal.original->environmentProfiles) ||
        currentProfiles == EnvironmentProfileJsonCodec::encode(
            journal.candidate->environmentProfiles);
    const bool sensitiveIsOld = sameSensitive(sensitive.value, oldDecoded.value);
    const bool sensitiveIsNew = sameSensitive(sensitive.value, newDecoded.value);
    if (!preferencesRecognized || !profilesRecognized ||
        (!sensitiveIsOld && !sensitiveIsNew)) {
        qWarning("Import recovery blocked: unrecognized transaction state");
        return PendingRecoveryResult::Blocked;
    }

    if (!sameSnapshot(*current, *journal.original)) {
        const auto publicRollback = compareAndApply(*journal.original, *current);
        if (publicRollback != ConfigurationImportService::MutationResult::Success) {
            qWarning() << "Import recovery blocked: public rollback result"
                       << static_cast<int>(publicRollback);
            return PendingRecoveryResult::Blocked;
        }
    }
    if (!sensitiveIsOld &&
        writePairingCode(oldDecoded.value, sensitive.value) !=
            ConfigurationImportService::MutationResult::Success)
        return PendingRecoveryResult::Blocked;

    const auto restored = snapshot();
    const auto restoredSensitive = readPairingCode();
    if (!restored || !sameSnapshot(*restored, *journal.original) ||
        !restoredSensitive.readable ||
        !sameSensitive(restoredSensitive.value, oldDecoded.value))
        return PendingRecoveryResult::Blocked;
    if (reconstructedJournal) {
        const QByteArray cleanupMarker = encodePrepareMarker(
            authenticationKey->bytes(), journal.transactionId,
            oldDecoded.commonBinding);
        const bool cleanupMarkerWritten = credentials.write(
            QString::fromLatin1(PrepareMarkerAccount), cleanupMarker);
        const auto cleanupMarkerStored = credentials.read(
            QString::fromLatin1(PrepareMarkerAccount));
        const auto cleanupMarkerDecoded = cleanupMarkerStored
            ? decodePrepareMarker(cleanupMarkerStored.value,
                                  authenticationKey->bytes())
            : DecodedCommitMarker{};
        if (!cleanupMarkerWritten || !cleanupMarkerDecoded.valid ||
            cleanupMarkerDecoded.transactionId != journal.transactionId ||
            cleanupMarkerDecoded.commonBinding != oldDecoded.commonBinding) {
            return PendingRecoveryResult::Blocked;
        }
        const bool oldRemoved = credentials.remove(
            QString::fromLatin1(OldCapsuleAccount));
        const bool newRemoved = credentials.remove(
            QString::fromLatin1(NewCapsuleAccount));
        const bool markerRemoved = oldRemoved && newRemoved && credentials.remove(
            QString::fromLatin1(PrepareMarkerAccount));
        if (!oldRemoved || !newRemoved || !markerRemoved)
            return PendingRecoveryResult::Blocked;
    } else if (abortPendingUnlocked() !=
               ConfigurationImportService::MutationResult::Success) {
        return PendingRecoveryResult::Blocked;
    }
    return PendingRecoveryResult::Recovered;
}
