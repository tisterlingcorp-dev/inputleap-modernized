#include "AppConfigSettingsJournal.h"
#include "RecoveryArtifactAuthenticator.h"

#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QScopeGuard>
#include <QSettings>
#include <QUuid>

#if defined(Q_OS_WIN)
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include <openssl/crypto.h>

namespace {
constexpr auto JournalRoot = "appConfigSaveJournal";
constexpr int JournalSchema = 1;
constexpr qsizetype MaxStateJsonBytes = 64 * 1024;

const QStringList& publicKeys()
{
    static const QStringList keys{
        QStringLiteral("screenName"), QStringLiteral("port"),
        QStringLiteral("interface"), QStringLiteral("logLevel"),
        QStringLiteral("logToFile"), QStringLiteral("logFilename"),
        QStringLiteral("receiveDirectory"), QStringLiteral("wizardLastRun"),
        QStringLiteral("language"), QStringLiteral("startedBefore"),
        QStringLiteral("autoConfig"), QStringLiteral("elevateMode"),
        QStringLiteral("elevateModeEnum"), QStringLiteral("autoConfigPrompted"),
        QStringLiteral("cryptoEnabled"),
        QStringLiteral("requireClientCertificate"), QStringLiteral("autoHide"),
        QStringLiteral("autoStart"), QStringLiteral("minimizeToTray")};
    return keys;
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
        const QString prefix = QStringLiteral("HKEY_CURRENT_USER\\");
        if (!path.startsWith(prefix, Qt::CaseInsensitive)) return false;
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
    HANDLE file = CreateFileW(
        reinterpret_cast<LPCWSTR>(settings.fileName().utf16()),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    const bool flushed = FlushFileBuffers(file) != FALSE;
    CloseHandle(file);
    return flushed;
#else
    QFile file(settings.fileName());
    if (!file.open(QIODevice::ReadOnly) || ::fsync(file.handle()) != 0)
        return false;
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

bool validValue(const QString& key, const QJsonValue& value)
{
    static const QSet<QString> strings{
        QStringLiteral("screenName"), QStringLiteral("interface"),
        QStringLiteral("logFilename"), QStringLiteral("receiveDirectory"),
        QStringLiteral("language")};
    static const QSet<QString> integers{
        QStringLiteral("port"), QStringLiteral("logLevel"),
        QStringLiteral("wizardLastRun"), QStringLiteral("elevateModeEnum")};
    static const QSet<QString> booleans{
        QStringLiteral("logToFile"), QStringLiteral("startedBefore"),
        QStringLiteral("autoConfig"), QStringLiteral("elevateMode"),
        QStringLiteral("autoConfigPrompted"), QStringLiteral("cryptoEnabled"),
        QStringLiteral("requireClientCertificate"), QStringLiteral("autoHide"),
        QStringLiteral("autoStart"), QStringLiteral("minimizeToTray")};
    if (strings.contains(key)) return value.isString();
    if (integers.contains(key))
        return value.isDouble() && value.toDouble() == value.toInt();
    if (!booleans.contains(key)) return false;
    return value.isBool() ||
        (value.isString() &&
         (value.toString() == QStringLiteral("true") ||
          value.toString() == QStringLiteral("false")));
}

bool validState(const QJsonObject& state)
{
    for (auto it = state.constBegin(); it != state.constEnd(); ++it) {
        if (!publicKeys().contains(it.key()) || !validValue(it.key(), it.value()))
            return false;
    }
    return true;
}

QByteArray encodeState(const QJsonObject& state)
{
    return QJsonDocument(state).toJson(QJsonDocument::Compact);
}

std::optional<QJsonObject> decodeState(const QByteArray& encoded)
{
    if (encoded.isEmpty() || encoded.size() > MaxStateJsonBytes)
        return std::nullopt;
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(encoded, &error);
    if (error.error != QJsonParseError::NoError || !document.isObject() ||
        !validState(document.object())) {
        return std::nullopt;
    }
    return document.object();
}

QByteArray bindingFor(const QString& transactionId,
                      const QJsonObject& original,
                      const QJsonObject& candidate)
{
    QCryptographicHash hash(QCryptographicHash::Sha256);
    const auto append = [&hash](const QByteArray& part) {
        const QByteArray size = QByteArray::number(part.size());
        hash.addData(size);
        hash.addData(QByteArrayLiteral(":"));
        hash.addData(QByteArray(part));
    };
    append(QByteArrayLiteral("inputleap-app-config-save-v1"));
    append(transactionId.toUtf8());
    append(encodeState(original));
    append(encodeState(candidate));
    return hash.result();
}

QByteArray capsuleBindingFor(
    QByteArrayView authenticationKey,
    const QByteArray& publicBinding,
    bool originalSecretPresent,
    bool secretTransition,
    const std::optional<SensitiveBytes>& secretCandidate)
{
    const QByteArray domain = QByteArrayLiteral("inputleap-app-config-capsule-v5");
    const char originalState = originalSecretPresent ? '\1' : '\0';
    const char transitionState = secretTransition ? '\1' : '\0';
    const char candidateState = secretCandidate ? '\1' : '\0';
    QVector<QByteArrayView> parts{
        QByteArrayView(publicBinding), QByteArrayView(&originalState, 1),
        QByteArrayView(&transitionState, 1),
        QByteArrayView(&candidateState, 1)};
    if (secretCandidate) parts.append(secretCandidate->bytes());
    return RecoveryArtifactAuthenticator::authenticate(
        authenticationKey, QByteArrayView(domain), parts);
}

QByteArray commitMarkerFor(QByteArrayView authenticationKey, QByteArrayView capsule)
{
    const QByteArray domain = QByteArrayLiteral("inputleap-app-config-commit-v2");
    return QByteArrayLiteral("ILACM1") +
        RecoveryArtifactAuthenticator::authenticate(
            authenticationKey, QByteArrayView(domain), {capsule});
}

bool validCommitMarker(const SensitiveBytes& marker, QByteArrayView authenticationKey,
                       QByteArrayView capsule)
{
    const QByteArray expected = commitMarkerFor(authenticationKey, capsule);
    const QByteArrayView actual = marker.bytes();
    return actual.size() == expected.size() &&
        CRYPTO_memcmp(actual.data(), expected.constData(),
                      static_cast<size_t>(expected.size())) == 0;
}

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
    return value <= 1024 * 1024 && input.size() - offset >= value;
}

QByteArray encodeCapsule(QByteArrayView authenticationKey,
                         const QString& transactionId, const QByteArray& binding,
                         const QJsonObject& original,
                         const QJsonObject& publicCandidate,
                         bool originalSecretPresent,
                         bool secretTransition,
                         const std::optional<SensitiveBytes>& secretCandidate)
{
    const QByteArray originalBytes = encodeState(original);
    const QByteArray candidateBytes = encodeState(publicCandidate);
    const QByteArray capsuleBinding = capsuleBindingFor(
        authenticationKey, binding, originalSecretPresent, secretTransition,
        secretCandidate);
    QByteArray encoded = QByteArrayLiteral("ILACSJ5");
    encoded.append(transactionId.toUtf8());
    encoded.append(capsuleBinding);
    appendLength(encoded, static_cast<quint32>(originalBytes.size()));
    encoded.append(originalBytes);
    appendLength(encoded, static_cast<quint32>(candidateBytes.size()));
    encoded.append(candidateBytes);
    encoded.append(originalSecretPresent ? '\1' : '\0');
    encoded.append(secretTransition ? '\1' : '\0');
    encoded.append(secretCandidate ? '\1' : '\0');
    if (secretCandidate) {
        const QByteArrayView bytes = secretCandidate->bytes();
        encoded.append(bytes.data(), bytes.size());
    }
    return encoded;
}

struct DecodedCapsule
{
    bool valid = false;
    QString transactionId;
    QJsonObject original;
    QJsonObject candidate;
    bool originalSecretPresent = false;
    bool secretTransition = false;
    std::optional<SensitiveBytes> value;
};

DecodedCapsule decodeCapsule(const SensitiveBytes& encoded,
                             QByteArrayView authenticationKey)
{
    const QByteArrayView bytes = encoded.bytes();
    const QByteArray magic = QByteArrayLiteral("ILACSJ5");
    constexpr qsizetype UuidSize = 36;
    const qsizetype digestSize = QCryptographicHash::hashLength(
        QCryptographicHash::Sha256);
    qsizetype offset = magic.size();
    if (bytes.size() < offset + UuidSize + digestSize + 4 + 4 + 3 ||
        CRYPTO_memcmp(bytes.data(), magic.constData(),
                      static_cast<size_t>(magic.size())) != 0) return {};
    const QString transactionId = QString::fromUtf8(bytes.data() + offset, UuidSize);
    const QUuid uuid(transactionId);
    if (uuid.isNull() || uuid.toString(QUuid::WithoutBraces) != transactionId)
        return {};
    offset += UuidSize;
    const QByteArray storedBinding(bytes.data() + offset, digestSize);
    offset += digestSize;
    quint32 originalSize = 0;
    if (!readLength(bytes, offset, originalSize)) return {};
    const auto original = decodeState(QByteArray(bytes.data() + offset, originalSize));
    offset += originalSize;
    quint32 candidateSize = 0;
    if (!readLength(bytes, offset, candidateSize)) return {};
    const auto candidate = decodeState(QByteArray(bytes.data() + offset, candidateSize));
    offset += candidateSize;
    if (!original || !candidate || bytes.size() < offset + 3) return {};
    const char originalState = bytes[offset++];
    if (originalState != '\0' && originalState != '\1') return {};
    const bool originalSecretPresent = originalState == '\1';
    const char transitionState = bytes[offset++];
    if (transitionState != '\0' && transitionState != '\1') return {};
    const bool secretTransition = transitionState == '\1';
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
    const QByteArray publicBinding = bindingFor(transactionId, *original, *candidate);
    const QByteArray expectedBinding = capsuleBindingFor(
        authenticationKey, publicBinding, originalSecretPresent, secretTransition,
        value);
    if (storedBinding.size() != expectedBinding.size() ||
        CRYPTO_memcmp(storedBinding.constData(), expectedBinding.constData(),
                      static_cast<size_t>(expectedBinding.size())) != 0) return {};
    return {true, transactionId, *original, *candidate,
            originalSecretPresent, secretTransition, std::move(value)};
}

bool sameSecret(const SecureCredentialStore::ReadResult& current,
                const std::optional<SensitiveBytes>& candidate)
{
    if (current.status == SecureCredentialStore::ReadResult::Status::Error)
        return false;
    if (current.has_value() != candidate.has_value()) return false;
    return !candidate || current->securelyEquals(candidate->bytes());
}

bool fieldsBelongToTransaction(const QJsonObject& current,
                               const QJsonObject& original,
                               const QJsonObject& candidate)
{
    for (const QString& key : publicKeys()) {
        const bool currentPresent = current.contains(key);
        const bool originalPresent = original.contains(key);
        const bool candidatePresent = candidate.contains(key);
        const bool matchesOriginal = currentPresent == originalPresent &&
            (!currentPresent || current.value(key) == original.value(key));
        const bool matchesCandidate = currentPresent == candidatePresent &&
            (!currentPresent || current.value(key) == candidate.value(key));
        if (!matchesOriginal && !matchesCandidate) return false;
    }
    return true;
}

struct PendingJournal
{
    enum class Status { None, Valid, Invalid } status = Status::None;
    QString transactionId;
    QJsonObject original;
    QJsonObject candidate;
    bool publicApplied = false;
};

PendingJournal loadJournal(QSettings& settings)
{
    settings.sync();
    if (settings.status() != QSettings::NoError)
        return {PendingJournal::Status::Invalid, {}, {}, {}};
    settings.beginGroup(QString::fromLatin1(JournalRoot));
    const QStringList keys = settings.childKeys();
    const QStringList groups = settings.childGroups();
    const QStringList expected{
        QStringLiteral("candidatePublic"), QStringLiteral("originalPublic"),
        QStringLiteral("schemaVersion"), QStringLiteral("state"),
        QStringLiteral("transactionId")};
    if (keys.isEmpty() && groups.isEmpty()) {
        settings.endGroup();
        return {};
    }
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
    if (schema.metaType().id() != QMetaType::Int || schema.toInt() != JournalSchema ||
        state.metaType().id() != QMetaType::QString ||
        (state.toString() != QStringLiteral("pending") &&
         state.toString() != QStringLiteral("public-applied")) ||
        id.metaType().id() != QMetaType::QString ||
        original.metaType().id() != QMetaType::QByteArray ||
        candidate.metaType().id() != QMetaType::QByteArray) {
        return {PendingJournal::Status::Invalid, {}, {}, {}};
    }
    const QString transactionId = id.toString();
    const QUuid uuid(transactionId);
    const auto originalState = decodeState(original.toByteArray());
    const auto candidateState = decodeState(candidate.toByteArray());
    if (uuid.isNull() || uuid.toString(QUuid::WithoutBraces) != transactionId ||
        !originalState || !candidateState) {
        return {PendingJournal::Status::Invalid, {}, {}, {}};
    }
    return {PendingJournal::Status::Valid, transactionId,
            *originalState, *candidateState,
            state.toString() == QStringLiteral("public-applied")};
}
} // namespace

AppConfigSettingsJournal::AppConfigSettingsJournal(
    QSettings& settings, SecureCredentialStore& credentials) :
    settings_(settings), credentials_(credentials)
{
}

QJsonObject AppConfigSettingsJournal::capture(QSettings& settings)
{
    settings.sync();
    QJsonObject state;
    for (const QString& key : publicKeys()) {
        if (settings.contains(key))
            state.insert(key, QJsonValue::fromVariant(settings.value(key)));
    }
    return state;
}

bool AppConfigSettingsJournal::apply(QSettings& settings,
                                     const QJsonObject& state)
{
    if (!validState(state)) return false;
    for (const QString& key : publicKeys()) {
        if (state.contains(key))
            settings.setValue(key, state.value(key).toVariant());
        else
            settings.remove(key);
    }
    return durableSync(settings);
}

bool AppConfigSettingsJournal::begin(
    const QJsonObject& original, const QJsonObject& candidate,
    const std::optional<SensitiveBytes>& candidateSecret)
{
    const QByteArray originalEncoded = encodeState(original);
    const QByteArray candidateEncoded = encodeState(candidate);
    if (!validState(original) || !validState(candidate) ||
        originalEncoded.size() > MaxStateJsonBytes ||
        candidateEncoded.size() > MaxStateJsonBytes ||
        loadJournal(settings_).status != PendingJournal::Status::None) {
        return false;
    }
    const auto existingCapsule = credentials_.read(CandidateCapsuleAccount);
    if (existingCapsule.status !=
        SecureCredentialStore::ReadResult::Status::NotFound) {
        return false;
    }
    const auto existingMarker = credentials_.read(CommitMarkerAccount);
    if (existingMarker.status !=
        SecureCredentialStore::ReadResult::Status::NotFound) {
        return false;
    }
    const auto authenticationKey = RecoveryArtifactAuthenticator::loadOrCreateKey(
        credentials_, AuthenticationKeyAccount);
    if (!authenticationKey) return false;
    const auto originalSecret = credentials_.read(PairingAccount);
    if (originalSecret.status == SecureCredentialStore::ReadResult::Status::Error)
        return false;
    const bool secretTransition = !sameSecret(originalSecret, candidateSecret);
    const QString transactionId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const QByteArray binding = bindingFor(transactionId, original, candidate);
    QByteArray capsule = encodeCapsule(authenticationKey->bytes(), transactionId,
                                       binding, original, candidate,
                                       originalSecret.has_value(), secretTransition,
                                       candidateSecret);
    const auto cleanse = qScopeGuard([&capsule] {
        if (!capsule.isEmpty())
            OPENSSL_cleanse(capsule.data(), static_cast<size_t>(capsule.size()));
    });
    if (!credentials_.write(CandidateCapsuleAccount, capsule)) {
        credentials_.remove(CandidateCapsuleAccount);
        return false;
    }
    const auto readback = credentials_.read(CandidateCapsuleAccount);
    if (!readback || !readback->securelyEquals(QByteArrayView(capsule))) {
        credentials_.remove(CandidateCapsuleAccount);
        return false;
    }
    settings_.beginGroup(QString::fromLatin1(JournalRoot));
    settings_.setValue(QStringLiteral("schemaVersion"), JournalSchema);
    settings_.setValue(QStringLiteral("state"), QStringLiteral("pending"));
    settings_.setValue(QStringLiteral("transactionId"), transactionId);
    settings_.setValue(QStringLiteral("originalPublic"), originalEncoded);
    settings_.setValue(QStringLiteral("candidatePublic"), candidateEncoded);
    settings_.endGroup();
    if (durableSync(settings_)) return true;
    settings_.remove(QString::fromLatin1(JournalRoot));
    durableSync(settings_);
    credentials_.remove(CandidateCapsuleAccount);
    return false;
}

bool AppConfigSettingsJournal::markPublicApplied()
{
    const PendingJournal journal = loadJournal(settings_);
    if (journal.status != PendingJournal::Status::Valid || journal.publicApplied)
        return false;
    settings_.beginGroup(QString::fromLatin1(JournalRoot));
    settings_.setValue(QStringLiteral("state"), QStringLiteral("public-applied"));
    settings_.endGroup();
    if (!durableSync(settings_)) return false;
    const PendingJournal verified = loadJournal(settings_);
    return verified.status == PendingJournal::Status::Valid &&
        verified.transactionId == journal.transactionId &&
        verified.original == journal.original &&
        verified.candidate == journal.candidate && verified.publicApplied;
}

bool AppConfigSettingsJournal::commit()
{
    const auto capsule = credentials_.read(CandidateCapsuleAccount);
    const auto authenticationKey = RecoveryArtifactAuthenticator::loadKey(
        credentials_, AuthenticationKeyAccount);
    if (!capsule || !authenticationKey) return false;
    const QByteArray marker = commitMarkerFor(
        authenticationKey->bytes(), capsule->bytes());
    if (!credentials_.write(CommitMarkerAccount, marker)) return false;
    const auto markerReadback = credentials_.read(CommitMarkerAccount);
    if (!markerReadback || !markerReadback->securelyEquals(QByteArrayView(marker)))
        return false;
    settings_.remove(QString::fromLatin1(JournalRoot));
    if (!durableSync(settings_)) return false;
    if (!credentials_.remove(CandidateCapsuleAccount)) return false;
    return credentials_.remove(CommitMarkerAccount);
}

AppConfigSettingsJournal::RecoveryResult AppConfigSettingsJournal::recover()
{
    const PendingJournal journal = loadJournal(settings_);
    if (journal.status == PendingJournal::Status::Invalid)
        return RecoveryResult::Blocked;
    if (!credentials_.available())
        return journal.status == PendingJournal::Status::None
            ? RecoveryResult::NotNeeded : RecoveryResult::Blocked;

    const auto marker = credentials_.read(CommitMarkerAccount);
    if (marker.status == SecureCredentialStore::ReadResult::Status::Error)
        return RecoveryResult::Blocked;
    const auto encoded = credentials_.read(CandidateCapsuleAccount);
    if (marker.has_value() &&
        encoded.status == SecureCredentialStore::ReadResult::Status::NotFound) {
        if (journal.status != PendingJournal::Status::None ||
            !credentials_.remove(CommitMarkerAccount)) {
            return RecoveryResult::Blocked;
        }
        return RecoveryResult::NotNeeded;
    }
    if (encoded.status == SecureCredentialStore::ReadResult::Status::NotFound)
        return journal.status == PendingJournal::Status::None
            ? RecoveryResult::NotNeeded : RecoveryResult::Blocked;
    if (!encoded) return RecoveryResult::Blocked;
    const auto authenticationKey = RecoveryArtifactAuthenticator::loadKey(
        credentials_, AuthenticationKeyAccount);
    if (!authenticationKey) return RecoveryResult::Blocked;
    if (marker.has_value() &&
        !validCommitMarker(*marker, authenticationKey->bytes(), encoded->bytes()))
        return RecoveryResult::Blocked;

    auto capsule = decodeCapsule(*encoded, authenticationKey->bytes());
    if (!capsule.valid) return RecoveryResult::Blocked;
    if (journal.status == PendingJournal::Status::Valid &&
        (journal.transactionId != capsule.transactionId ||
         journal.original != capsule.original ||
         journal.candidate != capsule.candidate)) {
        return RecoveryResult::Blocked;
    }
    const auto currentSecret = credentials_.read(PairingAccount);
    if (currentSecret.status == SecureCredentialStore::ReadResult::Status::Error)
        return RecoveryResult::Blocked;
    const QJsonObject current = capture(settings_);
    if (!validState(current) ||
        !fieldsBelongToTransaction(current, capsule.original, capsule.candidate)) {
        return RecoveryResult::Blocked;
    }

    const bool committed = marker.has_value();
    const bool candidateSecretApplied = capsule.value
        ? sameSecret(currentSecret, capsule.value)
        : capsule.originalSecretPresent &&
            currentSecret.status == SecureCredentialStore::ReadResult::Status::NotFound;
    const bool candidateApplied = committed
        ? current == capsule.candidate && sameSecret(currentSecret, capsule.value)
        : capsule.secretTransition && candidateSecretApplied;
    if (committed && !candidateApplied)
        return RecoveryResult::Blocked;
    const QJsonObject& destination = candidateApplied
        ? capsule.candidate : capsule.original;
    if (!apply(settings_, destination))
        return RecoveryResult::Blocked;

    if (candidateApplied) {
        if (!commit()) return RecoveryResult::Blocked;
    } else {
        if (journal.status == PendingJournal::Status::Valid) {
            settings_.remove(QString::fromLatin1(JournalRoot));
            if (!durableSync(settings_)) return RecoveryResult::Blocked;
        }
        if (!credentials_.remove(CandidateCapsuleAccount))
            return RecoveryResult::Blocked;
    }
    return candidateApplied ? RecoveryResult::RecoveredCandidate
                            : RecoveryResult::RecoveredOriginal;
}
