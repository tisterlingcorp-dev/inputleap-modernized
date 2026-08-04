#include "UpdateHelperProtocol.h"
#include "RecoveryArtifactAuthenticator.h"

#include <QDateTime>
#include <QCoreApplication>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSaveFile>

#include <cmath>
#include <limits>
#include <utility>
#include <vector>

#if defined(Q_OS_WIN)
#include <fcntl.h>
#include <io.h>
#endif


#if defined(Q_OS_WIN)
#define NOMINMAX
#include <Windows.h>
#endif

namespace {
void setError(QString* error, const QString& value)
{
    if (error)
        *error = value;
}

QString hex(const QByteArray& value)
{
    return QString::fromLatin1(value.toHex());
}

std::optional<QByteArray> parseHash(const QJsonValue& value)
{
    if (!value.isString())
        return std::nullopt;
    const QByteArray encoded = value.toString().toLatin1();
    static const QRegularExpression expression(QStringLiteral("^[0-9a-f]{64}$"));
    if (!expression.match(QString::fromLatin1(encoded)).hasMatch())
        return std::nullopt;
    const QByteArray decoded = QByteArray::fromHex(encoded);
    return decoded.size() == 32 ? std::optional(decoded) : std::nullopt;
}

QString base64Url(const QByteArray& value)
{
    return QString::fromLatin1(value.toBase64(
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

bool pathContainsReparsePoint(const QString& path)
{
#if defined(Q_OS_WIN)
    QString current = QFileInfo(path).absoluteFilePath();
    while (!current.isEmpty()) {
        const DWORD attributes = GetFileAttributesW(
            reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(current).utf16()));
        if (attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            return true;
        const QString parent = QFileInfo(current).absolutePath();
        if (parent == current)
            break;
        current = parent;
    }
#else
    Q_UNUSED(path);
#endif
    return false;
}

#if defined(Q_OS_WIN)
class StagingDirectoryLock final
{
public:
    explicit StagingDirectoryLock(const QString& path)
    {
        const QString native = QDir::toNativeSeparators(path);
        handle_ = CreateFileW(reinterpret_cast<LPCWSTR>(native.utf16()),
                              FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                              nullptr);
        if (handle_ == INVALID_HANDLE_VALUE || pathContainsReparsePoint(path)) {
            if (handle_ != INVALID_HANDLE_VALUE)
                CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }

    ~StagingDirectoryLock()
    {
        if (handle_ != INVALID_HANDLE_VALUE)
            CloseHandle(handle_);
    }

    bool valid() const noexcept { return handle_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

bool writeAtomicFileHandleRelative(const QString& path, const QByteArray& payload)
{
    const QFileInfo target(path);
    const QString temporaryPath = QDir(target.absolutePath()).filePath(
        QStringLiteral(".%1.%2.tmp").arg(target.fileName(),
            QString::number(QCoreApplication::applicationPid())));
    const QString nativeTemporary = QDir::toNativeSeparators(temporaryPath);
    HANDLE temporary = CreateFileW(
        reinterpret_cast<LPCWSTR>(nativeTemporary.utf16()),
        GENERIC_WRITE | DELETE,
        FILE_SHARE_READ,
        nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (temporary == INVALID_HANDLE_VALUE) {
        return false;
    }
    BY_HANDLE_FILE_INFORMATION temporaryInfo{};
    if (!GetFileInformationByHandle(temporary, &temporaryInfo) ||
        (temporaryInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (temporaryInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        CloseHandle(temporary);
        DeleteFileW(reinterpret_cast<LPCWSTR>(nativeTemporary.utf16()));
        return false;
    }
    DWORD written = 0;
    const bool wrote = WriteFile(temporary, payload.constData(),
                                 DWORD(payload.size()), &written, nullptr) &&
        written == DWORD(payload.size()) && FlushFileBuffers(temporary) == TRUE;
    const QString nativeFinal = QDir::toNativeSeparators(path);
    const std::wstring finalWide = nativeFinal.toStdWString();
    const DWORD renameBytes = DWORD(sizeof(FILE_RENAME_INFO) +
                                     finalWide.size() * sizeof(wchar_t));
    std::vector<unsigned char> renameStorage(renameBytes);
    auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(renameStorage.data());
    rename->ReplaceIfExists = TRUE;
    rename->RootDirectory = nullptr;
    rename->FileNameLength = DWORD(finalWide.size() * sizeof(wchar_t));
    memcpy(rename->FileName, finalWide.data(), rename->FileNameLength);
    const bool renamed = wrote && SetFileInformationByHandle(
        temporary, FileRenameInfo, rename, renameBytes) == TRUE;
    CloseHandle(temporary);
    if (!renamed)
        DeleteFileW(reinterpret_cast<LPCWSTR>(nativeTemporary.utf16()));
    return renamed;
}

bool openNewResultFileWithoutReparse(const QString& path, QFile& file)
{
    const QString native = QDir::toNativeSeparators(path);
    HANDLE handle = CreateFileW(
        reinterpret_cast<LPCWSTR>(native.utf16()),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        return false;
    const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(handle), _O_RDWR | _O_BINARY);
    if (fd == -1) {
        CloseHandle(handle);
        return false;
    }
    if (!file.open(fd, QIODevice::ReadWrite)) {
        _close(fd);
        return false;
    }
    return true;
}
#endif

std::optional<QByteArray> parseBase64Url(const QJsonValue& value)
{
    if (!value.isString())
        return std::nullopt;
    const QByteArray encoded = value.toString().toLatin1();
    static const QRegularExpression expression(QStringLiteral("^[A-Za-z0-9_-]+$"));
    if (!expression.match(QString::fromLatin1(encoded)).hasMatch())
        return std::nullopt;
    const QByteArray decoded = QByteArray::fromBase64(
        encoded, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    if (decoded.isEmpty() || base64Url(decoded).toLatin1() != encoded)
        return std::nullopt;
    return decoded;
}

bool safeAbsolutePath(const QString& value)
{
    if (value.isEmpty() || value.size() > 32767 ||
        value.contains(QLatin1Char('\0')) || value.contains(QLatin1Char('\r')) ||
        value.contains(QLatin1Char('\n'))) {
        return false;
    }
    const QFileInfo information(value);
    return information.isAbsolute() && QDir::cleanPath(value) == value;
}

std::optional<quint64> unsignedInteger(const QJsonValue& value, quint64 maximum)
{
    if (!value.isDouble())
        return std::nullopt;
    const double number = value.toDouble(-1);
    if (!std::isfinite(number) || number < 0 || std::floor(number) != number ||
        number > double(maximum)) {
        return std::nullopt;
    }
    return quint64(number);
}

QString outcomeName(UpdateInstallPolicy::MsiOutcome outcome)
{
    switch (outcome) {
    case UpdateInstallPolicy::MsiOutcome::Installing:
        return QStringLiteral("installing");
    case UpdateInstallPolicy::MsiOutcome::Success:
        return QStringLiteral("success");
    case UpdateInstallPolicy::MsiOutcome::SuccessRestartRequired:
        return QStringLiteral("success-restart-required");
    case UpdateInstallPolicy::MsiOutcome::Cancelled:
        return QStringLiteral("cancelled");
    case UpdateInstallPolicy::MsiOutcome::FailedBeforeInstall:
        return QStringLiteral("failed-before-install");
    case UpdateInstallPolicy::MsiOutcome::Failed:
        return QStringLiteral("failed");

    }
    return QStringLiteral("failed");
}

std::optional<UpdateInstallPolicy::MsiOutcome> parseOutcome(const QJsonValue& value)
{
    if (!value.isString()) return std::nullopt;
    const QString name = value.toString();
    for (const auto outcome : {
             UpdateInstallPolicy::MsiOutcome::Installing,
             UpdateInstallPolicy::MsiOutcome::Success,
             UpdateInstallPolicy::MsiOutcome::SuccessRestartRequired,
             UpdateInstallPolicy::MsiOutcome::Cancelled,
             UpdateInstallPolicy::MsiOutcome::FailedBeforeInstall,
             UpdateInstallPolicy::MsiOutcome::Failed}) {
        if (outcomeName(outcome) == name) return outcome;
    }
    return std::nullopt;
}

QByteArray resultAuthenticationTag(const UpdateHelperResult& result,
                                   QByteArrayView authenticationKey)
{
    const QByteArray domain = QByteArrayLiteral("inputleap-update-result-v1");
    const QByteArray outcome = outcomeName(result.outcome).toUtf8();
    const QByteArray exitCode = QByteArray::number(result.msiExitCode);
    const QByteArray relaunched(1, result.relaunchVerified ? '\1' : '\0');
    const QByteArray version = result.version.toUtf8();
    const QByteArray completed = result.completedAtUtc.toUTC().toString(
        QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")).toLatin1();
    return RecoveryArtifactAuthenticator::authenticate(
        authenticationKey, QByteArrayView(domain),
        {QByteArrayView(outcome), QByteArrayView(exitCode),
         QByteArrayView(relaunched), QByteArrayView(result.nonce),
         QByteArrayView(version), QByteArrayView(result.msiSha256),
         QByteArrayView(completed)});
}
}

QString UpdateHelperProtocol::installMutexName()
{
    return QStringLiteral("Global\\InputLeapUpdateInstallV1");
}

QString UpdateHelperProtocol::suppressAutomaticStartArgument()
{
    return QStringLiteral("--no-autostart-once");
}

QString UpdateHelperProtocol::resultAuthenticationAccount()
{
    return QStringLiteral("InputLeap/secure-update/result-auth-key");
}

QByteArray UpdateHelperProtocol::serializeInstruction(
    const UpdateHelperInstruction& instruction)
{
    const QJsonObject object{
        {QStringLiteral("appPath"), instruction.appPath},
        {QStringLiteral("appSha256"), hex(instruction.appSha256)},
        {QStringLiteral("manifestEnvelope"), base64Url(instruction.manifestEnvelope)},
        {QStringLiteral("msiPath"), instruction.msiPath},
        {QStringLiteral("msiSha256"), hex(instruction.msiSha256)},
        {QStringLiteral("msiSize"), qint64(instruction.msiSize)},
        {QStringLiteral("parentPath"), instruction.parentPath},
        {QStringLiteral("parentPid"), qint64(instruction.parentPid)},
        {QStringLiteral("parentSha256"), hex(instruction.parentSha256)},
        {QStringLiteral("readyNonce"), base64Url(instruction.readyNonce)},
        {QStringLiteral("readyPath"), instruction.readyPath},
        {QStringLiteral("resultPath"), instruction.resultPath},
        {QStringLiteral("schema"), 1},
    };
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

std::optional<UpdateHelperInstruction> UpdateHelperProtocol::parseInstruction(
    const QByteArray& encoded, QString* error)
{
    if (encoded.isEmpty() || encoded.size() > MaxInstructionBytes) {
        setError(error, QStringLiteral("instruction size is invalid"));
        return std::nullopt;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(encoded, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject() ||
        document.toJson(QJsonDocument::Compact) != encoded) {
        setError(error, QStringLiteral("instruction is not canonical JSON"));
        return std::nullopt;
    }
    const QJsonObject object = document.object();
    if (object.size() != 13 || object.value(QStringLiteral("schema")).toInt(-1) != 1) {
        setError(error, QStringLiteral("instruction schema is unsupported"));
        return std::nullopt;
    }
    const auto parentPid = unsignedInteger(object.value(QStringLiteral("parentPid")),
                                            std::numeric_limits<quint32>::max());
    const auto msiSize = unsignedInteger(object.value(QStringLiteral("msiSize")),
                                          UpdateService::MaxPackageBytes);
    const auto parentHash = parseHash(object.value(QStringLiteral("parentSha256")));
    const auto msiHash = parseHash(object.value(QStringLiteral("msiSha256")));
    const auto appHash = parseHash(object.value(QStringLiteral("appSha256")));
    const auto envelope = parseBase64Url(object.value(QStringLiteral("manifestEnvelope")));
    const auto readyNonce = parseBase64Url(object.value(QStringLiteral("readyNonce")));
    if (!parentPid || *parentPid == 0 || !msiSize || *msiSize == 0 ||
        !parentHash || !msiHash || !appHash || !envelope || !readyNonce ||
        readyNonce->size() != 16 ||
        envelope->size() > UpdateService::MaxEnvelopeBytes) {
        setError(error, QStringLiteral("instruction values are invalid"));
        return std::nullopt;
    }

    UpdateHelperInstruction instruction;
    instruction.parentPid = quint32(*parentPid);
    instruction.parentPath = object.value(QStringLiteral("parentPath")).toString();
    instruction.parentSha256 = *parentHash;
    instruction.msiPath = object.value(QStringLiteral("msiPath")).toString();
    instruction.msiSize = *msiSize;
    instruction.msiSha256 = *msiHash;
    instruction.appPath = object.value(QStringLiteral("appPath")).toString();
    instruction.appSha256 = *appHash;
    instruction.resultPath = object.value(QStringLiteral("resultPath")).toString();
    instruction.readyPath = object.value(QStringLiteral("readyPath")).toString();
    instruction.readyNonce = *readyNonce;
    instruction.manifestEnvelope = *envelope;
    if (!safeAbsolutePath(instruction.parentPath) ||
        !safeAbsolutePath(instruction.msiPath) ||
        !safeAbsolutePath(instruction.appPath) ||
        !safeAbsolutePath(instruction.resultPath) ||
        !safeAbsolutePath(instruction.readyPath) ||
        !instruction.msiPath.endsWith(QStringLiteral(".msi"), Qt::CaseInsensitive) ||
        !instruction.resultPath.endsWith(QStringLiteral(".result.json"), Qt::CaseInsensitive) ||
        !instruction.readyPath.endsWith(QStringLiteral(".ready.json"), Qt::CaseInsensitive) ||
        QFileInfo(instruction.msiPath).absolutePath() !=
            QFileInfo(instruction.resultPath).absolutePath() ||
        QFileInfo(instruction.msiPath).absolutePath() !=
            QFileInfo(instruction.readyPath).absolutePath()) {
        setError(error, QStringLiteral("instruction paths are invalid"));
        return std::nullopt;
    }
    return instruction;
}

QByteArray UpdateHelperProtocol::serializeResult(
    UpdateInstallPolicy::MsiOutcome outcome, quint32 exitCode,
    bool relaunchVerified, const QByteArray& nonce,
    const QString& version, const QByteArray& msiSha256,
    QByteArrayView authenticationKey, QDateTime completedAtUtc)
{
    UpdateHelperResult result;
    result.outcome = outcome;
    result.msiExitCode = exitCode;
    result.relaunchVerified = relaunchVerified;
    result.nonce = nonce;
    result.version = version;
    result.msiSha256 = msiSha256;
    result.completedAtUtc = completedAtUtc.isValid()
        ? completedAtUtc.toUTC() : QDateTime::currentDateTimeUtc();
    if (!authenticationKey.isEmpty())
        result.authenticationTag = resultAuthenticationTag(result, authenticationKey);
    QJsonObject object{
        {QStringLiteral("completedAtUtc"), result.completedAtUtc.toString(
             QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'"))},
        {QStringLiteral("msiExitCode"), qint64(exitCode)},
        {QStringLiteral("msiSha256"), hex(msiSha256)},
        {QStringLiteral("nonce"), base64Url(nonce)},
        {QStringLiteral("outcome"), outcomeName(outcome)},
        {QStringLiteral("relaunchVerified"), relaunchVerified},
        {QStringLiteral("schema"), result.authenticationTag.isEmpty() ? 1 : 2},
        {QStringLiteral("version"), version},
    };
    if (!result.authenticationTag.isEmpty())
        object.insert(QStringLiteral("authenticationTag"),
                      base64Url(result.authenticationTag));
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

std::optional<UpdateHelperResult> UpdateHelperProtocol::parseResult(
    const QByteArray& encoded, QString* error)
{
    if (encoded.isEmpty() || encoded.size() > MaxResultBytes) {
        setError(error, QStringLiteral("result size is invalid"));
        return std::nullopt;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(encoded, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject() ||
        document.toJson(QJsonDocument::Compact) != encoded) {
        setError(error, QStringLiteral("result is not canonical JSON"));
        return std::nullopt;
    }
    const QJsonObject object = document.object();
    const int schema = object.value(QStringLiteral("schema")).toInt(-1);
    const auto authenticationTag = schema == 2
        ? parseBase64Url(object.value(QStringLiteral("authenticationTag")))
        : std::optional<QByteArray>{};
    const auto outcome = parseOutcome(object.value(QStringLiteral("outcome")));
    const auto exitCode = unsignedInteger(
        object.value(QStringLiteral("msiExitCode")),
        std::numeric_limits<quint32>::max());
    const auto nonce = parseBase64Url(object.value(QStringLiteral("nonce")));
    const auto msiSha256 = parseHash(object.value(QStringLiteral("msiSha256")));
    const QString completed = object.value(QStringLiteral("completedAtUtc")).toString();
    const QDateTime completedAt = QDateTime::fromString(
        completed, QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'"));
    const QString version = object.value(QStringLiteral("version")).toString();
    if ((schema != 1 && schema != 2) ||
        object.size() != (schema == 2 ? 9 : 8) ||
        !outcome || !exitCode || !nonce || nonce->size() != 16 || !msiSha256 ||
        (schema == 2 && (!authenticationTag || authenticationTag->size() != 32)) ||
        !object.value(QStringLiteral("relaunchVerified")).isBool() ||
        completed.size() != 20 || !completedAt.isValid() ||
        version.isEmpty() || version.size() > 128 ||
        version.contains(QLatin1Char('\0')) || version.contains(QLatin1Char('\r')) ||
        version.contains(QLatin1Char('\n'))) {
        setError(error, QStringLiteral("result values are invalid"));
        return std::nullopt;
    }
    const bool outcomeMatchesExitCode =
        *outcome == UpdateInstallPolicy::MsiOutcome::Installing ||
        *outcome == UpdateInstallPolicy::MsiOutcome::FailedBeforeInstall
            ? *exitCode == std::numeric_limits<quint32>::max()
            : *outcome == UpdateInstallPolicy::classifyMsiExitCode(quint32(*exitCode));
    if (!outcomeMatchesExitCode) {
        setError(error, QStringLiteral("result outcome does not match MSI exit code"));
        return std::nullopt;
    }
    UpdateHelperResult result;
    result.outcome = *outcome;
    result.msiExitCode = quint32(*exitCode);
    result.relaunchVerified = object.value(QStringLiteral("relaunchVerified")).toBool();
    result.nonce = *nonce;
    result.version = version;
    result.msiSha256 = *msiSha256;
    result.completedAtUtc = completedAt;
    result.completedAtUtc.setTimeSpec(Qt::UTC);
    if (authenticationTag)
        result.authenticationTag = *authenticationTag;
    return result;
}

bool UpdateHelperProtocol::verifyResultAuthentication(
    const UpdateHelperResult& result, QByteArrayView authenticationKey)
{
    const QByteArray actual = resultAuthenticationTag(result, authenticationKey);
    return actual.size() == result.authenticationTag.size() &&
        !actual.isEmpty() &&
        CRYPTO_memcmp(actual.constData(), result.authenticationTag.constData(),
                      static_cast<size_t>(actual.size())) == 0;
}

UpdateHelperEngine::UpdateHelperEngine(
    EnvelopeVerifier verifier, SensitiveBytes resultAuthenticationKey)
    : verifier_(std::move(verifier)),
      resultAuthenticationKey_(std::move(resultAuthenticationKey))
{
}

bool UpdateHelperEngine::execute(const QByteArray& encodedInstruction,
                                 const QString& helperPath,
                                 UpdateHelperAdapter& adapter,
                                 QString* error) const
{
    const auto instruction = UpdateHelperProtocol::parseInstruction(encodedInstruction, error);
    if (!instruction || !verifier_ || !safeAbsolutePath(helperPath))
        return false;

    const QFileInfo helperInfo(helperPath);
    const QFileInfo parentInfo(instruction->parentPath);
    const QFileInfo appInfo(instruction->appPath);
    const QFileInfo msiInfo(instruction->msiPath);
    const QString helperDirectory = helperInfo.canonicalPath();
    if (helperDirectory.isEmpty() || helperDirectory != msiInfo.canonicalPath() ||
        parentInfo.canonicalPath() != appInfo.canonicalPath() ||
        parentInfo.canonicalFilePath() != appInfo.canonicalFilePath()) {
        setError(error, QStringLiteral("helper and application paths are not bound"));
        return false;
    }

    const UpdateService::Result verification = verifier_(instruction->manifestEnvelope);
    if (verification.error != UpdateService::Error::None || !verification.release ||
        !verification.release->installable ||
        verification.release->packageType != UpdateService::PackageType::WindowsMsi ||
        verification.release->size != instruction->msiSize ||
        verification.release->sha256 != instruction->msiSha256) {
        setError(error, QStringLiteral("signed update authorization is invalid"));
        return false;
    }
    if (!adapter.bindExactParent(instruction->parentPid, instruction->parentPath,
                                 instruction->parentSha256)) {
        setError(error, QStringLiteral("parent process identity was not verified"));
        return false;
    }
#if defined(Q_OS_WIN)
    StagingDirectoryLock stagingLock(QFileInfo(instruction->resultPath).absolutePath());
    if (!stagingLock.valid()) {
        setError(error, QStringLiteral("staging namespace could not be locked"));
        return false;
    }
#endif
    if (pathContainsReparsePoint(instruction->resultPath) ||
        pathContainsReparsePoint(instruction->readyPath)) {
        setError(error, QStringLiteral("staging namespace is not reparse-safe"));
        return false;
    }
    QFile resultChannel;
    resultChannel.setFileName(instruction->resultPath);
#if defined(Q_OS_WIN)
    const bool resultChannelOpened = openNewResultFileWithoutReparse(
        instruction->resultPath, resultChannel);
#else
    const bool resultChannelOpened =
        resultChannel.open(QIODevice::ReadWrite | QIODevice::NewOnly);
#endif
    if (!resultChannelOpened) {
        setError(error, QStringLiteral("installation result channel could not be reserved"));
        return false;
    }
    const QByteArray installingResult = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::Installing,
        std::numeric_limits<quint32>::max(), false, instruction->readyNonce,
        verification.release->version, instruction->msiSha256,
        resultAuthenticationKey_.bytes());
    if (resultChannel.write(installingResult) != installingResult.size() ||
        !resultChannel.flush()) {
        setError(error, QStringLiteral("installation progress result could not be committed"));
        return false;
    }
    const auto persistResult = [&](UpdateInstallPolicy::MsiOutcome outcome,
                                   quint32 exitCode, bool relaunched) {
        const QByteArray result = UpdateHelperProtocol::serializeResult(
            outcome, exitCode, relaunched, instruction->readyNonce,
            verification.release->version, instruction->msiSha256,
            resultAuthenticationKey_.bytes());
        return resultChannel.seek(0) &&
               resultChannel.write(result) == result.size() &&
               resultChannel.resize(result.size()) && resultChannel.flush();
    };
    const QByteArray ready = QJsonDocument(QJsonObject{
        {QStringLiteral("nonce"), base64Url(instruction->readyNonce)},
        {QStringLiteral("schema"), 1},
    }).toJson(QJsonDocument::Compact);
    if (pathContainsReparsePoint(instruction->readyPath)) {
        setError(error, QStringLiteral("ready channel namespace is not reparse-safe"));
        return false;
    }
    bool readyPublished = false;
#if defined(Q_OS_WIN)
    readyPublished = writeAtomicFileHandleRelative(instruction->readyPath, ready);
#else
    QFile::remove(instruction->readyPath);
    QSaveFile readyFile(instruction->readyPath);
    readyPublished = readyFile.open(QIODevice::WriteOnly) &&
        readyFile.write(ready) == ready.size() && readyFile.commit();
    if (!readyPublished)
        readyFile.cancelWriting();
#endif
    if (!readyPublished) {
        const bool persisted = persistResult(
            UpdateInstallPolicy::MsiOutcome::FailedBeforeInstall,
            std::numeric_limits<quint32>::max(), false);
        setError(error, persisted
            ? QStringLiteral("parent handshake could not be persisted")
            : QStringLiteral("parent handshake failure result could not be committed"));
        return false;
    }
    if (!adapter.waitForBoundParent()) {
        QFile::remove(instruction->readyPath);
        const bool persisted = persistResult(
            UpdateInstallPolicy::MsiOutcome::FailedBeforeInstall,
            std::numeric_limits<quint32>::max(), false);
        setError(error, persisted
            ? QStringLiteral("bound parent process did not stop")
            : QStringLiteral("parent wait failure result could not be committed"));
        return false;
    }
    QFile::remove(instruction->readyPath);
    const auto failBeforeInstall = [&](const QString& detail) {
        if (!persistResult(UpdateInstallPolicy::MsiOutcome::FailedBeforeInstall,
                           std::numeric_limits<quint32>::max(), false)) {
            setError(error, QStringLiteral(
                "pre-install failure result could not be committed before relaunch"));
            return false;
        }
        const bool relaunched = adapter.relaunchAndVerify(
            instruction->appPath, instruction->appSha256, true, true);
        const bool persisted = persistResult(
            UpdateInstallPolicy::MsiOutcome::FailedBeforeInstall,
            std::numeric_limits<quint32>::max(), relaunched);
        setError(error, !persisted
            ? QStringLiteral("pre-install failure result could not be committed")
            : (!relaunched
                ? QStringLiteral("pre-install failure could not relaunch the application")
                : detail));
        return false;
    };
    if (!adapter.verifyMsi(instruction->msiPath, *verification.release)) {
        return failBeforeInstall(QStringLiteral("MSI changed before installation"));
    }
    // Revalidate immediately before handing the path to Windows Installer.
    // The first verification occurs before the parent handshake and cannot
    // cover a replacement during that wait.
    if (!adapter.verifyMsi(instruction->msiPath, *verification.release)) {
        return failBeforeInstall(QStringLiteral("MSI changed immediately before installation"));
    }
    const auto exitCode = adapter.installMsi(instruction->msiPath);
    if (!exitCode) {
        return failBeforeInstall(QStringLiteral("Windows Installer could not be launched"));
    }
    auto outcome = UpdateInstallPolicy::classifyMsiExitCode(*exitCode);
    const bool success = UpdateInstallPolicy::transactionCompleted(outcome);
    if (!persistResult(outcome, *exitCode, false)) {
        setError(error, QStringLiteral(
            "installation result could not be committed before relaunch"));
        return false;
    }
    const bool relaunched = adapter.relaunchAndVerify(
        instruction->appPath, instruction->appSha256, !success, true);
    if (success) {
        if (!relaunched) {
            setError(error, QStringLiteral("updated application could not be launched"));
            return false;
        }
        // Only the relaunched GUI can attest its compiled version.  Leave the
        // preliminary result unconfirmed for that process to consume.
        return true;
    }
    if (!persistResult(outcome, *exitCode, relaunched)) {
        setError(error, QStringLiteral("installation result could not be persisted"));
        return false;
    }
    if (!relaunched) {
        setError(error, QStringLiteral("application relaunch could not be verified"));
        return false;
    }
    return true;
}
