#include "UpdateHelperProtocol.h"
#include "RecoveryArtifactAuthenticator.h"
#include "UpdateTrustConfig.h"
#include "WindowsAuthenticodeVerifier.h"
#include "WindowsStagedPackageGuard.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>

#if defined(Q_OS_WIN)
#define NOMINMAX
#include <Windows.h>
#include <shellapi.h>

#include <optional>
#include <vector>

namespace {
constexpr DWORD kInstallerTimeoutMs = 30u * 60u * 1000u;

QByteArray fileSha256(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return {};
    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!file.atEnd()) {
        const QByteArray chunk = file.read(64 * 1024);
        if (chunk.isEmpty() && !file.atEnd())
            return {};
        hash.addData(chunk);
    }
    return hash.result();
}

QString processPath(HANDLE process)
{
    std::vector<wchar_t> buffer(512);
    while (buffer.size() <= 32768) {
        DWORD size = DWORD(buffer.size());
        if (QueryFullProcessImageNameW(process, 0, buffer.data(), &size))
            return QString::fromWCharArray(buffer.data(), int(size));
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            return {};
        buffer.resize(buffer.size() * 2);
    }
    return {};
}

std::vector<BYTE> processUserSid(HANDLE process)
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token))
        return {};
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    const bool ok = size > 0 && GetTokenInformation(
        token, TokenUser, buffer.data(), size, &size);
    CloseHandle(token);
    return ok ? buffer : std::vector<BYTE>{};
}

bool sameUser(HANDLE process)
{
    const auto left = processUserSid(process);
    const auto right = processUserSid(GetCurrentProcess());
    if (left.empty() || right.empty())
        return false;
    const auto* leftUser = reinterpret_cast<const TOKEN_USER*>(left.data());
    const auto* rightUser = reinterpret_cast<const TOKEN_USER*>(right.data());
    return EqualSid(leftUser->User.Sid, rightUser->User.Sid) != FALSE;
}

bool sameCanonicalPath(const QString& left, const QString& right)
{
    const QString canonicalLeft = QFileInfo(left).canonicalFilePath();
    const QString canonicalRight = QFileInfo(right).canonicalFilePath();
    return !canonicalLeft.isEmpty() &&
           canonicalLeft.compare(canonicalRight, Qt::CaseInsensitive) == 0;
}

bool isReparsePoint(const QString& path)
{
    const DWORD attributes = GetFileAttributesW(
        reinterpret_cast<LPCWSTR>(path.utf16()));
    return attributes == INVALID_FILE_ATTRIBUTES ||
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

bool pathContainsReparsePoint(const QString& path)
{
    QString current = QFileInfo(path).absoluteFilePath();
    if (current.isEmpty()) return true;
    for (;;) {
        if (isReparsePoint(current)) return true;
        const QString parent = QFileInfo(current).dir().absolutePath();
        if (parent == current) return false;
        current = parent;
    }
}

QString quoteArgument(const QString& value)
{
    QString escaped = value;
    escaped.replace(QLatin1Char('"'), QStringLiteral("\\\""));
    return QStringLiteral("\"") + escaped + QStringLiteral("\"");
}

class WindowsUpdateHelperAdapter final : public UpdateHelperAdapter
{
public:
    ~WindowsUpdateHelperAdapter() override
    {
        if (parentProcess_) CloseHandle(parentProcess_);
        if (installMutex_) {
            if (installMutexOwned_) ReleaseMutex(installMutex_);
            CloseHandle(installMutex_);
        }
    }

    bool bindExactParent(quint32 pid, const QString& path,
                         const QByteArray& sha256) override
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                     FALSE, DWORD(pid));
        if (!process)
            return false;
        const bool verified = sameUser(process) &&
            sameCanonicalPath(processPath(process), path) &&
            fileSha256(path) == sha256;
        if (!verified) {
            CloseHandle(process);
            return false;
        }
        const QString mutexName = UpdateHelperProtocol::installMutexName();
        HANDLE installMutex = OpenMutexW(
            SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE,
            reinterpret_cast<LPCWSTR>(mutexName.utf16()));
        if (!installMutex) {
            CloseHandle(process);
            return false;
        }
        parentProcess_ = process;
        installMutex_ = installMutex;
        return true;
    }

    bool waitForBoundParent() override
    {
        if (!parentProcess_) return false;
        const DWORD wait = WaitForSingleObject(parentProcess_, 120000);
        CloseHandle(parentProcess_);
        parentProcess_ = nullptr;
        if (wait != WAIT_OBJECT_0 || !installMutex_) return false;
        const DWORD mutexWait = WaitForSingleObject(installMutex_, 10000);
        installMutexOwned_ = mutexWait == WAIT_OBJECT_0 || mutexWait == WAIT_ABANDONED;
        return installMutexOwned_;
    }

    bool verifyMsi(const QString& path,
                   const UpdateService::Release& release) override
    {
        releaseMsiLock();
        if (pathContainsReparsePoint(path)) return false;
        if (!msiGuard_.lock(path)) {
            return false;
        }
        lockedMsiPath_ = QFileInfo(path).canonicalFilePath();
        if (lockedMsiPath_.isEmpty() ||
            !UpdateInstallPolicy::verifyStagedPackage(path, release) ||
            !WindowsAuthenticode::verifyPinnedPublisher(
                path, release.authenticodeSignerSha256)) {
            releaseMsiLock();
            return false;
        }
        return true;
    }

    std::optional<quint32> installMsi(const QString& path) override
    {
        if (!msiGuard_.isLocked() ||
            !sameCanonicalPath(lockedMsiPath_, path) ||
            !msiGuard_.revalidatePath()) {
            releaseMsiLock();
            return std::nullopt;
        }
        wchar_t systemDirectory[MAX_PATH + 1]{};
        const UINT length = GetSystemDirectoryW(systemDirectory, MAX_PATH);
        if (length == 0 || length > MAX_PATH) {
            releaseMsiLock();
            return std::nullopt;
        }
        const QString executable = QDir(QString::fromWCharArray(systemDirectory))
                                       .filePath(QStringLiteral("msiexec.exe"));
        const QString parameters = QStringLiteral("/i %1 /passive /norestart")
                                       .arg(quoteArgument(path));
        SHELLEXECUTEINFOW execution{};
        execution.cbSize = sizeof(execution);
        execution.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        execution.lpVerb = L"runas";
        execution.lpFile = reinterpret_cast<LPCWSTR>(executable.utf16());
        execution.lpParameters = reinterpret_cast<LPCWSTR>(parameters.utf16());
        execution.nShow = SW_SHOWNORMAL;
        if (!ShellExecuteExW(&execution) || !execution.hProcess) {
            releaseMsiLock();
            return std::nullopt;
        }
        // Never report a pre-install failure while an elevated Windows
        // Installer process may still be active. Keep every lock until a
        // terminal process exit code exists, but do not allow a hung or
        // interactive msiexec to hold the update transaction forever.
        const DWORD wait = WaitForSingleObject(execution.hProcess,
                                               kInstallerTimeoutMs);
        if (wait == WAIT_TIMEOUT) {
            TerminateProcess(execution.hProcess, ERROR_TIMEOUT);
            WaitForSingleObject(execution.hProcess, 10000);
            CloseHandle(execution.hProcess);
            releaseMsiLock();
            return std::nullopt;
        }
        DWORD exitCode = 0;
        const bool ok = wait == WAIT_OBJECT_0 &&
                        GetExitCodeProcess(execution.hProcess, &exitCode);
        CloseHandle(execution.hProcess);
        releaseMsiLock();
        return ok ? std::optional<quint32>(exitCode) : std::nullopt;
    }

    bool relaunchAndVerify(const QString& appPath,
                           const QByteArray& expectedSha256,
                           bool requireExpectedHash,
                           bool suppressAutomaticStart) override
    {
        if (pathContainsReparsePoint(appPath) ||
            (requireExpectedHash && fileSha256(appPath) != expectedSha256)) {
            return false;
        }
        QString command = quoteArgument(appPath);
        if (suppressAutomaticStart)
            command.append(QLatin1Char(' ') +
                           UpdateHelperProtocol::suppressAutomaticStartArgument());
        std::vector<wchar_t> mutableCommand(size_t(command.size()) + 1);
        command.toWCharArray(mutableCommand.data());
        mutableCommand[size_t(command.size())] = L'\0';
        const QString workingDirectory = QFileInfo(appPath).absolutePath();
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        if (!CreateProcessW(reinterpret_cast<LPCWSTR>(appPath.utf16()),
                            mutableCommand.data(), nullptr, nullptr, FALSE,
                            CREATE_NEW_PROCESS_GROUP, nullptr,
                            reinterpret_cast<LPCWSTR>(workingDirectory.utf16()),
                            &startup, &process)) {
            return false;
        }
        const bool verified = sameCanonicalPath(processPath(process.hProcess), appPath);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return verified;
    }

private:
    void releaseMsiLock()
    {
        msiGuard_.release();
        lockedMsiPath_.clear();
    }

    HANDLE parentProcess_ = nullptr;
    WindowsStagedPackageGuard msiGuard_;
    HANDLE installMutex_ = nullptr;
    bool installMutexOwned_ = false;
    QString lockedMsiPath_;
};
}

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    const QStringList arguments = application.arguments();
    if (arguments.size() != 3 || arguments.at(1) != QStringLiteral("--instruction"))
        return 2;
    const QString instructionPath = QDir::cleanPath(arguments.at(2));
    const QFileInfo instructionInfo(instructionPath);
    if (!instructionInfo.isAbsolute() || pathContainsReparsePoint(instructionPath) ||
        instructionInfo.size() < 1 ||
        instructionInfo.size() > UpdateHelperProtocol::MaxInstructionBytes) {
        return 2;
    }
    QFile instructionFile(instructionPath);
    if (!instructionFile.open(QIODevice::ReadOnly))
        return 2;
    const QByteArray instruction = instructionFile.readAll();
    instructionFile.close();
    QFile::remove(instructionPath);

    const UpdateTrustConfig trust = UpdateTrustConfig::production();
    SecureCredentialStore credentialStore;
    auto resultAuthenticationKey = RecoveryArtifactAuthenticator::loadKey(
        credentialStore, UpdateHelperProtocol::resultAuthenticationAccount());
    if (!resultAuthenticationKey)
        return 3;
    UpdateHelperEngine engine([trust](const QByteArray& envelope) {
        return UpdateService::evaluate(
            envelope, trust.manifestUrl, QStringLiteral(INPUTLEAP_VERSION),
            trust.trustedKeys, QDateTime::currentDateTimeUtc(),
            trust.minimumValidSignatures);
    }, std::move(*resultAuthenticationKey));
    WindowsUpdateHelperAdapter adapter;
    QString error;
    return engine.execute(instruction, QCoreApplication::applicationFilePath(),
                          adapter, &error) ? 0 : 3;
}
#else
int main()
{
    return 1;
}
#endif
