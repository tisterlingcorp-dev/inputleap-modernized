#include "ipc/IpcPeerProcessAuth.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <wtsapi32.h>
#include <cwchar>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wtsapi32.lib")
#endif

#include <system_error>
#include <vector>

namespace inputleap {
namespace {

bool equalPathComponent(const std::filesystem::path& left,
                        const std::filesystem::path& right)
{
#ifdef _WIN32
    return _wcsicmp(left.native().c_str(), right.native().c_str()) == 0;
#else
    return left == right;
#endif
}

#ifdef _WIN32
std::optional<std::vector<std::uint8_t>> tokenUserSid(HANDLE process)
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        return std::nullopt;
    }

    DWORD bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes == 0) {
        CloseHandle(token);
        return std::nullopt;
    }

    std::vector<std::uint8_t> storage(bytes);
    if (!GetTokenInformation(token, TokenUser, storage.data(), bytes, &bytes)) {
        CloseHandle(token);
        return std::nullopt;
    }
    CloseHandle(token);

    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(storage.data());
    if (!IsValidSid(tokenUser->User.Sid)) {
        return std::nullopt;
    }
    const DWORD sidBytes = GetLengthSid(tokenUser->User.Sid);
    std::vector<std::uint8_t> sid(sidBytes);
    if (!CopySid(sidBytes, sid.data(), tokenUser->User.Sid)) {
        return std::nullopt;
    }
    return sid;
}

std::optional<std::vector<std::uint8_t>> accountSidForSession(DWORD sessionId)
{
    LPWSTR user = nullptr;
    LPWSTR domain = nullptr;
    DWORD userBytes = 0;
    DWORD domainBytes = 0;
    const BOOL queriedUser = WTSQuerySessionInformationW(
        WTS_CURRENT_SERVER_HANDLE, sessionId, WTSUserName, &user, &userBytes);
    const BOOL queriedDomain = WTSQuerySessionInformationW(
        WTS_CURRENT_SERVER_HANDLE, sessionId, WTSDomainName, &domain, &domainBytes);
    const auto releaseNames = [&] {
        if (user != nullptr) WTSFreeMemory(user);
        if (domain != nullptr) WTSFreeMemory(domain);
    };
    if (!queriedUser || !queriedDomain || user == nullptr || *user == L'\0') {
        releaseNames();
        return std::nullopt;
    }

    std::wstring account;
    if (domain != nullptr && *domain != L'\0') {
        account.assign(domain);
        account.push_back(L'\\');
    }
    account.append(user);
    releaseNames();

    DWORD sidBytes = 0;
    DWORD resolvedDomainChars = 0;
    SID_NAME_USE sidUse{};
    LookupAccountNameW(nullptr, account.c_str(), nullptr, &sidBytes,
                       nullptr, &resolvedDomainChars, &sidUse);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || sidBytes == 0) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> sid(sidBytes);
    std::vector<wchar_t> resolvedDomain(resolvedDomainChars);
    if (!LookupAccountNameW(
            nullptr, account.c_str(), sid.data(), &sidBytes,
            resolvedDomain.data(), &resolvedDomainChars, &sidUse) ||
        !IsValidSid(sid.data())) {
        return std::nullopt;
    }
    sid.resize(sidBytes);
    return sid;
}

std::optional<std::vector<std::uint8_t>> localSystemSid()
{
    DWORD sidBytes = SECURITY_MAX_SID_SIZE;
    std::vector<std::uint8_t> sid(sidBytes);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, sid.data(), &sidBytes)) {
        return std::nullopt;
    }
    sid.resize(sidBytes);
    return sid;
}
#endif

} // namespace

EIpcClientType IpcPeerProcessAuth::classifyExecutable(
    const std::filesystem::path& peerExecutable,
    const std::filesystem::path& daemonExecutable)
{
    if (!peerExecutable.is_absolute() || !daemonExecutable.is_absolute()) {
        return kIpcClientUnknown;
    }

    std::error_code error;
    const auto daemon = std::filesystem::canonical(daemonExecutable, error);
    if (error) {
        return kIpcClientUnknown;
    }
    const auto peer = std::filesystem::canonical(peerExecutable, error);
    if (error || !equalPathComponent(peer.parent_path(), daemon.parent_path())) {
        return kIpcClientUnknown;
    }

    const auto filename = peer.filename();
    if (equalPathComponent(filename, L"input-leap.exe") ||
        equalPathComponent(filename, L"input-leap-tauri.exe")) {
        return kIpcClientGui;
    }
    if (equalPathComponent(filename, L"input-leapc.exe") ||
        equalPathComponent(filename, L"input-leaps.exe")) {
        return kIpcClientNode;
    }
    return kIpcClientUnknown;
}

bool IpcPeerProcessAuth::isAuthorizedWindowsIdentity(
    EIpcClientType type,
    std::uint32_t peerSessionId,
    const std::vector<std::uint8_t>& peerUserSid,
    std::uint32_t activeSessionId,
    const std::vector<std::uint8_t>& activeUserSid,
    const std::vector<std::uint8_t>& localSystemSid)
{
    if (peerSessionId != activeSessionId || peerUserSid.empty() ||
        activeUserSid.empty() || localSystemSid.empty()) {
        return false;
    }
    if (type == kIpcClientGui) {
        return peerUserSid == activeUserSid;
    }
    if (type == kIpcClientNode) {
        return peerUserSid == activeUserSid || peerUserSid == localSystemSid;
    }
    return false;
}

std::optional<std::uint32_t> IpcPeerProcessAuth::peerProcessId(
    std::uintptr_t nativeSocket)
{
#ifdef _WIN32
    const SOCKET socket = static_cast<SOCKET>(nativeSocket);
    sockaddr_in local{};
    sockaddr_in peer{};
    int localSize = sizeof(local);
    int peerSize = sizeof(peer);
    if (getsockname(socket, reinterpret_cast<sockaddr*>(&local), &localSize) != 0 ||
        getpeername(socket, reinterpret_cast<sockaddr*>(&peer), &peerSize) != 0 ||
        local.sin_family != AF_INET || peer.sin_family != AF_INET ||
        local.sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
        peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        return std::nullopt;
    }

    DWORD bytes = 0;
    const DWORD first = GetExtendedTcpTable(
        nullptr, &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (first != ERROR_INSUFFICIENT_BUFFER || bytes == 0) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> storage(bytes);
    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(storage.data());
    if (GetExtendedTcpTable(
            table, &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return std::nullopt;
    }

    const auto localPort = ntohs(local.sin_port);
    const auto peerPort = ntohs(peer.sin_port);
    for (DWORD index = 0; index < table->dwNumEntries; ++index) {
        const auto& row = table->table[index];
        if (row.dwState == MIB_TCP_STATE_ESTAB &&
            row.dwLocalAddr == peer.sin_addr.s_addr &&
            row.dwRemoteAddr == local.sin_addr.s_addr &&
            ntohs(static_cast<u_short>(row.dwLocalPort)) == peerPort &&
            ntohs(static_cast<u_short>(row.dwRemotePort)) == localPort) {
            return row.dwOwningPid;
        }
    }
#else
    (void)nativeSocket;
#endif
    return std::nullopt;
}

std::optional<IpcAuthenticatedPeer> IpcPeerProcessAuth::authenticatePeer(
    std::uintptr_t nativeSocket,
    const std::filesystem::path& daemonExecutable)
{
#ifdef _WIN32
    const auto processId = peerProcessId(nativeSocket);
    if (!processId) {
        return std::nullopt;
    }

    const HANDLE process = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, *processId);
    if (process == nullptr || WaitForSingleObject(process, 0) != WAIT_TIMEOUT) {
        if (process != nullptr) {
            CloseHandle(process);
        }
        return std::nullopt;
    }

    FILETIME created{};
    FILETIME exited{};
    FILETIME kernel{};
    FILETIME user{};
    std::vector<wchar_t> path(32768);
    DWORD pathLength = static_cast<DWORD>(path.size());
    const BOOL queriedTimes = GetProcessTimes(
        process, &created, &exited, &kernel, &user);
    const BOOL queriedPath = QueryFullProcessImageNameW(
        process, 0, path.data(), &pathLength);
    DWORD processSessionId = 0;
    const BOOL queriedSession = ProcessIdToSessionId(*processId, &processSessionId);
    const auto peerUserSid = tokenUserSid(process);
    const DWORD activeSessionId = WTSGetActiveConsoleSessionId();
    const auto activeUserSid = accountSidForSession(activeSessionId);
    const auto systemSid = localSystemSid();
    const auto revalidatedProcessId = peerProcessId(nativeSocket);
    const bool processStillRunning =
        WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
    CloseHandle(process);
    if (!queriedTimes || !queriedPath || !queriedSession || pathLength == 0 ||
        !peerUserSid || !activeUserSid || !systemSid || !processStillRunning ||
        !revalidatedProcessId || *revalidatedProcessId != *processId) {
        return std::nullopt;
    }

    std::error_code error;
    const auto executable = std::filesystem::canonical(
        std::filesystem::path(std::wstring(path.data(), pathLength)), error);
    if (error) {
        return std::nullopt;
    }
    const auto type = classifyExecutable(executable, daemonExecutable);
    if (type == kIpcClientUnknown) {
        return std::nullopt;
    }
    if (!isAuthorizedWindowsIdentity(
            type, processSessionId, *peerUserSid, activeSessionId,
            *activeUserSid, *systemSid)) {
        return std::nullopt;
    }

    ULARGE_INTEGER creationTime{};
    creationTime.LowPart = created.dwLowDateTime;
    creationTime.HighPart = created.dwHighDateTime;
    return IpcAuthenticatedPeer{
        type, *processId, creationTime.QuadPart, executable,
        processSessionId, *peerUserSid};
#else
    (void)nativeSocket;
    (void)daemonExecutable;
    return std::nullopt;
#endif
}

bool IpcPeerProcessAuth::validatePeer(
    std::uintptr_t nativeSocket,
    const IpcAuthenticatedPeer& peer,
    const std::filesystem::path& daemonExecutable)
{
    const auto current = authenticatePeer(nativeSocket, daemonExecutable);
    return current &&
        current->type == peer.type &&
        current->processId == peer.processId &&
        current->processCreationTime == peer.processCreationTime &&
        equalPathComponent(current->executable, peer.executable) &&
        current->windowsSessionId == peer.windowsSessionId &&
        current->windowsUserSid == peer.windowsUserSid;
}

std::filesystem::path IpcPeerProcessAuth::currentProcessExecutable()
{
#ifdef _WIN32
    std::vector<wchar_t> path(512);
    for (;;) {
        const DWORD length = GetModuleFileNameW(
            nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0) {
            return {};
        }
        if (length < path.size() - 1) {
            return std::filesystem::path(std::wstring(path.data(), length));
        }
        if (path.size() >= 32768) {
            return {};
        }
        path.resize(path.size() * 2);
    }
#else
    return {};
#endif
}

} // namespace inputleap
