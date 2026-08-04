#pragma once

#include "ipc/Ipc.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

namespace inputleap {

struct IpcAuthenticatedPeer
{
    EIpcClientType type{kIpcClientUnknown};
    std::uint32_t processId{0};
    std::uint64_t processCreationTime{0};
    std::filesystem::path executable;
    std::uint32_t windowsSessionId{0};
    std::vector<std::uint8_t> windowsUserSid;
};

class IpcPeerProcessAuth
{
public:
    static EIpcClientType classifyExecutable(
        const std::filesystem::path& peerExecutable,
        const std::filesystem::path& daemonExecutable);
    static bool isAuthorizedWindowsIdentity(
        EIpcClientType type,
        std::uint32_t peerSessionId,
        const std::vector<std::uint8_t>& peerUserSid,
        std::uint32_t activeSessionId,
        const std::vector<std::uint8_t>& activeUserSid,
        const std::vector<std::uint8_t>& localSystemSid);
    static std::optional<std::uint32_t> peerProcessId(std::uintptr_t nativeSocket);
    static std::optional<IpcAuthenticatedPeer> authenticatePeer(
        std::uintptr_t nativeSocket,
        const std::filesystem::path& daemonExecutable);
    static bool validatePeer(
        std::uintptr_t nativeSocket,
        const IpcAuthenticatedPeer& peer,
        const std::filesystem::path& daemonExecutable);
    static std::filesystem::path currentProcessExecutable();
};

} // namespace inputleap
