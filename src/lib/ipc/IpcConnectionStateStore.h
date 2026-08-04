#pragma once

#include "ipc/Ipc.h"
#include "ipc/IpcMessage.h"

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace inputleap {

class IpcConnectionStateStore
{
public:
    struct Relay {
        EIpcClientType recipient;
        IpcConnectionStateMessage message;
    };

    std::vector<Relay> receive(EIpcClientType sender, std::uint64_t connectionId,
                               const IpcConnectionStateMessage& message);
    std::vector<Relay> clientConnected(EIpcClientType type, std::uint64_t connectionId);
    std::vector<Relay> clientDisconnected(EIpcClientType type, std::uint64_t connectionId);

    // Compatibility for non-session-aware callers; production IPC passes IDs.
    std::vector<Relay> receive(EIpcClientType sender,
                               const IpcConnectionStateMessage& message);
    std::vector<Relay> clientConnected(EIpcClientType type);
    std::vector<Relay> clientDisconnected(EIpcClientType type);
    const std::map<std::string, IpcConnectionStateMessage>& snapshot() const { return snapshot_; }

private:
    static std::string key(const IpcConnectionStateMessage& message);
    std::map<std::string, IpcConnectionStateMessage> snapshot_;
    std::optional<std::uint64_t> activeNodeConnectionId_;
};

} // namespace inputleap
