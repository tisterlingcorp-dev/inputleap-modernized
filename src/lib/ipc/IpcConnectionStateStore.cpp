#include "ipc/IpcConnectionStateStore.h"

namespace inputleap {

std::string IpcConnectionStateStore::key(const IpcConnectionStateMessage& message)
{
    return std::to_string(static_cast<unsigned>(message.role())) + ":" +
           std::to_string(static_cast<unsigned>(message.identityPresence())) + ":" +
           message.technicalName();
}

std::vector<IpcConnectionStateStore::Relay>
IpcConnectionStateStore::receive(EIpcClientType sender, const IpcConnectionStateMessage& message)
{
    if (sender == kIpcClientNode && !activeNodeConnectionId_) {
        clientConnected(sender, 0);
    }
    return receive(sender, 0, message);
}

std::vector<IpcConnectionStateStore::Relay>
IpcConnectionStateStore::receive(EIpcClientType sender, std::uint64_t connectionId,
                                 const IpcConnectionStateMessage& message)
{
    if (sender != kIpcClientNode) {
        return {};
    }
    if (!activeNodeConnectionId_ || *activeNodeConnectionId_ != connectionId) {
        return {};
    }
    snapshot_.insert_or_assign(key(message), message);
    return {{kIpcClientGui, message}};
}

std::vector<IpcConnectionStateStore::Relay>
IpcConnectionStateStore::clientConnected(EIpcClientType type)
{
    return clientConnected(type, 0);
}

std::vector<IpcConnectionStateStore::Relay>
IpcConnectionStateStore::clientConnected(EIpcClientType type, std::uint64_t connectionId)
{
    std::vector<Relay> result;
    if (type == kIpcClientNode) {
        activeNodeConnectionId_ = connectionId;
        return result;
    }
    if (type == kIpcClientGui) {
        for (const auto& entry : snapshot_) {
            result.push_back({kIpcClientGui, entry.second});
        }
    }
    return result;
}

std::vector<IpcConnectionStateStore::Relay>
IpcConnectionStateStore::clientDisconnected(EIpcClientType type)
{
    return clientDisconnected(type, 0);
}

std::vector<IpcConnectionStateStore::Relay>
IpcConnectionStateStore::clientDisconnected(EIpcClientType type,
                                            std::uint64_t connectionId)
{
    std::vector<Relay> result;
    if (type != kIpcClientNode || !activeNodeConnectionId_ ||
        *activeNodeConnectionId_ != connectionId) {
        return result;
    }
    activeNodeConnectionId_.reset();
    for (auto& entry : snapshot_) {
        const auto& current = entry.second;
        if (current.state() == IpcConnectionState::Connected) {
            entry.second = IpcConnectionStateMessage(
                IpcConnectionState::Disconnected, current.role(), current.identityPresence(),
                current.technicalName(), "node IPC connection closed");
            result.push_back({kIpcClientGui, entry.second});
        }
    }
    return result;
}

} // namespace inputleap
