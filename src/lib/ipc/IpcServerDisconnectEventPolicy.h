#pragma once

#include "base/Event.h"
#include "ipc/Ipc.h"

#include <algorithm>

namespace inputleap {

inline Event makeIpcServerClientDisconnectedEvent(
    const EventTarget* target, EIpcClientType clientType, std::uint64_t connectionId = 0)
{
    return Event(EventType::IPC_SERVER_CLIENT_DISCONNECTED, target,
                 create_event_data<IpcServerClientDisconnectedInfo>(
                     IpcServerClientDisconnectedInfo{clientType, connectionId}));
}

template<class Container, class Pointer>
bool removeIpcClientByPointer(Container& clients, Pointer pointer)
{
    const auto it = std::find(clients.begin(), clients.end(), pointer);
    if (it == clients.end()) {
        return false;
    }
    clients.erase(it);
    return true;
}

} // namespace inputleap
