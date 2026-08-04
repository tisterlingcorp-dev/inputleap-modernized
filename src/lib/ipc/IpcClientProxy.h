/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2012 Nick Bolton
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "ipc/Ipc.h"
#include "ipc/IpcFrameReader.h"
#include "ipc/IpcPeerProcessAuth.h"
#include "arch/IArchMultithread.h"
#include "base/EventTypes.h"
#include "base/Event.h"
#include "base/EventTarget.h"
#include "base/Fwd.h"

#include <mutex>
#include <optional>

namespace inputleap {

class IpcMessage;
class IpcCommandMessage;
class IpcHelloMessage;
class IpcConnectionStateMessage;
class IStream;

class IpcClientProxy : public EventTarget {
    friend class IpcServer;

public:
    IpcClientProxy(std::unique_ptr<inputleap::IStream>&& stream, IEventQueue* events,
                   EIpcClientType expectedClientType = kIpcClientUnknown);
    IpcClientProxy(std::unique_ptr<inputleap::IStream>&& stream, IEventQueue* events,
                   std::uintptr_t nativeSocket, IpcAuthenticatedPeer authenticatedPeer,
                   std::filesystem::path daemonExecutable);
    virtual ~IpcClientProxy();

private:
    void send(const IpcMessage& message);
    void handle_data();
    void handle_disconnect();
    void handle_write_error();
    void disconnect();

private:
    std::unique_ptr<inputleap::IStream> stream_;
    IpcFrameReader frameReader_{IpcFrameReader::Direction::ClientToServer};
    EIpcClientType m_clientType;
    const EIpcClientType m_expectedClientType;
    std::optional<IpcAuthenticatedPeer> m_authenticatedPeer;
    std::uintptr_t m_nativeSocket{0};
    std::filesystem::path m_daemonExecutable;
    bool m_disconnecting;
    std::uint64_t m_connectionId{0};
    std::mutex m_readMutex;
    std::mutex m_writeMutex;
    IEventQueue* m_events;
};

} // namespace inputleap
