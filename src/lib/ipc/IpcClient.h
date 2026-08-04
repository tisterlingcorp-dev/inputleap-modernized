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
#include "net/Fwd.h"
#include "net/NetworkAddress.h"
#include "net/TCPSocket.h"
#include "base/EventTarget.h"
#include "base/EventTypes.h"
#include <map>
#include <memory>
#include <string>

namespace inputleap {

class IpcServerProxy;
class IpcMessage;
class IpcConnectionStateMessage;

//! IPC client for communication between daemon and GUI.
/*!
 * See \ref IpcServer description.
 */
class IpcClient : public EventTarget {
public:
    enum class SendResult { Rejected, Queued, Sent };
    IpcClient(IEventQueue* events, SocketMultiplexer* socketMultiplexer);
    IpcClient(IEventQueue* events, SocketMultiplexer* socketMultiplexer, int port);
    IpcClient(IEventQueue* events, SocketMultiplexer* socketMultiplexer, int port,
              EIpcClientType clientType);
    virtual ~IpcClient();

    //! @name manipulators
    //@{

    //! Connects to the IPC server at localhost.
    void connect();

    //! Disconnects from the IPC server.
    void disconnect();

    //! Sends a message to the server.
    void send(const IpcMessage& message);
    SendResult sendConnectionState(const IpcConnectionStateMessage& message);

    //@}

private:
    void init();
    void beginConnection();
    void cleanupConnection();
    void scheduleReconnect();
    void cancelReconnect();
    void handle_connection_lost();
    void handle_connected();
    void handle_message_received(const Event& event);
    static std::string connectionStateKey(const IpcConnectionStateMessage& message);

private:
    NetworkAddress m_serverAddress;
    SocketMultiplexer* m_socketMultiplexer;
    std::unique_ptr<TCPSocket> m_socket;
    std::unique_ptr<IpcServerProxy> server_;
    IEventQueue* m_events;
    EventQueueTimer* m_retryTimer{nullptr};
    EIpcClientType m_clientType{kIpcClientNode};
    bool m_ready{false};
    bool m_userDisconnecting{true};
    std::map<std::string, IpcConnectionStateMessage> m_connectionStateSnapshot;
};

} // namespace inputleap
