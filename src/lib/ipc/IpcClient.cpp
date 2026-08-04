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

#include "ipc/IpcClient.h"
#include "ipc/Ipc.h"
#include "ipc/IpcServerProxy.h"
#include "ipc/IpcMessage.h"
#include "base/EventQueueTimer.h"
#include "base/IEventQueue.h"
#include <cassert>

namespace inputleap {

IpcClient::IpcClient(IEventQueue* events, SocketMultiplexer* socketMultiplexer) :
    IpcClient(events, socketMultiplexer, IPC_PORT, kIpcClientNode)
{
}

IpcClient::IpcClient(IEventQueue* events, SocketMultiplexer* socketMultiplexer, int port) :
    IpcClient(events, socketMultiplexer, port, kIpcClientNode)
{
}

IpcClient::IpcClient(
    IEventQueue* events, SocketMultiplexer* socketMultiplexer, int port,
    EIpcClientType clientType) :
    m_serverAddress(NetworkAddress(IPC_HOST, port)),
    m_socketMultiplexer(socketMultiplexer),
    m_events(events),
    m_clientType(clientType)
{
    init();
}

void
IpcClient::init()
{
    m_serverAddress.resolve();
}

IpcClient::~IpcClient()
{
    disconnect();
}

void
IpcClient::connect()
{
    m_userDisconnecting = false;
    beginConnection();
}

void
IpcClient::disconnect()
{
    m_userDisconnecting = true;
    m_ready = false;
    cancelReconnect();
    cleanupConnection();
}

void IpcClient::beginConnection()
{
    if (m_userDisconnecting || m_socket) {
        return;
    }

    try {
        m_socket = std::make_unique<TCPSocket>(
            m_events, m_socketMultiplexer, IArchNetwork::kINET);
        const auto* target = m_socket->get_event_target();
        m_events->add_handler(EventType::DATA_SOCKET_CONNECTED, target,
                              [this](const auto&){ handle_connected(); });
        m_events->add_handler(EventType::DATA_SOCKET_CONNECTION_FAILED, target,
                              [this](const auto&){ handle_connection_lost(); });
        m_events->add_handler(EventType::SOCKET_DISCONNECTED, target,
                              [this](const auto&){ handle_connection_lost(); });
        m_events->add_handler(EventType::STREAM_INPUT_SHUTDOWN, target,
                              [this](const auto&){ handle_connection_lost(); });
        m_events->add_handler(EventType::STREAM_OUTPUT_SHUTDOWN, target,
                              [this](const auto&){ handle_connection_lost(); });

        server_ = std::make_unique<IpcServerProxy>(*m_socket, m_events);
        m_events->add_handler(EventType::IPC_SERVER_PROXY_MESSAGE_RECEIVED, server_.get(),
                              [this](const auto& e){ handle_message_received(e); });
        m_socket->connect(m_serverAddress);
    }
    catch (...) {
        cleanupConnection();
        scheduleReconnect();
    }
}

void IpcClient::cleanupConnection()
{
    m_ready = false;
    if (server_) {
        m_events->remove_handler(EventType::IPC_SERVER_PROXY_MESSAGE_RECEIVED,
                                 server_.get());
        server_.reset();
    }
    if (m_socket) {
        const auto* target = m_socket->get_event_target();
        m_events->remove_handler(EventType::DATA_SOCKET_CONNECTED, target);
        m_events->remove_handler(EventType::DATA_SOCKET_CONNECTION_FAILED, target);
        m_events->remove_handler(EventType::SOCKET_DISCONNECTED, target);
        m_events->remove_handler(EventType::STREAM_INPUT_SHUTDOWN, target);
        m_events->remove_handler(EventType::STREAM_OUTPUT_SHUTDOWN, target);
        m_socket->close();
        m_socket.reset();
    }
}

void IpcClient::handle_connection_lost()
{
    if (m_userDisconnecting) {
        return;
    }
    cleanupConnection();
    scheduleReconnect();
}

void IpcClient::scheduleReconnect()
{
    if (m_userDisconnecting || m_retryTimer != nullptr) {
        return;
    }
    m_retryTimer = m_events->newOneShotTimer(0.5, nullptr);
    m_events->add_handler(EventType::TIMER, m_retryTimer,
                          [this](const auto&) {
        auto* timer = m_retryTimer;
        m_retryTimer = nullptr;
        m_events->remove_handler(EventType::TIMER, timer);
        m_events->deleteTimer(timer);
        beginConnection();
    });
}

void IpcClient::cancelReconnect()
{
    if (m_retryTimer == nullptr) {
        return;
    }
    m_events->remove_handler(EventType::TIMER, m_retryTimer);
    m_events->deleteTimer(m_retryTimer);
    m_retryTimer = nullptr;
}

void
IpcClient::send(const IpcMessage& message)
{
    assert(server_);
    server_->send(message);
}

IpcClient::SendResult
IpcClient::sendConnectionState(const IpcConnectionStateMessage& message)
{
    constexpr std::size_t kMaximumConnectionStates = 256;
    const auto key = connectionStateKey(message);
    if (m_connectionStateSnapshot.find(key) == m_connectionStateSnapshot.end() &&
        m_connectionStateSnapshot.size() >= kMaximumConnectionStates) {
        return SendResult::Rejected;
    }
    m_connectionStateSnapshot.insert_or_assign(key, message);
    if (!server_ || !m_ready) {
        return SendResult::Queued;
    }
    send(message);
    return SendResult::Sent;
}

void IpcClient::handle_connected()
{
    m_events->add_event(EventType::IPC_CLIENT_CONNECTED, this);

    IpcHelloMessage message(m_clientType);
    send(message);
    m_ready = true;
    for (const auto& entry : m_connectionStateSnapshot) {
        send(entry.second);
    }
}

std::string IpcClient::connectionStateKey(const IpcConnectionStateMessage& message)
{
    return std::to_string(static_cast<unsigned>(message.role())) + ":" +
           std::to_string(static_cast<unsigned>(message.identityPresence())) + ":" +
           message.technicalName();
}

void IpcClient::handle_message_received(const Event& e)
{
    Event event(EventType::IPC_CLIENT_MESSAGE_RECEIVED, this);
    event.clone_data_from(e);
    m_events->add_event(std::move(event));
}

} // namespace inputleap
