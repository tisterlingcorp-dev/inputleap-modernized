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

#include "ipc/IpcServer.h"
#include "ipc/IpcServerDisconnectEventPolicy.h"

#include "ipc/Ipc.h"
#include "ipc/IpcClientProxy.h"
#include "ipc/IpcMessage.h"
#include "ipc/IpcPeerProcessAuth.h"
#include "net/IDataSocket.h"
#include "net/TCPSocket.h"
#include "io/IStream.h"
#include "base/IEventQueue.h"
#include "base/Event.h"
#include "base/Log.h"

namespace inputleap {

std::shared_ptr<IpcMessage> copyIpcServerMessageForDispatch(
    const IpcMessage& message)
{
    switch (message.type()) {
    case kIpcHello:
        return std::make_shared<IpcHelloMessage>(static_cast<const IpcHelloMessage&>(message));
    case kIpcCommand:
        return std::make_shared<IpcCommandMessage>(static_cast<const IpcCommandMessage&>(message));
    case kIpcStartRequest:
        return std::make_shared<IpcStartRequestMessage>(
            static_cast<const IpcStartRequestMessage&>(message));
    case kIpcConnectionState:
        return std::make_shared<IpcConnectionStateMessage>(static_cast<const IpcConnectionStateMessage&>(message));
    case kIpcLogLine:
        return std::make_shared<IpcLogLineMessage>(static_cast<const IpcLogLineMessage&>(message));
    case kIpcShutdown:
        return std::make_shared<IpcShutdownMessage>();
    case kIpcCommandApplied:
        return std::make_shared<IpcCommandAppliedMessage>(
            static_cast<const IpcCommandAppliedMessage&>(message));
    case kIpcStopRequest:
        return std::make_shared<IpcStopRequestMessage>(
            static_cast<const IpcStopRequestMessage&>(message));
    case kIpcReloadRequest:
        return std::make_shared<IpcReloadRequestMessage>(
            static_cast<const IpcReloadRequestMessage&>(message));
    case kIpcRuntimeStatusRequest:
        return std::make_shared<IpcRuntimeStatusRequestMessage>(
            static_cast<const IpcRuntimeStatusRequestMessage&>(message));
    case kIpcTopologyRequest:
        return std::make_shared<IpcTopologyRequestMessage>(
            static_cast<const IpcTopologyRequestMessage&>(message));
    default:
        return {};
    }
}

IpcServer::IpcServer(IEventQueue* events, SocketMultiplexer* socketMultiplexer) :
    m_mock(false),
    m_events(events),
    m_socketMultiplexer(socketMultiplexer),
    m_address(NetworkAddress(IPC_HOST, IPC_PORT)),
    m_daemonExecutable(IpcPeerProcessAuth::currentProcessExecutable())
{
    init();
}

IpcServer::IpcServer(IEventQueue* events, SocketMultiplexer* socketMultiplexer,
                     int port, IpcPeerAuthenticationMode authenticationMode,
                     const std::filesystem::path& daemonExecutable) :
    m_mock(false),
    m_events(events),
    m_socketMultiplexer(socketMultiplexer),
    m_address(NetworkAddress::forListener(IPC_HOST, port)),
    m_daemonExecutable(daemonExecutable),
    m_authenticationMode(authenticationMode)
{
    if (m_authenticationMode == IpcPeerAuthenticationMode::RequireOperatingSystemIdentity &&
        m_daemonExecutable.empty()) {
        m_daemonExecutable = IpcPeerProcessAuth::currentProcessExecutable();
    }
    init();
}

void
IpcServer::init()
{
    socket_ = std::make_unique<TCPListenSocket>(m_events, m_socketMultiplexer, IArchNetwork::kINET);

    m_address.resolve();

    m_events->add_handler(EventType::LISTEN_SOCKET_CONNECTING, socket_.get(),
                          [this](const auto&){ handle_client_connecting(); });
}

IpcServer::~IpcServer()
{
    if (m_mock) {
        return;
    }

    m_events->remove_handler(EventType::LISTEN_SOCKET_CONNECTING, socket_.get());
    socket_.reset();

    {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        ClientList::iterator it;
        for (it = m_clients.begin(); it != m_clients.end(); it++) {
            deleteClient(*it);
        }
        m_clients.clear();
    }
}

void
IpcServer::listen()
{
    socket_->bind(m_address);
}

int IpcServer::port() const
{
    return socket_->boundPort();
}

void IpcServer::handle_client_connecting()
{
    auto stream = socket_->accept();
    if (!stream) {
        return;
    }

    LOG_DEBUG("accepted ipc client connection");

    std::optional<IpcAuthenticatedPeer> authenticatedPeer;
    std::uintptr_t nativeSocket = 0;
    if (m_authenticationMode == IpcPeerAuthenticationMode::RequireOperatingSystemIdentity) {
        const auto* tcpSocket = dynamic_cast<const TCPSocket*>(stream.get());
        if (tcpSocket == nullptr) {
            LOG_WARN("rejecting ipc peer: accepted stream is not TCP");
            stream->close();
            return;
        }
        nativeSocket = tcpSocket->nativeHandle();
        authenticatedPeer = IpcPeerProcessAuth::authenticatePeer(
            nativeSocket, m_daemonExecutable);
        if (!authenticatedPeer) {
            LOG_WARN("rejecting unauthenticated local ipc peer");
            stream->close();
            return;
        }
    }

    IpcClientProxy* proxy = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        if (authenticatedPeer) {
            proxy = new IpcClientProxy(
                std::move(stream), m_events, nativeSocket,
                std::move(*authenticatedPeer), m_daemonExecutable);
        }
        else {
            proxy = new IpcClientProxy(std::move(stream), m_events);
        }
        proxy->m_connectionId = m_nextConnectionId++;
        m_clients.push_back(proxy);
    }

    m_events->add_handler(EventType::IPC_CLIENT_PROXY_DISCONNECTED, proxy,
                          [this](const auto& e){ handle_client_disconnected(e); });
    m_events->add_handler(EventType::IPC_CLIENT_PROXY_MESSAGE_RECEIVED, proxy,
                          [this](const auto& e){ handle_message_received(e); });

    m_events->add_event(EventType::IPC_SERVER_CLIENT_CONNECTED, this,
                        create_event_data<IpcClientProxy*>(proxy));
}

void IpcServer::handle_client_disconnected(const Event& e)
{
    IpcClientProxy* proxy = const_cast<IpcClientProxy*>(
                static_cast<const IpcClientProxy*>(e.getTarget()));

    const EIpcClientType clientType = proxy->m_clientType;
    const std::uint64_t connectionId = proxy->m_connectionId;
    {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        if (!removeIpcClientByPointer(m_clients, proxy)) {
            return;
        }
        deleteClient(proxy);
        LOG_DEBUG("ipc client proxy removed, connected=%zd", m_clients.size());
    }

    m_events->add_event(makeIpcServerClientDisconnectedEvent(
        this, clientType, connectionId));
}

void IpcServer::handle_message_received(const Event& e)
{
    auto owned = copyIpcServerMessageForDispatch(e.get_data_as<IpcMessage>());
    if (!owned) {
        return;
    }
    const auto* proxy = static_cast<const IpcClientProxy*>(e.getTarget());
    m_events->add_event(EventType::IPC_SERVER_MESSAGE_RECEIVED, this,
                        create_event_data<IpcServerMessage>(
                            IpcServerMessage{proxy->m_clientType,
                                             proxy->m_connectionId,
                                             std::move(owned)}));
}

void
IpcServer::deleteClient(IpcClientProxy* proxy)
{
    m_events->remove_handler(EventType::IPC_CLIENT_PROXY_MESSAGE_RECEIVED, proxy);
    m_events->remove_handler(EventType::IPC_CLIENT_PROXY_DISCONNECTED, proxy);
    delete proxy;
}

bool
IpcServer::hasClients(EIpcClientType clientType) const
{
    std::lock_guard<std::mutex> lock(m_clientsMutex);

    if (m_clients.empty()) {
        return false;
    }

    ClientList::const_iterator it;
    for (it = m_clients.begin(); it != m_clients.end(); it++) {
        // at least one client is alive and type matches, there are clients.
        IpcClientProxy* p = *it;
        if (!p->m_disconnecting && p->m_clientType == clientType) {
            return true;
        }
    }

    // all clients must be disconnecting, no active clients.
    return false;
}

void
IpcServer::send(const IpcMessage& message, EIpcClientType filterType)
{
    std::lock_guard<std::mutex> lock(m_clientsMutex);

    ClientList::iterator it;
    for (it = m_clients.begin(); it != m_clients.end(); it++) {
        IpcClientProxy* proxy = *it;
        if (proxy->m_clientType == filterType) {
            proxy->send(message);
        }
    }
}

bool IpcServer::sendCommandAppliedResponse(
    const IpcServerMessage& request, const std::string& acceptedNonce)
{
    if (request.origin != kIpcClientGui || !request.message ||
        acceptedNonce.size() != 16) {
        return false;
    }

    std::string requestNonce;
    switch (request.message->type()) {
    case kIpcStartRequest:
        requestNonce = static_cast<const IpcStartRequestMessage&>(
            *request.message).nonce();
        break;
    case kIpcReloadRequest:
        requestNonce = static_cast<const IpcReloadRequestMessage&>(
            *request.message).requestNonce();
        break;
    case kIpcStopRequest:
        requestNonce = static_cast<const IpcStopRequestMessage&>(
            *request.message).requestNonce();
        break;
    case kIpcTopologyRequest:
        requestNonce = static_cast<const IpcTopologyRequestMessage&>(
            *request.message).requestNonce();
        break;
    default:
        return false;
    }
    if (requestNonce != acceptedNonce) {
        return false;
    }
    return sendToConnection(
        IpcCommandAppliedMessage(acceptedNonce), request.connectionId, kIpcClientGui);
}

bool IpcServer::sendRuntimeStatusResponse(
    const IpcServerMessage& request, std::uint8_t schemaVersion,
    IpcRuntimeState runtimeState, const std::string& appliedNonce)
{
    if (request.origin != kIpcClientGui || !request.message ||
        request.message->type() != kIpcRuntimeStatusRequest ||
        schemaVersion != 1 ||
        (!appliedNonce.empty() && appliedNonce.size() != 16) ||
        (runtimeState != IpcRuntimeState::Stopped &&
         runtimeState != IpcRuntimeState::Running &&
         runtimeState != IpcRuntimeState::Unknown)) {
        return false;
    }
    const auto& status = static_cast<const IpcRuntimeStatusRequestMessage&>(
        *request.message);
    if (status.queryNonce().size() != 16) {
        return false;
    }
    return sendToConnection(
        IpcRuntimeStatusResponseMessage(
            status.queryNonce(), schemaVersion, runtimeState, appliedNonce),
        request.connectionId, kIpcClientGui);
}

bool IpcServer::sendToConnection(
    const IpcMessage& message, std::uint64_t connectionId,
    EIpcClientType expectedClientType)
{
    std::lock_guard<std::mutex> lock(m_clientsMutex);

    for (IpcClientProxy* proxy : m_clients) {
        if (proxy->m_connectionId == connectionId &&
            proxy->m_clientType == expectedClientType && !proxy->m_disconnecting) {
            proxy->send(message);
            return true;
        }
    }
    return false;
}

} // namespace inputleap
