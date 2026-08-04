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

#include "ipc/IpcClientProxy.h"

#include "ipc/Ipc.h"
#include "ipc/IpcMessage.h"
#include "inputleap/ProtocolUtil.h"
#include "io/IStream.h"
#include "arch/Arch.h"
#include "base/Log.h"

namespace inputleap {

IpcClientProxy::IpcClientProxy(std::unique_ptr<IStream>&& stream, IEventQueue* events,
                               EIpcClientType expectedClientType) :
    stream_(std::move(stream)),
    m_clientType(kIpcClientUnknown),
    m_expectedClientType(expectedClientType),
    m_disconnecting(false),
    m_events(events)
{
    m_events->add_handler(EventType::STREAM_INPUT_READY, stream_->get_event_target(),
                          [this](const auto&){ handle_data(); });
    m_events->add_handler(EventType::STREAM_OUTPUT_ERROR, stream_->get_event_target(),
                          [this](const auto&){ handle_write_error(); });
    m_events->add_handler(EventType::STREAM_INPUT_SHUTDOWN, stream_->get_event_target(),
                          [this](const auto&){ handle_disconnect(); });
    m_events->add_handler(EventType::STREAM_OUTPUT_SHUTDOWN, stream_->get_event_target(),
                          [this](const auto&){ handle_write_error(); });
}

IpcClientProxy::IpcClientProxy(std::unique_ptr<IStream>&& stream, IEventQueue* events,
                               std::uintptr_t nativeSocket,
                               IpcAuthenticatedPeer authenticatedPeer,
                               std::filesystem::path daemonExecutable) :
    stream_(std::move(stream)),
    m_clientType(kIpcClientUnknown),
    m_expectedClientType(authenticatedPeer.type),
    m_authenticatedPeer(std::move(authenticatedPeer)),
    m_nativeSocket(nativeSocket),
    m_daemonExecutable(std::move(daemonExecutable)),
    m_disconnecting(false),
    m_events(events)
{
    m_events->add_handler(EventType::STREAM_INPUT_READY, stream_->get_event_target(),
                          [this](const auto&){ handle_data(); });
    m_events->add_handler(EventType::STREAM_OUTPUT_ERROR, stream_->get_event_target(),
                          [this](const auto&){ handle_write_error(); });
    m_events->add_handler(EventType::STREAM_INPUT_SHUTDOWN, stream_->get_event_target(),
                          [this](const auto&){ handle_disconnect(); });
    m_events->add_handler(EventType::STREAM_OUTPUT_SHUTDOWN, stream_->get_event_target(),
                          [this](const auto&){ handle_write_error(); });
}

IpcClientProxy::~IpcClientProxy()
{
    m_events->remove_handler(EventType::STREAM_INPUT_READY, stream_->get_event_target());
    m_events->remove_handler(EventType::STREAM_OUTPUT_ERROR, stream_->get_event_target());
    m_events->remove_handler(EventType::STREAM_INPUT_SHUTDOWN, stream_->get_event_target());
    m_events->remove_handler(EventType::STREAM_OUTPUT_SHUTDOWN, stream_->get_event_target());

    // Ensure that client proxy is not deleted from below some active client feet
    {
        std::lock_guard<std::mutex> lock_read(m_readMutex);
        std::lock_guard<std::mutex> lock_write(m_writeMutex);
    }
}

void IpcClientProxy::handle_disconnect()
{
    disconnect();
    LOG_DEBUG("ipc client disconnected");
}

void IpcClientProxy::handle_write_error()
{
    disconnect();
    LOG_DEBUG("ipc client write error");
}

void IpcClientProxy::handle_data()
{
    // don't allow the dtor to destroy the stream while we're using it.
    std::lock_guard<std::mutex> lock(m_readMutex);

    LOG_DEBUG("start ipc handle data");

    std::uint8_t input[4096];
    for (std::uint32_t n = stream_->read(input, sizeof(input));
         n != 0 && !frameReader_.invalid();
         n = stream_->read(input, sizeof(input))) {
        frameReader_.append(input, n);

        while (!frameReader_.invalid()) {
            auto message = frameReader_.take();
            if (!message) break;

        if (m_authenticatedPeer && !IpcPeerProcessAuth::validatePeer(
                m_nativeSocket, *m_authenticatedPeer, m_daemonExecutable)) {
            LOG_WARN("authenticated ipc peer identity changed");
            disconnect();
            break;
        }

        EventDataBase* event_data = nullptr;
        bool authorized = false;
        switch (message->type()) {
        case kIpcHello: {
            const auto& hello = static_cast<const IpcHelloMessage&>(*message);
            const bool matchesAuthenticatedProcess =
                m_expectedClientType == kIpcClientUnknown ||
                m_expectedClientType == hello.clientType();
            if (m_clientType == kIpcClientUnknown && matchesAuthenticatedProcess) {
                m_clientType = hello.clientType();
                event_data = create_event_data<IpcHelloMessage>(hello);
                authorized = true;
            }
            break;
        }
        case kIpcCommand:
            if (m_clientType == kIpcClientGui) {
                event_data = create_event_data<IpcCommandMessage>(
                    static_cast<const IpcCommandMessage&>(*message));
                authorized = true;
            }
            break;
        case kIpcStartRequest:
            if (m_clientType == kIpcClientGui) {
                event_data = create_event_data<IpcStartRequestMessage>(
                    static_cast<const IpcStartRequestMessage&>(*message));
                authorized = true;
            }
            break;
        case kIpcStopRequest:
            if (m_clientType == kIpcClientGui) {
                event_data = create_event_data<IpcStopRequestMessage>(
                    static_cast<const IpcStopRequestMessage&>(*message));
                authorized = true;
            }
            break;
        case kIpcReloadRequest:
            if (m_clientType == kIpcClientGui) {
                event_data = create_event_data<IpcReloadRequestMessage>(
                    static_cast<const IpcReloadRequestMessage&>(*message));
                authorized = true;
            }
            break;
        case kIpcRuntimeStatusRequest:
            if (m_clientType == kIpcClientGui) {
                event_data = create_event_data<IpcRuntimeStatusRequestMessage>(
                    static_cast<const IpcRuntimeStatusRequestMessage&>(*message));
                authorized = true;
            }
            break;
        case kIpcTopologyRequest:
            if (m_clientType == kIpcClientGui) {
                event_data = create_event_data<IpcTopologyRequestMessage>(
                    static_cast<const IpcTopologyRequestMessage&>(*message));
                authorized = true;
            }
            break;
        case kIpcConnectionState:
            if (m_clientType == kIpcClientNode) {
                event_data = create_event_data<IpcConnectionStateMessage>(
                    static_cast<const IpcConnectionStateMessage&>(*message));
                authorized = true;
            }
            break;
        default:
            break;
        }
        if (!authorized) {
            LOG_WARN("unauthorized ipc message type=%d client=%d",
                     message->type(), m_clientType);
            disconnect();
            break;
        }
            m_events->add_event(EventType::IPC_CLIENT_PROXY_MESSAGE_RECEIVED,
                                this, event_data);
        }
    }

    if (frameReader_.invalid()) {
        LOG_ERR("invalid ipc message");
        disconnect();
    }

    LOG_DEBUG("finished ipc handle data");
}

void
IpcClientProxy::send(const IpcMessage& message)
{
    // don't allow other threads to write until we've finished the entire
    // message. stream write is locked, but only for that single write.
    // also, don't allow the dtor to destroy the stream while we're using it.
    std::lock_guard<std::mutex> lock(m_writeMutex);

    LOG_DEBUG4("ipc write: %d", message.type());

    switch (message.type()) {
    case kIpcLogLine: {
        const IpcLogLineMessage& llm = static_cast<const IpcLogLineMessage&>(message);
        std::string logLine = llm.logLine();
        ProtocolUtil::writef(stream_.get(), kIpcMsgLogLine, &logLine);
        break;
    }

    case kIpcShutdown:
        ProtocolUtil::writef(stream_.get(), kIpcMsgShutdown);
        break;

    case kIpcCommandApplied: {
        std::string nonce = static_cast<const IpcCommandAppliedMessage&>(message).nonce();
        ProtocolUtil::writef(stream_.get(), kIpcMsgCommandApplied, &nonce);
        break;
    }

    case kIpcRuntimeStatusResponse: {
        const auto& status =
            static_cast<const IpcRuntimeStatusResponseMessage&>(message);
        std::string queryNonce = status.queryNonce();
        std::string appliedNonce = status.appliedNonce();
        ProtocolUtil::writef(
            stream_.get(), kIpcMsgRuntimeStatusResponse,
            &queryNonce, static_cast<std::uint32_t>(status.schemaVersion()),
            static_cast<std::uint32_t>(status.runtimeState()), &appliedNonce);
        break;
    }

    case kIpcConnectionState: {
        const auto& state = static_cast<const IpcConnectionStateMessage&>(message);
        std::string technicalName = state.technicalName();
        std::string detail = state.detail();
        ProtocolUtil::writef(stream_.get(), kIpcMsgConnectionState,
                             static_cast<std::uint32_t>(state.state()),
                             static_cast<std::uint32_t>(state.role()),
                             static_cast<std::uint32_t>(state.identityPresence()),
                             &technicalName, &detail);
        break;
    }

    default:
        LOG_ERR("ipc message not supported: %d", message.type());
        break;
    }
}

void
IpcClientProxy::disconnect()
{
    if (m_disconnecting) {
        return;
    }
    LOG_DEBUG("ipc disconnect, closing stream");
    m_disconnecting = true;
    stream_->close();
    m_events->add_event(EventType::IPC_CLIENT_PROXY_DISCONNECTED, this);
}

} // namespace inputleap
