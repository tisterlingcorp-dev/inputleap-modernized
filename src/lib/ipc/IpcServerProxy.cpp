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

#include "ipc/IpcServerProxy.h"

#include "ipc/IpcMessage.h"
#include "ipc/Ipc.h"
#include "inputleap/ProtocolUtil.h"
#include "io/IStream.h"
#include "base/Log.h"

namespace inputleap {

IpcServerProxy::IpcServerProxy(inputleap::IStream& stream, IEventQueue* events) :
    m_stream(stream),
    m_events(events)
{
    m_events->add_handler(EventType::STREAM_INPUT_READY, stream.get_event_target(),
                          [this](const auto&){ handle_data(); });
}

IpcServerProxy::~IpcServerProxy()
{
    m_events->remove_handler(EventType::STREAM_INPUT_READY, m_stream.get_event_target());
}

void IpcServerProxy::handle_data()
{
    LOG_DEBUG("start ipc handle data");

    std::uint8_t input[4096];
    for (std::uint32_t n = m_stream.read(input, sizeof(input)); n != 0;
         n = m_stream.read(input, sizeof(input))) {
        frameReader_.append(input, n);
    }

    while (!frameReader_.invalid()) {
        auto message = frameReader_.take();
        if (!message) break;

        EventDataBase* event_data = nullptr;
        switch (message->type()) {
        case kIpcLogLine:
            event_data = create_event_data<IpcLogLineMessage>(
                static_cast<const IpcLogLineMessage&>(*message));
            break;
        case kIpcShutdown:
            event_data = create_event_data<IpcShutdownMessage>(
                static_cast<const IpcShutdownMessage&>(*message));
            break;
        case kIpcConnectionState:
            event_data = create_event_data<IpcConnectionStateMessage>(
                static_cast<const IpcConnectionStateMessage&>(*message));
            break;
        case kIpcCommandApplied:
            event_data = create_event_data<IpcCommandAppliedMessage>(
                static_cast<const IpcCommandAppliedMessage&>(*message));
            break;
        case kIpcRuntimeStatusResponse:
            event_data = create_event_data<IpcRuntimeStatusResponseMessage>(
                static_cast<const IpcRuntimeStatusResponseMessage&>(*message));
            break;
        default:
            break;
        }
        if (event_data != nullptr) {
            m_events->add_event(EventType::IPC_SERVER_PROXY_MESSAGE_RECEIVED,
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
IpcServerProxy::send(const IpcMessage& message)
{
    LOG_DEBUG4("ipc write: %d", message.type());

    switch (message.type()) {
    case kIpcHello: {
        const IpcHelloMessage& hm = static_cast<const IpcHelloMessage&>(message);
        ProtocolUtil::writef(&m_stream, kIpcMsgHello,
                             static_cast<std::uint32_t>(hm.clientType()));
        break;
    }

    case kIpcCommand: {
        const IpcCommandMessage& cm = static_cast<const IpcCommandMessage&>(message);
        std::string command = cm.command();
        ProtocolUtil::writef(&m_stream, kIpcMsgCommand, &command,
                             static_cast<std::uint32_t>(cm.elevate() ? 1 : 0));
        break;
    }

    case kIpcStartRequest: {
        const auto& start = static_cast<const IpcStartRequestMessage&>(message);
        std::string nonce = start.nonce();
        std::string command = start.command();
        ProtocolUtil::writef(
            &m_stream, kIpcMsgStartRequest, &nonce, &command,
            static_cast<std::uint32_t>(start.elevate() ? 1 : 0));
        break;
    }

    case kIpcStopRequest: {
        const auto& stop = static_cast<const IpcStopRequestMessage&>(message);
        std::string requestNonce = stop.requestNonce();
        std::string expectedAppliedNonce = stop.expectedAppliedNonce();
        ProtocolUtil::writef(
            &m_stream, kIpcMsgStopRequest, &requestNonce, &expectedAppliedNonce);
        break;
    }

    case kIpcReloadRequest: {
        const auto& reload = static_cast<const IpcReloadRequestMessage&>(message);
        std::string requestNonce = reload.requestNonce();
        std::string expectedAppliedNonce = reload.expectedAppliedNonce();
        ProtocolUtil::writef(
            &m_stream, kIpcMsgReloadRequest,
            &requestNonce, &expectedAppliedNonce);
        break;
    }

    case kIpcRuntimeStatusRequest: {
        const auto& status =
            static_cast<const IpcRuntimeStatusRequestMessage&>(message);
        std::string queryNonce = status.queryNonce();
        ProtocolUtil::writef(
            &m_stream, kIpcMsgRuntimeStatusRequest, &queryNonce);
        break;
    }

    case kIpcTopologyRequest: {
        const auto& topology =
            static_cast<const IpcTopologyRequestMessage&>(message);
        std::string requestNonce = topology.requestNonce();
        std::string expectedGeneration = topology.expectedGeneration();
        std::string payload = topology.payload();
        ProtocolUtil::writef(
            &m_stream, kIpcMsgTopologyRequest,
            &requestNonce, &expectedGeneration, &payload);
        break;
    }

    case kIpcConnectionState: {
        const auto& state = static_cast<const IpcConnectionStateMessage&>(message);
        std::string technicalName = state.technicalName();
        std::string detail = state.detail();
        ProtocolUtil::writef(&m_stream, kIpcMsgConnectionState,
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
IpcServerProxy::disconnect()
{
    LOG_DEBUG("ipc disconnect, closing stream");
    m_stream.close();
}

} // namespace inputleap
