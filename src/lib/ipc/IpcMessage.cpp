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

#include "ipc/IpcMessage.h"
#include "ipc/Ipc.h"

#include <stdexcept>
#include <utility>

namespace inputleap {

IpcMessage::IpcMessage(std::uint8_t type) :
    m_type(type)
{
}

IpcMessage::~IpcMessage()
{
}

IpcHelloMessage::IpcHelloMessage(EIpcClientType clientType) :
    IpcMessage(kIpcHello),
    m_clientType(clientType)
{
}

IpcHelloMessage::~IpcHelloMessage()
{
}

IpcShutdownMessage::IpcShutdownMessage() :
IpcMessage(kIpcShutdown)
{
}

IpcShutdownMessage::~IpcShutdownMessage()
{
}

IpcCommandAppliedMessage::IpcCommandAppliedMessage(std::string nonce) :
    IpcMessage(kIpcCommandApplied),
    m_nonce(std::move(nonce))
{
    if (m_nonce.size() != 16) throw std::invalid_argument("invalid IPC stop nonce");
}

IpcCommandAppliedMessage::~IpcCommandAppliedMessage() = default;

IpcStopRequestMessage::IpcStopRequestMessage(
    std::string requestNonce, std::string expectedAppliedNonce) :
    IpcMessage(kIpcStopRequest),
    m_requestNonce(std::move(requestNonce)),
    m_expectedAppliedNonce(std::move(expectedAppliedNonce))
{
    if (m_requestNonce.size() != 16 || m_expectedAppliedNonce.size() != 16 ||
        m_requestNonce == m_expectedAppliedNonce) {
        throw std::invalid_argument("invalid IPC stop nonces");
    }
}

IpcReloadRequestMessage::IpcReloadRequestMessage(
    std::string requestNonce, std::string expectedAppliedNonce) :
    IpcMessage(kIpcReloadRequest),
    m_requestNonce(std::move(requestNonce)),
    m_expectedAppliedNonce(std::move(expectedAppliedNonce))
{
    if (m_requestNonce.size() != 16 || m_expectedAppliedNonce.size() != 16) {
        throw std::invalid_argument("invalid IPC reload nonces");
    }
}

IpcRuntimeStatusRequestMessage::IpcRuntimeStatusRequestMessage(
    std::string queryNonce) :
    IpcMessage(kIpcRuntimeStatusRequest),
    m_queryNonce(std::move(queryNonce))
{
    if (m_queryNonce.size() != 16) {
        throw std::invalid_argument("invalid IPC runtime status query nonce");
    }
}

IpcRuntimeStatusResponseMessage::IpcRuntimeStatusResponseMessage(
    std::string queryNonce, std::uint8_t schemaVersion,
    IpcRuntimeState runtimeState, std::string appliedNonce) :
    IpcMessage(kIpcRuntimeStatusResponse),
    m_queryNonce(std::move(queryNonce)),
    m_schemaVersion(schemaVersion),
    m_runtimeState(runtimeState),
    m_appliedNonce(std::move(appliedNonce))
{
    if (m_queryNonce.size() != 16 || m_schemaVersion != 1 ||
        m_runtimeState > IpcRuntimeState::Unknown ||
        (!m_appliedNonce.empty() && m_appliedNonce.size() != 16)) {
        throw std::invalid_argument("invalid IPC runtime status response");
    }
}

IpcTopologyRequestMessage::IpcTopologyRequestMessage(
    std::string requestNonce, std::string expectedGeneration,
    std::string payload) :
    IpcMessage(kIpcTopologyRequest),
    m_requestNonce(std::move(requestNonce)),
    m_expectedGeneration(std::move(expectedGeneration)),
    m_payload(std::move(payload))
{
    if (m_requestNonce.size() != 16 || m_expectedGeneration.size() != 16 ||
        m_requestNonce == m_expectedGeneration) {
        throw std::invalid_argument("invalid IPC topology generations");
    }
}

IpcLogLineMessage::IpcLogLineMessage(const std::string& logLine) :
    IpcMessage(kIpcLogLine),
    m_logLine(logLine)
{
}

IpcLogLineMessage::~IpcLogLineMessage()
{
}

IpcCommandMessage::IpcCommandMessage(const std::string& command, bool elevate) :
    IpcMessage(kIpcCommand),
    m_command(command),
    m_elevate(elevate)
{
}

IpcCommandMessage::~IpcCommandMessage()
{
}

IpcStartRequestMessage::IpcStartRequestMessage(
    std::string nonce, std::string command, bool elevate) :
    IpcMessage(kIpcStartRequest),
    m_nonce(std::move(nonce)),
    m_command(std::move(command)),
    m_elevate(elevate)
{
    if (m_nonce.size() != 16) throw std::invalid_argument("invalid IPC start nonce");
}

IpcConnectionStateMessage::IpcConnectionStateMessage(
    IpcConnectionState state, IpcConnectionRole role,
    IpcIdentityPresence identityPresence, std::string technicalName, std::string detail) :
    IpcMessage(kIpcConnectionState),
    m_state(state),
    m_role(role),
    m_identityPresence(identityPresence),
    m_technicalName(std::move(technicalName)),
    m_detail(std::move(detail))
{
    if (state > IpcConnectionState::Disconnected
        || role > IpcConnectionRole::ServerPeer
        || identityPresence > IpcIdentityPresence::LegacyUnavailable) {
        throw std::invalid_argument("invalid typed IPC connection state value");
    }
    if (m_identityPresence == IpcIdentityPresence::Known && m_technicalName.empty()) {
        throw std::invalid_argument("known IPC peer identity must have a technical name");
    }
    if (m_identityPresence == IpcIdentityPresence::LegacyUnavailable && !m_technicalName.empty()) {
        throw std::invalid_argument("legacy-unavailable IPC peer identity must not have a technical name");
    }
}

} // namespace inputleap
