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
#include "base/EventTypes.h"
#include "base/Event.h"
#include <string>

namespace inputleap {

class IpcMessage {
public:
    virtual ~IpcMessage();

    //! Gets the message type ID.
    std::uint8_t type() const { return m_type; }

protected:
    IpcMessage(std::uint8_t type);

private:
    std::uint8_t m_type;
};

class IpcHelloMessage : public IpcMessage {
public:
    IpcHelloMessage(EIpcClientType clientType);
    virtual ~IpcHelloMessage();

    //! Gets the message type ID.
    EIpcClientType clientType() const { return m_clientType; }

private:
    EIpcClientType m_clientType;
};

class IpcShutdownMessage : public IpcMessage {
public:
    IpcShutdownMessage();
    virtual ~IpcShutdownMessage();
};

class IpcCommandAppliedMessage : public IpcMessage {
public:
    explicit IpcCommandAppliedMessage(std::string nonce);
    virtual ~IpcCommandAppliedMessage();
    const std::string& nonce() const { return m_nonce; }
private:
    std::string m_nonce;
};

class IpcStopRequestMessage : public IpcMessage {
public:
    IpcStopRequestMessage(std::string requestNonce,
                          std::string expectedAppliedNonce);
    const std::string& requestNonce() const { return m_requestNonce; }
    const std::string& expectedAppliedNonce() const { return m_expectedAppliedNonce; }
private:
    std::string m_requestNonce;
    std::string m_expectedAppliedNonce;
};

class IpcReloadRequestMessage : public IpcMessage {
public:
    IpcReloadRequestMessage(std::string requestNonce,
                            std::string expectedAppliedNonce);
    const std::string& requestNonce() const { return m_requestNonce; }
    const std::string& expectedAppliedNonce() const { return m_expectedAppliedNonce; }
private:
    std::string m_requestNonce;
    std::string m_expectedAppliedNonce;
};

class IpcRuntimeStatusRequestMessage : public IpcMessage {
public:
    explicit IpcRuntimeStatusRequestMessage(std::string queryNonce);
    const std::string& queryNonce() const { return m_queryNonce; }
private:
    std::string m_queryNonce;
};

class IpcRuntimeStatusResponseMessage : public IpcMessage {
public:
    IpcRuntimeStatusResponseMessage(std::string queryNonce,
                                    std::uint8_t schemaVersion,
                                    IpcRuntimeState runtimeState,
                                    std::string appliedNonce);
    const std::string& queryNonce() const { return m_queryNonce; }
    std::uint8_t schemaVersion() const { return m_schemaVersion; }
    IpcRuntimeState runtimeState() const { return m_runtimeState; }
    const std::string& appliedNonce() const { return m_appliedNonce; }
private:
    std::string m_queryNonce;
    std::uint8_t m_schemaVersion;
    IpcRuntimeState m_runtimeState;
    std::string m_appliedNonce;
};

class IpcTopologyRequestMessage : public IpcMessage {
public:
    IpcTopologyRequestMessage(std::string requestNonce,
                              std::string expectedGeneration,
                              std::string payload);
    const std::string& requestNonce() const { return m_requestNonce; }
    const std::string& expectedGeneration() const { return m_expectedGeneration; }
    const std::string& payload() const { return m_payload; }
private:
    std::string m_requestNonce;
    std::string m_expectedGeneration;
    std::string m_payload;
};


class IpcLogLineMessage : public IpcMessage {
public:
    IpcLogLineMessage(const std::string& logLine);
    virtual ~IpcLogLineMessage();

    //! Gets the log line.
    std::string logLine() const { return m_logLine; }

private:
    std::string m_logLine;
};

class IpcCommandMessage : public IpcMessage {
public:
    IpcCommandMessage(const std::string& command, bool elevate);
    virtual ~IpcCommandMessage();

    //! Gets the command.
    std::string command() const { return m_command; }

    //! Gets whether or not the process should be elevated on MS Windows.
    bool elevate() const { return m_elevate; }

private:
    std::string m_command;
    bool m_elevate;
};

class IpcStartRequestMessage : public IpcMessage {
public:
    IpcStartRequestMessage(std::string nonce, std::string command, bool elevate);
    const std::string& nonce() const { return m_nonce; }
    const std::string& command() const { return m_command; }
    bool elevate() const { return m_elevate; }

private:
    std::string m_nonce;
    std::string m_command;
    bool m_elevate;
};

class IpcConnectionStateMessage : public IpcMessage {
public:
    IpcConnectionStateMessage(IpcConnectionState state,
                              IpcConnectionRole role,
                              IpcIdentityPresence identityPresence,
                              std::string technicalName,
                              std::string detail = {});

    IpcConnectionState state() const { return m_state; }
    IpcConnectionRole role() const { return m_role; }
    IpcIdentityPresence identityPresence() const { return m_identityPresence; }
    const std::string& technicalName() const { return m_technicalName; }
    const std::string& detail() const { return m_detail; }

private:
    IpcConnectionState m_state;
    IpcConnectionRole m_role;
    IpcIdentityPresence m_identityPresence;
    std::string m_technicalName;
    std::string m_detail;
};

} // namespace inputleap
