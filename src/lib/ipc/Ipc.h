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

#include <cstdint>

#define IPC_HOST "127.0.0.1"
#define IPC_PORT 24801

enum EIpcMessage {
    kIpcHello,
    kIpcLogLine,
    kIpcCommand,
    kIpcShutdown,
    kIpcConnectionState,
    kIpcCommandApplied,
    kIpcStopRequest,
    kIpcStartRequest,
    kIpcReloadRequest,
    kIpcRuntimeStatusRequest,
    kIpcRuntimeStatusResponse,
    kIpcTopologyRequest,
};

enum class IpcRuntimeState : std::uint8_t {
    Stopped = 0,
    Running = 1,
    Unknown = 2,
};

enum class IpcConnectionState : std::uint8_t {
    Available = 0,
    Connected = 1,
    Disconnected = 2,
};

enum class IpcConnectionRole : std::uint8_t {
    ClientPeer = 0,
    ServerPeer = 1,
};

// Empty technicalName is valid only when legacy identity degradation is explicit.
enum class IpcIdentityPresence : std::uint8_t {
    Known = 0,
    LegacyUnavailable = 1,
};

enum EIpcClientType {
    kIpcClientUnknown,
    kIpcClientGui,
    kIpcClientNode,
};

struct IpcServerClientDisconnectedInfo {
    EIpcClientType clientType;
    std::uint64_t connectionId;
};

// handshake: node/gui -> daemon
// $1 = type, the client identifies it's self as gui or node (input-leapc/s).
extern const char*        kIpcMsgHello;

// log line: daemon -> gui
// $1 = aggregate log lines collected from input-leaps/c or the daemon itself.
extern const char*        kIpcMsgLogLine;

// command: gui -> daemon
// $1 = command; the command for the daemon to launch, typically the full
// path to input-leaps/c. $2 = true when process must be elevated on ms windows.
extern const char*        kIpcMsgCommand;
extern const char*        kIpcMsgStartRequest;
// correlated fail-closed reload of the last durably applied command.
extern const char*        kIpcMsgReloadRequest;
extern const char*        kIpcMsgRuntimeStatusRequest;
extern const char*        kIpcMsgRuntimeStatusResponse;
// Atomic topology transaction: GUI -> daemon. The path and primary screen are
// daemon-owned; only request/expected generations and payload cross the wire.
extern const char*        kIpcMsgTopologyRequest;
// correlated fail-closed stop request: GUI -> daemon, $1 = request nonce and
// $2 = the exact 16-byte generation the caller is authorized to stop.
extern const char*        kIpcMsgStopRequest;

// shutdown: daemon -> node
// the daemon tells input-leaps/c to shut down gracefully.
extern const char*        kIpcMsgShutdown;

// connection state: node -> daemon -> gui. Strings use ProtocolUtil framing.
extern const char*        kIpcMsgConnectionState;
// daemon -> GUI after the correlated stop is durably persisted and the core exited.
// $1 = the exact 16-byte nonce from kIpcMsgStopRequest.
extern const char*        kIpcMsgCommandApplied;
