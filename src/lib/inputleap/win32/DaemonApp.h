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

#include "arch/Arch.h"
#include "base/Fwd.h"
#include "ipc/IpcServer.h"
#include "ipc/IpcMessage.h"
#include "ipc/IpcConnectionStateStore.h"
#include "inputleap/win32/DaemonCommandPolicy.h"
#include "inputleap/win32/DaemonTopologyTransaction.h"

#include <optional>
#include <functional>
#include <string>


namespace inputleap {

class IpcLogOutputter;
class MSWindowsWatchdog;
struct DaemonAppCommandTransactionTestAccess;
struct DaemonAppRealCommandChainTestAccess;
struct DaemonAppTopologyTransactionTestAccess;

class DaemonApp {

public:
    DaemonApp();
    virtual ~DaemonApp();
    int run(int argc, char** argv);
    void mainLoop(bool daemonized);

private:
    struct TopologyAuthority {
        std::filesystem::path configPath;
        std::string primaryScreen;
    };

    struct CommandTransactionServices {
        std::function<bool(const std::string&, const std::string&)> persist;
        std::function<bool(const std::string&, bool)> applyStart;
        std::function<bool()> stopAndWait;
        std::function<void(const std::string&)> acknowledge;
    };
    friend struct DaemonAppCommandTransactionTestAccess;
    friend struct DaemonAppRealCommandChainTestAccess;
    friend struct DaemonAppTopologyTransactionTestAccess;
    void daemonize();
    void foregroundError(const char* message);
    std::string logFilename();
    void handle_ipc_message(const Event& event);
    void handle_ipc_client_disconnected(const Event& event);
    void send_connection_relays(const std::vector<IpcConnectionStateStore::Relay>& relays);
    bool applyStartTransaction(const std::string& command, bool elevate,
                               const std::string& nonce,
                               std::function<bool()> applyRuntimeConfiguration = {},
                               const std::string& reloadExpectedNonce = {},
                               const IpcServerMessage* replyRequest = nullptr,
                               bool emitAcknowledgement = true);
    bool applyStopTransaction(const std::string& requestNonce,
                              const std::string& expectedAppliedNonce,
                              const IpcServerMessage* replyRequest = nullptr);
    bool applyReloadTransaction(const std::string& requestNonce,
                                const std::string& expectedAppliedNonce,
                                const IpcServerMessage* replyRequest = nullptr);
    TopologyTransactionResult applyTopologyTransaction(
        const IpcTopologyRequestMessage& request,
        const IpcServerMessage* replyRequest = nullptr);
    bool applyRestoredStartTransaction(
        const std::string& acceptedCommand, const std::string& persistedCommand,
        bool elevate, const std::string& nonce,
        const std::string& policyMarker, const std::string& appliedNonce,
        const std::string& reloadExpectedNonce = {});
    bool applyRestoredTopologyTransaction(
        const TopologyAuthority& authority,
        const std::string& acceptedCommand, const std::string& persistedCommand,
        bool elevate, const std::string& nonce,
        const std::string& policyMarker, const std::string& appliedNonce,
        const std::string& reloadExpectedNonce = {});
    std::optional<TopologyAuthority> topologyAuthorityForCommand(
        const ValidatedDaemonCommand& command) const;
    bool restorePersistedStartRequest(
        const std::string& persistedCommand,
        const std::string& acceptedCommand, bool elevate,
        const std::string& nonce,
        const std::string& policyMarker, const std::string& appliedNonce,
        const std::string& reloadExpectedNonce = {});
    bool restorePersistedStopRequest(
        const std::string& requestNonce,
        const std::string& expectedAppliedNonce,
        const std::string& policyMarker,
        const std::string& appliedNonce);
    void saveCommandSetting(const std::string& key, const std::string& value);
    std::string readCommandSetting(const std::string& key) const;

public:
    static DaemonApp* s_instance;

    MSWindowsWatchdog* m_watchdog;

private:
    struct AppliedReloadRequest {
        std::string requestNonce;
        std::string expectedAppliedNonce;
        std::string command;
        bool elevate{false};
    };

    IpcServer* m_ipcServer;
    IpcLogOutputter* m_ipcLogOutputter;
    IEventQueue* m_events;
    FileLogOutputter* m_fileLogOutputter;
    IpcConnectionStateStore m_connectionStateStore;
    std::optional<AppliedDaemonCommandRequest> m_lastAppliedStartRequest;
    std::optional<AppliedReloadRequest> m_lastAppliedReloadRequest;
    std::optional<AppliedDaemonStopRequest> m_lastAppliedStopRequest;
    std::optional<TopologyAuthority> m_topologyAuthority;
    std::optional<CommandTransactionServices> m_commandTransactionServicesOverride;
    HKEY m_commandRegistryRootOverride{nullptr};
    std::string m_commandRegistrySubkeyOverride;
    std::filesystem::path m_daemonExecutableOverride;
};

#define LOG_FILENAME "input-leapd.log"

} // namespace inputleap
