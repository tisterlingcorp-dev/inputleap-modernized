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

#include "inputleap/win32/DaemonApp.h"
#include "inputleap/win32/DaemonCommandPolicy.h"

#include "inputleap/App.h"
#include "inputleap/ArgParser.h"
#include "inputleap/ServerArgs.h"
#include "inputleap/ClientArgs.h"
#include "ipc/IpcClientProxy.h"
#include "ipc/IpcMessage.h"
#include "ipc/IpcLogOutputter.h"
#include "net/SocketMultiplexer.h"
#include "arch/XArch.h"
#include "base/Log.h"
#include "base/EventQueue.h"
#include "base/log_outputters.h"
#include "base/Log.h"
#include "common/DataDirectories.h"

#include "arch/win32/ArchMiscWindows.h"
#include "arch/win32/XArchWindows.h"
#include "inputleap/Screen.h"
#include "platform/MSWindowsScreen.h"
#include "platform/MSWindowsDebugOutputter.h"
#include "platform/MSWindowsWatchdog.h"
#include "platform/MSWindowsWatchdogLifecycle.h"
#include "platform/MSWindowsEventQueueBuffer.h"
#include "platform/MSWindowsUtil.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <string>
#include <chrono>
#include <iostream>
#include <sstream>

namespace inputleap {

DaemonApp* DaemonApp::s_instance = nullptr;

int
mainLoopStatic()
{
    DaemonApp::s_instance->mainLoop(true);
    return kExitSuccess;
}

int
mainLoopStatic(int, const char**)
{
    return ArchMiscWindows::runDaemon(mainLoopStatic);
}

DaemonApp::DaemonApp() :
    m_ipcServer(nullptr),
    m_ipcLogOutputter(nullptr),
    m_watchdog(nullptr),
    m_events(nullptr),
    m_fileLogOutputter(nullptr)
{
    s_instance = this;
}

DaemonApp::~DaemonApp()
{
}

void DaemonApp::saveCommandSetting(
    const std::string& key, const std::string& value)
{
    if (m_commandRegistryRootOverride == nullptr) {
        ARCH->setting(key, value);
        return;
    }

    HKEY registryKey = nullptr;
    const LONG result = RegCreateKeyExA(
        m_commandRegistryRootOverride, m_commandRegistrySubkeyOverride.c_str(),
        0, nullptr, REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr,
        &registryKey, nullptr);
    if (result != ERROR_SUCCESS) {
        throw std::runtime_error("could not access isolated command registry key");
    }
    try {
        ArchMiscWindows::setValue(registryKey, key.c_str(), value);
        RegCloseKey(registryKey);
    }
    catch (...) {
        RegCloseKey(registryKey);
        throw;
    }
}

std::string DaemonApp::readCommandSetting(const std::string& key) const
{
    if (m_commandRegistryRootOverride == nullptr) {
        return ARCH->setting(key);
    }

    HKEY registryKey = nullptr;
    if (RegOpenKeyExA(
            m_commandRegistryRootOverride, m_commandRegistrySubkeyOverride.c_str(),
            0, KEY_READ, &registryKey) != ERROR_SUCCESS) {
        return {};
    }
    try {
        const auto value = ArchMiscWindows::readValueString(registryKey, key.c_str());
        RegCloseKey(registryKey);
        return value;
    }
    catch (...) {
        RegCloseKey(registryKey);
        throw;
    }
}

bool DaemonApp::applyStartTransaction(const std::string& command, bool elevate,
                                      const std::string& nonce,
                                      std::function<bool()> applyRuntimeConfiguration,
                                      const std::string& reloadExpectedNonce,
                                      const IpcServerMessage* replyRequest,
                                      bool emitAcknowledgement)
{
    if (!nonce.empty() && m_lastAppliedStopRequest &&
        m_lastAppliedStopRequest->requestNonce == nonce) {
        return false;
    }

    CommandTransactionServices services;
    if (m_commandTransactionServicesOverride) {
        services = *m_commandTransactionServicesOverride;
    }
    else {
        services.persist = [this](const std::string& key, const std::string& value) {
            try {
                saveCommandSetting(key, value);
                return true;
            }
            catch (const std::runtime_error& error) {
                LOG_ERR("failed to save %s setting, %s", key.c_str(), error.what());
                return false;
            }
        };
        services.applyStart = [this](const std::string& acceptedCommand, bool acceptedElevate) {
            return m_watchdog->setCommandAndWait(
                acceptedCommand, acceptedElevate, std::chrono::seconds(35));
        };
        services.stopAndWait = [this] {
            return m_watchdog->stopCommandAndWait(std::chrono::seconds(35));
        };
        services.acknowledge = [this, replyRequest](const std::string& acceptedNonce) {
            if (!acceptedNonce.empty() && replyRequest != nullptr) {
                m_ipcServer->sendCommandAppliedResponse(*replyRequest, acceptedNonce);
            }
        };
    }

    bool runtimeEffectAttempted = false;
    const bool applied = DaemonCommandPolicy::persistApplyAndAcknowledgeOnce(
        command, elevate, nonce, m_lastAppliedStartRequest,
        services.persist,
        [&services, &command, elevate, &applyRuntimeConfiguration, &runtimeEffectAttempted] {
            runtimeEffectAttempted = true;
            if (!services.applyStart(command, elevate)) {
                return false;
            }
            return !applyRuntimeConfiguration || applyRuntimeConfiguration();
        },
        [&services, &nonce, emitAcknowledgement] {
            if (emitAcknowledgement) services.acknowledge(nonce);
        },
        reloadExpectedNonce);
    if (!applied && runtimeEffectAttempted) {
        if (!services.stopAndWait()) {
            LOG_ERR("failed to stop core after incomplete command transaction");
        }
        m_lastAppliedStartRequest.reset();
        m_lastAppliedReloadRequest.reset();
        m_lastAppliedStopRequest.reset();
    }
    if (applied) {
        m_lastAppliedReloadRequest.reset();
        m_lastAppliedStopRequest.reset();
        if (nonce.empty()) {
            m_lastAppliedStartRequest.reset();
        }
    }
    return applied;
}

bool DaemonApp::applyStopTransaction(const std::string& requestNonce,
                                     const std::string& expectedAppliedNonce,
                                     const IpcServerMessage* replyRequest)
{
    if (requestNonce.size() != 16 || expectedAppliedNonce.size() != 16 ||
        requestNonce == expectedAppliedNonce) {
        return false;
    }
    const bool matchingStopRequest =
        m_lastAppliedStopRequest &&
        m_lastAppliedStopRequest->requestNonce == requestNonce;
    if (matchingStopRequest) {
        if (m_lastAppliedStopRequest->expectedAppliedNonce != expectedAppliedNonce) {
            return false;
        }
    }
    else if (!m_lastAppliedStartRequest ||
        m_lastAppliedStartRequest->nonce != expectedAppliedNonce) {
        return false;
    }

    CommandTransactionServices services;
    if (m_commandTransactionServicesOverride) {
        services = *m_commandTransactionServicesOverride;
    }
    else {
        services.persist = [this](const std::string& key, const std::string& value) {
            try {
                saveCommandSetting(key, value);
                return true;
            }
            catch (const std::runtime_error& error) {
                LOG_ERR("failed to persist correlated stop field %s, %s",
                        key.c_str(), error.what());
                return false;
            }
        };
        services.applyStart = [this](const std::string& acceptedCommand, bool acceptedElevate) {
            return m_watchdog->setCommandAndWait(
                acceptedCommand, acceptedElevate, std::chrono::seconds(35));
        };
        services.stopAndWait = [this] {
            return m_watchdog->stopCommandAndWait(std::chrono::seconds(35));
        };
        services.acknowledge = [this, replyRequest](const std::string& acceptedNonce) {
            if (replyRequest != nullptr) {
                m_ipcServer->sendCommandAppliedResponse(*replyRequest, acceptedNonce);
            }
        };
    }

    bool runtimeStopWasAttempted = false;
    bool runtimeStopWasConfirmed = false;
    const bool stopped = DaemonCommandPolicy::persistStopAndAcknowledgeOnce(
        requestNonce, expectedAppliedNonce, m_lastAppliedStopRequest,
        services.persist,
        [&services, &runtimeStopWasAttempted, &runtimeStopWasConfirmed] {
            runtimeStopWasAttempted = true;
            runtimeStopWasConfirmed = services.stopAndWait();
            return runtimeStopWasConfirmed;
        },
        [&services, &requestNonce] { services.acknowledge(requestNonce); });
    if (stopped) {
        m_lastAppliedStartRequest.reset();
        m_lastAppliedReloadRequest.reset();
    }
    else if (runtimeStopWasAttempted) {
        m_lastAppliedStartRequest.reset();
        m_lastAppliedReloadRequest.reset();
        if (!runtimeStopWasConfirmed) {
            m_lastAppliedStopRequest.reset();
        }
    }
    return stopped;
}

bool DaemonApp::applyReloadTransaction(
    const std::string& requestNonce, const std::string& expectedAppliedNonce,
    const IpcServerMessage* replyRequest)
{
    if (requestNonce.size() != 16 || expectedAppliedNonce.size() != 16 ||
        requestNonce == expectedAppliedNonce || !m_lastAppliedStartRequest) {
        return false;
    }

    const auto currentRequest = *m_lastAppliedStartRequest;
    if (m_lastAppliedReloadRequest &&
        m_lastAppliedReloadRequest->requestNonce == requestNonce &&
        m_lastAppliedReloadRequest->expectedAppliedNonce == expectedAppliedNonce &&
        currentRequest.nonce == requestNonce &&
        m_lastAppliedReloadRequest->command == currentRequest.command &&
        m_lastAppliedReloadRequest->elevate == currentRequest.elevate) {
        const auto replay = *m_lastAppliedReloadRequest;
        const bool acknowledged = applyStartTransaction(
            currentRequest.command, currentRequest.elevate, requestNonce,
            {}, expectedAppliedNonce, replyRequest);
        if (acknowledged) {
            m_lastAppliedReloadRequest = replay;
        }
        return acknowledged;
    }

    if (expectedAppliedNonce != currentRequest.nonce) {
        return false;
    }

    const bool applied = applyStartTransaction(
        currentRequest.command, currentRequest.elevate, requestNonce,
        {}, expectedAppliedNonce, replyRequest);
    if (applied) {
        m_lastAppliedReloadRequest = AppliedReloadRequest{
            requestNonce, expectedAppliedNonce,
            currentRequest.command, currentRequest.elevate};
    }
    return applied;
}

TopologyTransactionResult DaemonApp::applyTopologyTransaction(
    const IpcTopologyRequestMessage& request,
    const IpcServerMessage* replyRequest)
{
    if (!m_topologyAuthority || !m_lastAppliedStartRequest ||
        m_lastAppliedStartRequest->nonce.size() != 16) {
        return {TopologyTransactionStatus::Rejected, {},
                "topology authority is unavailable"};
    }

    const auto prior = *m_lastAppliedStartRequest;
    DaemonTopologyTransaction transaction(m_topologyAuthority->configPath);
    const auto result = transaction.apply(
        TopologyTransactionRequest{
            request.requestNonce(), request.expectedGeneration(),
            request.payload(), m_topologyAuthority->primaryScreen},
        prior.nonce,
        {
            [this, &prior, &request] {
                return applyStartTransaction(
                    prior.command, prior.elevate, request.requestNonce(),
                    {}, prior.nonce, nullptr, false);
            },
            [this, &prior] {
                return applyStartTransaction(
                    prior.command, prior.elevate, prior.nonce,
                    {}, {}, nullptr, false);
            },
        });

    if ((result.status == TopologyTransactionStatus::Applied ||
         result.status == TopologyTransactionStatus::Replayed) &&
        replyRequest != nullptr &&
        !m_ipcServer->sendCommandAppliedResponse(
            *replyRequest, request.requestNonce())) {
        LOG_ERR("failed to send correlated topology acknowledgement");
    }
    return result;
}

bool DaemonApp::applyRestoredStartTransaction(
    const std::string& acceptedCommand, const std::string& persistedCommand,
    bool elevate, const std::string& nonce,
    const std::string& policyMarker, const std::string& appliedNonce,
    const std::string& reloadExpectedNonce)
{
    CommandTransactionServices services;
    if (m_commandTransactionServicesOverride) {
        services = *m_commandTransactionServicesOverride;
    }
    else {
        services.persist = [this](const std::string& key, const std::string& value) {
            try {
                saveCommandSetting(key, value);
                return true;
            }
            catch (const std::runtime_error& error) {
                LOG_ERR("failed to save %s setting, %s", key.c_str(), error.what());
                return false;
            }
        };
        services.applyStart = [this](const std::string& acceptedCommand, bool acceptedElevate) {
            return m_watchdog->setCommandAndWait(
                acceptedCommand, acceptedElevate, std::chrono::seconds(35));
        };
        services.stopAndWait = [this] {
            return m_watchdog->stopCommandAndWait(std::chrono::seconds(35));
        };
    }

    bool transactionComplete = services.applyStart(acceptedCommand, elevate);
    if (transactionComplete && !nonce.empty() && appliedNonce != nonce) {
        transactionComplete = services.persist("CommandAppliedNonce", nonce);
    }
    if (transactionComplete && !nonce.empty()) {
        transactionComplete = restorePersistedStartRequest(
            persistedCommand, acceptedCommand, elevate, nonce, policyMarker, nonce,
            reloadExpectedNonce);
    }

    if (!transactionComplete) {
        if (!services.stopAndWait()) {
            LOG_ERR("failed to stop core after incomplete restored command transaction");
        }
        m_lastAppliedStartRequest.reset();
        m_lastAppliedReloadRequest.reset();
        m_lastAppliedStopRequest.reset();
    }
    return transactionComplete;
}

std::optional<DaemonApp::TopologyAuthority>
DaemonApp::topologyAuthorityForCommand(
    const ValidatedDaemonCommand& command) const
{
    if (!command.server) {
        return std::nullopt;
    }

    auto arguments = command.arguments;
    ArgParser parser(nullptr);
    const char** argv = parser.getArgv(arguments);
    ServerArgs serverArgs;
    const bool parsed = parser.parseServerArgs(
        serverArgs, static_cast<int>(arguments.size()), argv);
    delete[] argv;
    if (!parsed || serverArgs.m_configFile.empty() || serverArgs.m_name.empty()) {
        return std::nullopt;
    }

    const auto requestedPath = path_from_utf8(serverArgs.m_configFile);
    std::error_code pathError;
    const auto authoritativePath =
        std::filesystem::weakly_canonical(requestedPath, pathError);
    if (!requestedPath.is_absolute() || pathError || authoritativePath.empty()) {
        return std::nullopt;
    }
    return TopologyAuthority{authoritativePath, serverArgs.m_name};
}

bool DaemonApp::applyRestoredTopologyTransaction(
    const TopologyAuthority& authority,
    const std::string& acceptedCommand, const std::string& persistedCommand,
    bool elevate, const std::string& nonce,
    const std::string& policyMarker, const std::string& appliedNonce,
    const std::string& reloadExpectedNonce)
{
    DaemonTopologyTransaction transaction(authority.configPath);
    const auto recovery = transaction.recover();
    if (recovery.action == TopologyRecoveryAction::Failed) {
        LOG_ERR("topology recovery failed closed, %s", recovery.error.c_str());
        return false;
    }

    if (!applyRestoredStartTransaction(
            acceptedCommand, persistedCommand, elevate, nonce,
            policyMarker, appliedNonce, reloadExpectedNonce)) {
        return false;
    }

    if (recovery.action == TopologyRecoveryAction::Committed ||
        recovery.action == TopologyRecoveryAction::RolledBack) {
        const auto& recoveredGeneration =
            recovery.action == TopologyRecoveryAction::Committed
                ? recovery.requestNonce : recovery.expectedGeneration;
        if (!m_lastAppliedStartRequest || recoveredGeneration.size() != 16) {
            LOG_ERR("topology recovery produced no valid runtime generation");
            CommandTransactionServices services =
                m_commandTransactionServicesOverride
                    ? *m_commandTransactionServicesOverride
                    : CommandTransactionServices{};
            if (services.stopAndWait) {
                services.stopAndWait();
            }
            m_lastAppliedStartRequest.reset();
            m_lastAppliedReloadRequest.reset();
            return false;
        }

        if (recovery.action == TopologyRecoveryAction::RolledBack) {
            CommandTransactionServices services;
            if (m_commandTransactionServicesOverride) {
                services = *m_commandTransactionServicesOverride;
            }
            else {
                services.persist = [this](
                    const std::string& key, const std::string& value) {
                    try {
                        saveCommandSetting(key, value);
                        return true;
                    }
                    catch (const std::runtime_error& error) {
                        LOG_ERR("failed to save recovered %s setting, %s",
                                key.c_str(), error.what());
                        return false;
                    }
                };
                services.stopAndWait = [this] {
                    return m_watchdog->stopCommandAndWait(
                        std::chrono::seconds(35));
                };
            }

            const auto recoveredMarker =
                DaemonCommandPolicy::persistedCommandMarker(
                    persistedCommand, elevate, recoveredGeneration);
            const bool recoveryPersisted = services.persist &&
                services.persist("CommandPolicyVersion", {}) &&
                services.persist("CommandAppliedNonce", {}) &&
                services.persist("CommandReloadExpectedNonce", {}) &&
                services.persist("Command", persistedCommand) &&
                services.persist("Elevate", elevate ? "1" : "0") &&
                services.persist("CommandRequestNonce", recoveredGeneration) &&
                services.persist("CommandPolicyVersion", recoveredMarker) &&
                services.persist("CommandAppliedNonce", recoveredGeneration);
            if (!recoveryPersisted ||
                !restorePersistedStartRequest(
                    persistedCommand, acceptedCommand, elevate, recoveredGeneration,
                    recoveredMarker, recoveredGeneration, {})) {
                LOG_ERR("failed to persist recovered topology generation");
                if (services.stopAndWait && !services.stopAndWait()) {
                    LOG_ERR("failed to stop core after incomplete topology recovery");
                }
                m_lastAppliedStartRequest.reset();
                m_lastAppliedReloadRequest.reset();
                m_lastAppliedStopRequest.reset();
                return false;
            }
        }
        else {
            m_lastAppliedStartRequest->nonce = recoveredGeneration;
            m_lastAppliedReloadRequest.reset();
        }
    }

    m_topologyAuthority = authority;
    if (recovery.action == TopologyRecoveryAction::RolledBack) {
        transaction.finalizeRecovery();
    }
    return true;
}

bool DaemonApp::restorePersistedStartRequest(
    const std::string& persistedCommand,
    const std::string& acceptedCommand, bool elevate, const std::string& nonce,
    const std::string& policyMarker, const std::string& appliedNonce,
    const std::string& reloadExpectedNonce)
{
    if (!reloadExpectedNonce.empty() &&
        (nonce.size() != 16 || reloadExpectedNonce.size() != 16 ||
         nonce == reloadExpectedNonce)) {
        m_lastAppliedStartRequest.reset();
        m_lastAppliedReloadRequest.reset();
        return false;
    }
    auto restored = DaemonCommandPolicy::restoreAppliedRequest(
        persistedCommand, elevate, nonce, policyMarker, appliedNonce,
        reloadExpectedNonce);
    if (!restored) {
        m_lastAppliedStartRequest.reset();
        m_lastAppliedReloadRequest.reset();
        return false;
    }
    restored->command = acceptedCommand;
    m_lastAppliedStartRequest = std::move(restored);
    if (reloadExpectedNonce.empty()) {
        m_lastAppliedReloadRequest.reset();
    }
    else {
        m_lastAppliedReloadRequest = AppliedReloadRequest{
            nonce, reloadExpectedNonce, acceptedCommand, elevate};
    }
    return true;
}

bool DaemonApp::restorePersistedStopRequest(
    const std::string& requestNonce,
    const std::string& expectedAppliedNonce,
    const std::string& policyMarker,
    const std::string& appliedNonce)
{
    auto restored = DaemonCommandPolicy::restoreAppliedStopRequest(
        requestNonce, expectedAppliedNonce, policyMarker, appliedNonce);
    if (!restored) {
        m_lastAppliedStopRequest.reset();
        return false;
    }
    m_lastAppliedStopRequest = std::move(restored);
    m_lastAppliedStartRequest.reset();
    m_lastAppliedReloadRequest.reset();
    return true;
}

int
DaemonApp::run(int argc, char** argv)
{
    // win32 instance needed for threading, etc.
    ArchMiscWindows::setInstanceWin32(GetModuleHandle(nullptr));

    Arch arch;
    arch.init();

    Log log;
    EventQueue events;
    m_events = &events;

    bool uninstall = false;
    try
    {
        // sends debug messages to visual studio console window.
        log.insert(new MSWindowsDebugOutputter());

        // default log level to system setting.
        std::string logLevel = arch.setting("LogLevel");
        if (logLevel != "")
            log.setFilter(logLevel.c_str());

        bool foreground = false;

        for (int i = 1; i < argc; ++i) {
            std::string arg(argv[i]);

            if (arg == "/f" || arg == "-f") {
                foreground = true;
            }
            else if (arg == "/install") {
                uninstall = true;
                arch.installDaemon();
                return kExitSuccess;
            }
            else if (arg == "/uninstall") {
                arch.uninstallDaemon();
                return kExitSuccess;
            }
            else {
                std::stringstream ss;
                ss << "Unrecognized argument: " << arg;
                foregroundError(ss.str().c_str());
                return kExitArgs;
            }
        }

        if (foreground) {
            // add a console to catch Ctrl+C and run process in foreground
            // instead of daemonizing. useful for debugging.
            if (IsDebuggerPresent())
                AllocConsole();
            mainLoop(false);
        }
        else {
            arch.daemonize("InputLeap", mainLoopStatic);
        }

        return kExitSuccess;
    }
    catch (std::runtime_error& e) {
        std::string message = e.what();
        if (uninstall && (message.find("The service has not been started") != std::string::npos)) {
            // TODO: if we're keeping this use error code instead (what is it?!).
            // HACK: this message happens intermittently, not sure where from but
            // it's quite misleading for the user. they thing something has gone
            // horribly wrong, but it's just the service manager reporting a false
            // positive (the service has actually shut down in most cases).
        }
        else {
            foregroundError(message.c_str());
        }
        return kExitFailed;
    }
    catch (std::exception& e) {
        foregroundError(e.what());
        return kExitFailed;
    }
    catch (...) {
        foregroundError("Unrecognized error.");
        return kExitFailed;
    }
}

void
DaemonApp::mainLoop(bool daemonized)
{
    try
    {
        DAEMON_RUNNING(true);

        if (daemonized) {
            m_fileLogOutputter = new FileLogOutputter(logFilename().c_str());
            CLOG->insert(m_fileLogOutputter);
        }

        // create socket multiplexer.  this must happen after daemonization
        // on unix because threads evaporate across a fork().
        SocketMultiplexer multiplexer;
        auto cleanup = MSWindowsWatchdogLifecycle::makeScopeExit([this] {
            if (m_watchdog != nullptr) {
                m_watchdog->setFileLogOutputter(nullptr);
                m_watchdog->stop();
                delete m_watchdog;
                m_watchdog = nullptr;
            }
            if (m_ipcServer != nullptr) {
                m_events->remove_handler(
                    EventType::IPC_SERVER_MESSAGE_RECEIVED, m_ipcServer);
                m_events->remove_handler(
                    EventType::IPC_SERVER_CLIENT_DISCONNECTED, m_ipcServer);
            }
            if (m_ipcLogOutputter != nullptr) {
                CLOG->remove(m_ipcLogOutputter);
                delete m_ipcLogOutputter;
                m_ipcLogOutputter = nullptr;
            }
            delete m_ipcServer;
            m_ipcServer = nullptr;
            if (m_fileLogOutputter != nullptr) {
                CLOG->remove(m_fileLogOutputter);
                delete m_fileLogOutputter;
                m_fileLogOutputter = nullptr;
            }
            DAEMON_RUNNING(false);
        });

        // uses event queue, must be created here.
        m_ipcServer = new IpcServer(m_events, &multiplexer);

        // send logging to gui via ipc, log system adopts outputter.
        m_ipcLogOutputter = new IpcLogOutputter(*m_ipcServer, kIpcClientGui, true);
        CLOG->insert(m_ipcLogOutputter);

        m_watchdog = new MSWindowsWatchdog(daemonized, false, *m_ipcServer, *m_ipcLogOutputter);
        m_watchdog->setFileLogOutputter(m_fileLogOutputter);

        m_events->add_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, m_ipcServer,
                              [this](const auto& event) { handle_ipc_message(event); });
        m_events->add_handler(EventType::IPC_SERVER_CLIENT_DISCONNECTED, m_ipcServer,
                              [this](const auto& event) { handle_ipc_client_disconnected(event); });
        m_ipcServer->listen();

        // install the platform event queue to handle service stop events.
        m_events->set_buffer(std::make_unique<MSWindowsEventQueueBuffer>(m_events));

        std::string command = readCommandSetting("Command");
        bool elevate = readCommandSetting("Elevate") == "1";
        const std::string commandRequestNonce =
            readCommandSetting("CommandRequestNonce");
        const std::string commandPolicyVersion =
            readCommandSetting("CommandPolicyVersion");
        const std::string commandAppliedNonce =
            readCommandSetting("CommandAppliedNonce");
        const std::string commandReloadExpectedNonce =
            readCommandSetting("CommandReloadExpectedNonce");
        const std::string commandStopRequestNonce =
            readCommandSetting("CommandStopRequestNonce");
        const std::string commandStopExpectedAppliedNonce =
            readCommandSetting("CommandStopExpectedAppliedNonce");
        const std::string commandStopPolicyVersion =
            readCommandSetting("CommandStopPolicyVersion");
        const std::string commandStopAppliedNonce =
            readCommandSetting("CommandStopAppliedNonce");
        std::optional<ValidatedDaemonCommand> validatedCommand;
        if (!command.empty()) {
            const auto daemonExecutable = DaemonCommandPolicy::currentProcessExecutable();
            if (commandRequestNonce.empty()) {
                validatedCommand = DaemonCommandPolicy::validatePersistedCommand(
                    command, elevate, commandPolicyVersion, daemonExecutable);
            }
            else if (commandPolicyVersion ==
                     (commandReloadExpectedNonce.empty()
                          ? DaemonCommandPolicy::persistedCommandMarker(
                              command, elevate, commandRequestNonce)
                          : DaemonCommandPolicy::persistedCommandMarker(
                              command, elevate, commandRequestNonce,
                              commandReloadExpectedNonce))) {
                validatedCommand = DaemonCommandPolicy::validateCommandLine(
                    command, daemonExecutable);
            }
            if (!validatedCommand) {
                m_lastAppliedStartRequest.reset();
                LOG_WARN("discarding untrusted persisted core command");
                try {
                    saveCommandSetting("Command", std::string());
                    saveCommandSetting("Elevate", std::string("0"));
                    saveCommandSetting("CommandRequestNonce", std::string());
                    saveCommandSetting("CommandAppliedNonce", std::string());
                    saveCommandSetting("CommandReloadExpectedNonce", std::string());
                    saveCommandSetting("CommandPolicyVersion", std::string());
                }
                catch (const std::runtime_error& error) {
                    LOG_ERR("failed to clear untrusted persisted command, %s",
                            error.what());
                }
            }
        }

        m_watchdog->startAsync();
        if (validatedCommand) {
            LOG_INFO("applying validated last known core command");
            const auto topologyAuthority =
                topologyAuthorityForCommand(*validatedCommand);
            const bool restored = topologyAuthority
                ? applyRestoredTopologyTransaction(
                    *topologyAuthority, validatedCommand->command, command,
                    elevate, commandRequestNonce, commandPolicyVersion,
                    commandAppliedNonce, commandReloadExpectedNonce)
                : applyRestoredStartTransaction(
                    validatedCommand->command, command, elevate,
                    commandRequestNonce, commandPolicyVersion,
                    commandAppliedNonce, commandReloadExpectedNonce);
            if (!restored) {
                LOG_ERR("validated persisted core command could not be applied");
            }
        }
        else {
            restorePersistedStopRequest(
                commandStopRequestNonce, commandStopExpectedAppliedNonce,
                commandStopPolicyVersion, commandStopAppliedNonce);
        }

        m_events->loop();
    }
    catch (std::exception& e) {
        LOG_CRIT("An error occurred: %s", e.what());
    }
    catch (...) {
        LOG_CRIT("An unknown error occurred.\n");
    }
}

void
DaemonApp::foregroundError(const char* message)
{
    MessageBox(nullptr, message, "InputLeap Service", MB_OK | MB_ICONERROR);
}

std::string
DaemonApp::logFilename()
{
    std::string logFilename = ARCH->setting("LogFilename");
    if (logFilename.empty())
        logFilename = inputleap::path_to_utf8(inputleap::DataDirectories::global() / LOG_FILENAME);
    MSWindowsUtil::createDirectory(logFilename, true);
    return logFilename;
}

void DaemonApp::handle_ipc_message(const Event& e)
{
    const auto& received = e.get_data_as<IpcServerMessage>();
    const IpcMessage& m = *received.message;
    switch (m.type()) {
        case kIpcCommand:
        case kIpcStartRequest: {
            if (received.origin != kIpcClientGui) {
                LOG_WARN("rejected ipc command from non-gui origin=%d", received.origin);
                return;
            }
            std::string startNonce;
            std::string command;
            bool elevate = false;
            std::optional<TopologyAuthority> requestedTopologyAuthority;
            if (m.type() == kIpcStartRequest) {
                const auto& start = static_cast<const IpcStartRequestMessage&>(m);
                startNonce = start.nonce();
                command = start.command();
                elevate = start.elevate();
            }
            else {
                const auto& legacy = static_cast<const IpcCommandMessage&>(m);
                command = legacy.command();
                elevate = legacy.elevate();
            }

            // if empty quotes, clear.
            if (command == "\"\"") {
                command.clear();
            }

            std::function<bool()> applyRuntimeConfiguration;
            if (!command.empty()) {
                const auto daemonExecutable = m_daemonExecutableOverride.empty()
                    ? DaemonCommandPolicy::currentProcessExecutable()
                    : m_daemonExecutableOverride;
                const auto validatedCommand = DaemonCommandPolicy::validateCommandLine(
                    command, daemonExecutable);
                if (!validatedCommand) {
                    LOG_ERR("rejected ipc command: executable or arguments are not allowed");
                    return;
                }
                command = validatedCommand->command;
                auto argsArray = validatedCommand->arguments;
                const bool server = validatedCommand->server;
                LOG_DEBUG("new validated core command, elevate=%d", elevate);

                ArgParser argParser(nullptr);
                const char** argv = argParser.getArgv(argsArray);
                ServerArgs serverArgs;
                ClientArgs clientArgs;
                int argc = static_cast<int>(argsArray.size());
                ArgsBase* argBase = nullptr;
                bool parsed = false;

                if (server) {
                    parsed = argParser.parseServerArgs(serverArgs, argc, argv);
                    argBase = &serverArgs;
                }
                else {
                    parsed = argParser.parseClientArgs(clientArgs, argc, argv);
                    argBase = &clientArgs;
                }

                delete[] argv;
                if (!parsed) {
                    LOG_ERR("rejected ipc command: invalid core arguments");
                    return;
                }

                requestedTopologyAuthority =
                    topologyAuthorityForCommand(*validatedCommand);
                if (server && !requestedTopologyAuthority) {
                    LOG_WARN("server command has no trustworthy topology authority");
                }

                const std::string logLevel = argBase->m_logFilter != nullptr
                    ? std::string(argBase->m_logFilter) : std::string();
                const bool hasLogFile = argBase->m_logFile != nullptr;
                const std::string logFilename = hasLogFile
                    ? std::string(argBase->m_logFile) : std::string();
                if (hasLogFile && m_fileLogOutputter != nullptr) {
                    auto launchArguments = validatedCommand->arguments;
                    for (auto it = launchArguments.begin();
                         it != launchArguments.end();) {
                        if (*it != "--log") {
                            ++it;
                            continue;
                        }
                        auto afterLogFile = it;
                        ++afterLogFile;
                        if (afterLogFile == launchArguments.end()) {
                            LOG_ERR("rejected ipc command: missing log file argument");
                            return;
                        }
                        ++afterLogFile;
                        it = launchArguments.erase(it, afterLogFile);
                    }
                    command = DaemonCommandPolicy::serializeArguments(launchArguments);
                    LOG_DEBUG("removed log file argument from core command");
                }
                applyRuntimeConfiguration = [this, logLevel, logFilename, hasLogFile] {
                    if (!logLevel.empty() && !CLOG->setFilter(logLevel.c_str())) {
                        LOG_ERR("rejected runtime log level after core start confirmation");
                        return false;
                    }
                    if (m_fileLogOutputter != nullptr) {
                        m_watchdog->setFileLogOutputter(
                            hasLogFile ? m_fileLogOutputter : nullptr);
                        m_fileLogOutputter->setLogFilename(logFilename.c_str());
                    }
                    return true;
                };
            }
            else {
                LOG_DEBUG("empty command, elevate=%d", elevate);
            }

            const bool startApplied = applyStartTransaction(
                command, elevate, startNonce,
                std::move(applyRuntimeConfiguration), {}, &received);
            if (!startApplied) {
                LOG_ERR("correlated core start was not durably applied");
            }
            else {
                m_topologyAuthority = std::move(requestedTopologyAuthority);
            }
            break;
        }

        case kIpcStopRequest: {
            if (received.origin != kIpcClientGui) {
                LOG_WARN("rejected ipc stop from non-gui origin=%d", received.origin);
                return;
            }
            const auto& stop = static_cast<const IpcStopRequestMessage&>(m);
            if (!applyStopTransaction(
                    stop.requestNonce(), stop.expectedAppliedNonce(),
                    &received)) {
                LOG_ERR("correlated core stop was not confirmed");
            }
            break;
        }

        case kIpcReloadRequest: {
            if (received.origin != kIpcClientGui) {
                LOG_WARN("rejected ipc reload from non-gui origin=%d", received.origin);
                return;
            }
            const auto& reload = static_cast<const IpcReloadRequestMessage&>(m);
            if (!applyReloadTransaction(
                    reload.requestNonce(), reload.expectedAppliedNonce(),
                    &received)) {
                LOG_ERR("correlated core reload was not durably applied");
            }
            break;
        }

        case kIpcRuntimeStatusRequest: {
            if (received.origin != kIpcClientGui) {
                LOG_WARN("rejected ipc runtime status query from non-gui origin=%d",
                         received.origin);
                return;
            }
            const auto& query =
                static_cast<const IpcRuntimeStatusRequestMessage&>(m);
            const auto state = m_watchdog == nullptr
                ? IpcRuntimeState::Unknown
                : (m_watchdog->isProcessActive()
                    ? IpcRuntimeState::Running
                    : IpcRuntimeState::Stopped);
            const std::string appliedNonce = m_lastAppliedStartRequest
                ? m_lastAppliedStartRequest->nonce
                : std::string();
            if (!m_ipcServer->sendRuntimeStatusResponse(
                    received, 1, state, appliedNonce)) {
                LOG_ERR("failed to send correlated runtime status response");
            }
            break;
        }

        case kIpcTopologyRequest: {
            if (received.origin != kIpcClientGui) {
                LOG_WARN("rejected ipc topology from non-gui origin=%d",
                         received.origin);
                return;
            }
            const auto& topology =
                static_cast<const IpcTopologyRequestMessage&>(m);
            const auto result = applyTopologyTransaction(topology, &received);
            if (result.status != TopologyTransactionStatus::Applied &&
                result.status != TopologyTransactionStatus::Replayed) {
                LOG_ERR("atomic topology transaction failed: %s",
                        result.error.c_str());
            }
            break;
        }

        case kIpcHello: {
            const auto& hm = static_cast<const IpcHelloMessage&>(m);
            if (hm.clientType() != received.origin) {
                LOG_WARN("rejected ipc hello with mismatched origin=%d claimed=%d",
                         received.origin, hm.clientType());
                return;
            }
            std::string type;
            switch (hm.clientType()) {
                case kIpcClientGui: type = "gui"; break;
                case kIpcClientNode: type = "node"; break;
                default: type = "unknown"; break;
            }

            LOG_DEBUG("ipc hello, type=%s", type.c_str());

            const char * serverstatus = m_watchdog->isProcessActive() ? "active" : "not active";

            // using CLOG_PRINT here allows the GUI to see that the server status
            // regardless of which log level is set
            LOG_PRINT("server status: %s", serverstatus);

            m_ipcLogOutputter->notifyBuffer();
            if (hm.clientType() == kIpcClientGui) {
                send_connection_relays(m_connectionStateStore.clientConnected(
                    kIpcClientGui, received.connectionId));
            }
            else if (hm.clientType() == kIpcClientNode) {
                send_connection_relays(m_connectionStateStore.clientConnected(
                    kIpcClientNode, received.connectionId));
            }
            break;
        }
        case kIpcConnectionState:
            if (received.origin != kIpcClientNode) {
                LOG_WARN("rejected ipc connection state from non-node origin=%d",
                         received.origin);
                return;
            }
            send_connection_relays(m_connectionStateStore.receive(
                received.origin, received.connectionId,
                static_cast<const IpcConnectionStateMessage&>(m)));
            break;
    }
}

void DaemonApp::send_connection_relays(
    const std::vector<IpcConnectionStateStore::Relay>& relays)
{
    for (const auto& relay : relays) {
        m_ipcServer->send(relay.message, relay.recipient);
    }
}

void DaemonApp::handle_ipc_client_disconnected(const Event& event)
{
    const auto& disconnected = event.get_data_as<IpcServerClientDisconnectedInfo>();
    send_connection_relays(m_connectionStateStore.clientDisconnected(
        disconnected.clientType, disconnected.connectionId));
}

} // namespace inputleap
