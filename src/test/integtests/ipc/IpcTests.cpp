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

// TODO: fix, tests failing intermittently on mac.
#ifndef WINAPI_CARBON

#define INPUTLEAP_TEST_ENV

#include "test/global/TestEventQueue.h"
#include "ipc/IpcServer.h"
#include "ipc/IpcClient.h"
#include "ipc/IpcServerProxy.h"
#include "ipc/IpcMessage.h"
#include "ipc/IpcClientProxy.h"
#include "ipc/Ipc.h"
#include "net/SocketMultiplexer.h"
#include "net/XSocket.h"
#include "mt/Thread.h"
#include "arch/Arch.h"
#include "base/Log.h"
#include "base/EventQueue.h"
#include "base/EventQueueTimer.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <random>


#ifdef _WIN32
#include "arch/win32/ArchMiscWindows.h"
#include "base/log_outputters.h"
#include "inputleap/win32/DaemonApp.h"
#include "ipc/IpcLogOutputter.h"
#include "platform/MSWindowsWatchdog.h"
#include <windows.h>
#include <cstdint>
#include <fstream>
#include <thread>
#include <vector>
#endif

#define TEST_IPC_PORT m_testIpcPort
#define TEST_AUTHENTICATED_IPC_PORT m_authenticatedIpcPort

namespace inputleap {

#ifdef _WIN32
struct DaemonAppRealCommandChainTestAccess
{
    static void configure(
        DaemonApp& app, IpcServer& server, MSWindowsWatchdog& watchdog,
        IpcLogOutputter& ipcLogOutputter, FileLogOutputter& fileLogOutputter,
        IEventQueue& events,
        HKEY registryRoot, const std::string& registrySubkey,
        const std::filesystem::path& daemonExecutable)
    {
        app.m_ipcServer = &server;
        app.m_watchdog = &watchdog;
        app.m_ipcLogOutputter = &ipcLogOutputter;
        app.m_fileLogOutputter = &fileLogOutputter;
        app.m_events = &events;
        app.m_commandRegistryRootOverride = registryRoot;
        app.m_commandRegistrySubkeyOverride = registrySubkey;
        app.m_daemonExecutableOverride = daemonExecutable;
        events.add_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server,
                           [&app](const Event& event) {
            app.handle_ipc_message(event);
        });
    }
};

static std::vector<std::vector<std::string>> readCapturedArguments(
    const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    std::vector<std::vector<std::string>> records;
    while (input) {
        std::uint32_t argc = 0;
        if (!input.read(reinterpret_cast<char*>(&argc), sizeof(argc))) {
            break;
        }
        std::vector<std::string> arguments;
        for (std::uint32_t index = 0; index < argc; ++index) {
            std::uint32_t size = 0;
            if (!input.read(reinterpret_cast<char*>(&size), sizeof(size))) {
                return {};
            }
            std::string argument(size, '\0');
            if (size != 0 && !input.read(argument.data(), size)) {
                return {};
            }
            arguments.push_back(std::move(argument));
        }
        records.push_back(std::move(arguments));
    }
    return records;
}

static std::vector<std::vector<std::string>> waitForCapturedArguments(
    const std::filesystem::path& path, std::size_t expectedRecords)
{
    for (int attempt = 0; attempt < 40; ++attempt) {
        auto records = readCapturedArguments(path);
        if (records.size() >= expectedRecords) {
            return records;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return readCapturedArguments(path);
}
#endif

class IpcTests : public ::testing::Test
{
public:
    IpcTests();
    virtual ~IpcTests();

    void connectToServer_handle_message_received(const Event& e);
    void sendMessageToServer_serverHandleMessageReceived(const Event& e);
    void sendMessageToClient_server_handle_client_connected(const Event& e);
    void sendMessageToClient_client_handle_message_received(const Event& e);
    std::unique_ptr<IpcServer> listenOnAvailablePort(
        SocketMultiplexer* socketMultiplexer,
        IpcPeerAuthenticationMode authenticationMode,
        const std::filesystem::path& daemonExecutable = {});

public:
    SocketMultiplexer m_multiplexer;
    bool m_connectToServer_helloMessageReceived;
    bool m_connectToServer_hasClientNode;
    IpcServer* m_connectToServer_server;
    std::string m_sendMessageToServer_receivedString;
    bool m_sendMessageToServer_receivedElevate{true};
    std::string m_sendMessageToClient_receivedString;
    EIpcClientType m_receivedOrigin{kIpcClientUnknown};
    std::shared_ptr<IpcMessage> m_retainedMessage;
    IpcClient* m_sendMessageToServer_client;
    IpcServer* m_sendMessageToClient_server;
    TestEventQueue m_events;
    int m_testIpcPort{0};
    int m_authenticatedIpcPort{0};

};

TEST_F(IpcTests, connectToServer)
{
    SocketMultiplexer socketMultiplexer;
    auto serverOwner = listenOnAvailablePort(
        &socketMultiplexer, IpcPeerAuthenticationMode::DisabledForTests);
    auto& server = *serverOwner;
    m_connectToServer_server = &server;

    m_events.add_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server,
                         [this](const auto& e)
    {
        connectToServer_handle_message_received(e);
    });

    IpcClient client(&m_events, &socketMultiplexer, TEST_IPC_PORT);
    client.connect();

    m_events.initQuitTimeout(5);
    m_events.loop();
    m_events.remove_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server);
    m_events.cleanupQuitTimeout();

    EXPECT_EQ(true, m_connectToServer_helloMessageReceived);
    EXPECT_EQ(true, m_connectToServer_hasClientNode);
}

TEST_F(IpcTests, clientAddressRejectsZeroPort)
{
    EXPECT_THROW(NetworkAddress("127.0.0.1", 0), XSocketAddress);
}

#ifdef _WIN32
TEST_F(IpcTests, AuthenticatedServerAcceptsOfficialGuiProcess)
{
    wchar_t modulePath[32768]{};
    const DWORD moduleLength = GetModuleFileNameW(
        nullptr, modulePath, static_cast<DWORD>(std::size(modulePath)));
    ASSERT_GT(moduleLength, 0u);
    const auto helper = std::filesystem::path(modulePath).parent_path() /
        "ipcpeerprocessclienthelper.exe";
    ASSERT_TRUE(std::filesystem::exists(helper));

    const auto root = std::filesystem::temp_directory_path() /
        ("inputleap-ipc-server-peer-auth-" + std::to_string(GetCurrentProcessId()) +
         "-" + std::to_string(std::random_device{}()));
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    const auto daemon = root / "input-leapd.exe";
    const auto gui = root / "input-leap.exe";
    std::ofstream(daemon, std::ios::binary).put('\0');
    std::filesystem::copy_file(
        helper, gui, std::filesystem::copy_options::overwrite_existing);

    PROCESS_INFORMATION process{};
    EIpcClientType receivedOrigin = kIpcClientUnknown;
    {
        SocketMultiplexer socketMultiplexer;
        auto serverOwner = listenOnAvailablePort(
            &socketMultiplexer,
            IpcPeerAuthenticationMode::RequireOperatingSystemIdentity, daemon);
        auto& server = *serverOwner;
        m_events.add_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server,
                             [&](const Event& event) {
            const auto& received = event.get_data_as<IpcServerMessage>();
            if (received.message->type() == kIpcHello) {
                receivedOrigin = received.origin;
                m_events.raiseQuitEvent();
            }
        });

        std::wstring commandLine = L"\"" + gui.native() + L"\" " +
            std::to_wstring(TEST_AUTHENTICATED_IPC_PORT);
        std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
        mutableCommand.push_back(L'\0');
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        ASSERT_TRUE(CreateProcessW(
            gui.native().c_str(), mutableCommand.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, root.native().c_str(), &startup, &process));

        m_events.initQuitTimeout(5);
        m_events.loop();
        m_events.cleanupQuitTimeout();
        m_events.remove_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server);
        EXPECT_EQ(receivedOrigin, kIpcClientGui);
    }

    EXPECT_EQ(WaitForSingleObject(process.hProcess, 5000), WAIT_OBJECT_0);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    std::error_code cleanupError;
    std::filesystem::remove_all(root, cleanupError);
}

TEST_F(IpcTests, AuthenticatedServerRejectsArbitraryLocalProcess)
{
    wchar_t modulePath[32768]{};
    const DWORD moduleLength = GetModuleFileNameW(
        nullptr, modulePath, static_cast<DWORD>(std::size(modulePath)));
    ASSERT_GT(moduleLength, 0u);
    const auto helper = std::filesystem::path(modulePath).parent_path() /
        "ipcpeerprocessclienthelper.exe";
    ASSERT_TRUE(std::filesystem::exists(helper));

    const auto root = std::filesystem::temp_directory_path() /
        ("inputleap-ipc-server-peer-reject-" + std::to_string(GetCurrentProcessId()) +
         "-" + std::to_string(std::random_device{}()));
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    const auto daemon = root / "input-leapd.exe";
    const auto attacker = root / "malware.exe";
    std::ofstream(daemon, std::ios::binary).put('\0');
    std::filesystem::copy_file(
        helper, attacker, std::filesystem::copy_options::overwrite_existing);

    PROCESS_INFORMATION process{};
    bool connectedEvent = false;
    bool messageEvent = false;
    {
        SocketMultiplexer socketMultiplexer;
        auto serverOwner = listenOnAvailablePort(
            &socketMultiplexer,
            IpcPeerAuthenticationMode::RequireOperatingSystemIdentity, daemon);
        auto& server = *serverOwner;
        m_events.add_handler(EventType::IPC_SERVER_CLIENT_CONNECTED, &server,
                             [&](const Event&) { connectedEvent = true; });
        m_events.add_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server,
                             [&](const Event&) { messageEvent = true; });
        auto* timer = m_events.newOneShotTimer(0.25, nullptr);
        m_events.add_handler(EventType::TIMER, timer,
                             [&](const Event&) { m_events.raiseQuitEvent(); });

        std::wstring commandLine = L"\"" + attacker.native() + L"\" " +
            std::to_wstring(TEST_AUTHENTICATED_IPC_PORT);
        std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
        mutableCommand.push_back(L'\0');
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        ASSERT_TRUE(CreateProcessW(
            attacker.native().c_str(), mutableCommand.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, root.native().c_str(), &startup, &process));

        m_events.loop();
        m_events.remove_handler(EventType::TIMER, timer);
        delete timer;
        m_events.remove_handler(EventType::IPC_SERVER_CLIENT_CONNECTED, &server);
        m_events.remove_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server);
    }

    EXPECT_FALSE(connectedEvent);
    EXPECT_FALSE(messageEvent);
    EXPECT_EQ(WaitForSingleObject(process.hProcess, 5000), WAIT_OBJECT_0);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    std::error_code cleanupError;
    std::filesystem::remove_all(root, cleanupError);
}
#endif

TEST_F(IpcTests, nodeSendsConnectionStateToServerAfterHello)
{
    SocketMultiplexer socketMultiplexer;
    auto serverOwner = listenOnAvailablePort(
        &socketMultiplexer, IpcPeerAuthenticationMode::DisabledForTests);
    auto& server = *serverOwner;

    // Event handler sends a valid node-owned connection state to the server.
    m_events.add_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server,
                         [this](const auto& e)
    {
        sendMessageToServer_serverHandleMessageReceived(e);
    });

    IpcClient client(&m_events, &socketMultiplexer, TEST_IPC_PORT);
    client.connect();
    m_sendMessageToServer_client = &client;

    m_events.initQuitTimeout(5);
    m_events.loop();
    m_events.remove_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server);
    m_events.cleanupQuitTimeout();

    EXPECT_EQ("test", m_sendMessageToServer_receivedString);
    EXPECT_FALSE(m_sendMessageToServer_receivedElevate);
}

TEST_F(IpcTests, serverMessageCarriesOriginAndOwnedPayload)
{
    SocketMultiplexer socketMultiplexer;
    auto serverOwner = listenOnAvailablePort(
        &socketMultiplexer, IpcPeerAuthenticationMode::DisabledForTests);
    auto& server = *serverOwner;
    m_events.add_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server,
                         [this](const Event& event) {
        const auto& received = event.get_data_as<IpcServerMessage>();
        if (received.message->type() == kIpcHello) {
            m_receivedOrigin = received.origin;
            m_retainedMessage = received.message;
            m_events.raiseQuitEvent();
        }
    });
    {
        IpcClient client(&m_events, &socketMultiplexer, TEST_IPC_PORT);
        client.connect();
        m_events.initQuitTimeout(5);
        m_events.loop();
    }
    m_events.remove_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server);
    m_events.cleanupQuitTimeout();

    ASSERT_TRUE(m_retainedMessage);
    EXPECT_EQ(m_receivedOrigin, kIpcClientNode);
    EXPECT_EQ(static_cast<const IpcHelloMessage&>(*m_retainedMessage).clientType(),
              kIpcClientNode);
}

TEST_F(IpcTests, distinctConnectionStatesAreQueuedUntilHelloThenAllSent)
{
    SocketMultiplexer socketMultiplexer;
    auto serverOwner = listenOnAvailablePort(
        &socketMultiplexer, IpcPeerAuthenticationMode::DisabledForTests);
    auto& server = *serverOwner;
    int helloCount = 0;
    int stateCount = 0;
    m_events.add_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server,
                         [&](const Event& event) {
        const auto& message = *event.get_data_as<IpcServerMessage>().message;
        helloCount += message.type() == kIpcHello;
        stateCount += message.type() == kIpcConnectionState;
        if (stateCount == 2) m_events.raiseQuitEvent();
    });
    IpcClient client(&m_events, &socketMultiplexer, TEST_IPC_PORT);
    EXPECT_EQ(client.sendConnectionState(IpcConnectionStateMessage(
                  IpcConnectionState::Connected, IpcConnectionRole::ClientPeer,
                  IpcIdentityPresence::LegacyUnavailable, "")),
              IpcClient::SendResult::Queued);
    EXPECT_EQ(client.sendConnectionState(IpcConnectionStateMessage(
                  IpcConnectionState::Connected, IpcConnectionRole::ServerPeer,
                  IpcIdentityPresence::Known, "peer-two")),
              IpcClient::SendResult::Queued);
    EXPECT_EQ(stateCount, 0);
    client.connect();
    m_events.initQuitTimeout(5);
    m_events.loop();
    EXPECT_EQ(helloCount, 1);
    EXPECT_EQ(stateCount, 2);
    client.disconnect();
    client.disconnect();
    m_events.remove_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server);
    m_events.cleanupQuitTimeout();
}

TEST_F(IpcTests, clientReconnectsAndReplaysStateAfterServerRestart)
{
    SocketMultiplexer socketMultiplexer;
    auto server = listenOnAvailablePort(
        &socketMultiplexer, IpcPeerAuthenticationMode::DisabledForTests);

    int helloCount = 0;
    int stateCount = 0;
    int targetStateCount = 1;
    auto installHandler = [&] {
        m_events.add_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, server.get(),
                             [&](const Event& event) {
            const auto type = event.get_data_as<IpcServerMessage>().message->type();
            helloCount += type == kIpcHello;
            if (type == kIpcConnectionState) {
                ++stateCount;
                if (stateCount == targetStateCount) {
                    m_events.raiseQuitEvent();
                }
            }
        });
    };
    installHandler();

    IpcClient client(&m_events, &socketMultiplexer, TEST_IPC_PORT);
    EXPECT_EQ(client.sendConnectionState(IpcConnectionStateMessage(
                  IpcConnectionState::Connected, IpcConnectionRole::ServerPeer,
                  IpcIdentityPresence::Known, "replay-peer")),
              IpcClient::SendResult::Queued);
    client.connect();
    m_events.initQuitTimeout(5);
    m_events.loop();
    m_events.cleanupQuitTimeout();
    ASSERT_EQ(helloCount, 1);
    ASSERT_EQ(stateCount, 1);

    m_events.remove_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, server.get());
    server.reset();
    server = std::make_unique<IpcServer>(
        &m_events, &socketMultiplexer, TEST_IPC_PORT,
        IpcPeerAuthenticationMode::DisabledForTests);
    server->listen();
    targetStateCount = 2;
    installHandler();

    m_events.initQuitTimeout(8);
    m_events.loop();
    m_events.cleanupQuitTimeout();

    EXPECT_EQ(helloCount, 2);
    EXPECT_EQ(stateCount, 2);
    client.disconnect();
    m_events.remove_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, server.get());
}

TEST_F(IpcTests, sendMessageToClient)
{
    SocketMultiplexer socketMultiplexer;
    auto serverOwner = listenOnAvailablePort(
        &socketMultiplexer, IpcPeerAuthenticationMode::DisabledForTests);
    auto& server = *serverOwner;
    m_sendMessageToClient_server = &server;

    // event handler sends "test" log line to client.
    m_events.add_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server,
                         [this](const auto& e)
    {
        sendMessageToClient_server_handle_client_connected(e);
    });

    IpcClient client(&m_events, &socketMultiplexer, TEST_IPC_PORT);
    client.connect();

    m_events.add_handler(EventType::IPC_CLIENT_MESSAGE_RECEIVED, &client,
                         [this](const auto& e)
    {
        sendMessageToClient_client_handle_message_received(e);
    });

    m_events.initQuitTimeout(5);
    m_events.loop();
    m_events.remove_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server);
    m_events.remove_handler(EventType::IPC_CLIENT_MESSAGE_RECEIVED, &client);
    m_events.cleanupQuitTimeout();

    EXPECT_EQ("test", m_sendMessageToClient_receivedString);
}

TEST_F(IpcTests, RuntimeStatusResponseIsDirectedOnlyToRequestingGui)
{
    SocketMultiplexer socketMultiplexer;
    auto serverOwner = listenOnAvailablePort(
        &socketMultiplexer, IpcPeerAuthenticationMode::DisabledForTests);
    auto& server = *serverOwner;
    IpcClient guiA(
        &m_events, &socketMultiplexer, TEST_IPC_PORT, kIpcClientGui);
    IpcClient guiB(
        &m_events, &socketMultiplexer, TEST_IPC_PORT, kIpcClientGui);
    const std::string queryNonce{"01234567\0abcdefg", 16};
    const std::string appliedNonce{"fedcba98\0" "7654321", 16};
    int helloCount = 0;
    int requests = 0;
    int responsesA = 0;
    int responsesB = 0;
    EventQueueTimer* drainTimer = nullptr;

    m_events.add_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server,
                         [&](const Event& event) {
        const auto& received = event.get_data_as<IpcServerMessage>();
        if (received.message->type() == kIpcHello) {
            ++helloCount;
            if (helloCount == 2) {
                guiA.send(IpcRuntimeStatusRequestMessage(queryNonce));
            }
        }
        else if (received.message->type() == kIpcRuntimeStatusRequest) {
            ++requests;
            const auto& request =
                static_cast<const IpcRuntimeStatusRequestMessage&>(*received.message);
            EXPECT_EQ(request.queryNonce(), queryNonce);
            EXPECT_TRUE(server.sendRuntimeStatusResponse(
                received, 1, IpcRuntimeState::Running, appliedNonce));
        }
    });
    m_events.add_handler(EventType::IPC_CLIENT_MESSAGE_RECEIVED, &guiA,
                         [&](const Event& event) {
        const auto& message = event.get_data_as<IpcMessage>();
        if (message.type() != kIpcRuntimeStatusResponse) return;
        ++responsesA;
        const auto& response =
            static_cast<const IpcRuntimeStatusResponseMessage&>(message);
        EXPECT_EQ(response.queryNonce(), queryNonce);
        EXPECT_EQ(response.appliedNonce(), appliedNonce);
        EXPECT_EQ(response.schemaVersion(), 1);
        EXPECT_EQ(response.runtimeState(), IpcRuntimeState::Running);
        drainTimer = m_events.newOneShotTimer(0.1, nullptr);
        m_events.add_handler(EventType::TIMER, drainTimer,
                             [&](const Event&) { m_events.raiseQuitEvent(); });
    });
    m_events.add_handler(EventType::IPC_CLIENT_MESSAGE_RECEIVED, &guiB,
                         [&](const Event& event) {
        if (event.get_data_as<IpcMessage>().type() == kIpcRuntimeStatusResponse) {
            ++responsesB;
        }
    });

    guiA.connect();
    guiB.connect();
    m_events.initQuitTimeout(5);
    m_events.loop();
    m_events.cleanupQuitTimeout();

    if (drainTimer != nullptr) {
        m_events.remove_handler(EventType::TIMER, drainTimer);
        delete drainTimer;
    }
    guiA.disconnect();
    guiB.disconnect();
    m_events.remove_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server);
    m_events.remove_handler(EventType::IPC_CLIENT_MESSAGE_RECEIVED, &guiA);
    m_events.remove_handler(EventType::IPC_CLIENT_MESSAGE_RECEIVED, &guiB);

    EXPECT_EQ(helloCount, 2);
    EXPECT_EQ(requests, 1);
    EXPECT_EQ(responsesA, 1);
    EXPECT_EQ(responsesB, 0);
}

#ifdef _WIN32
TEST_F(IpcTests, DaemonAppStartUsesRealRegistryWatchdogAndAckSocket)
{
    const auto unique = std::to_string(GetCurrentProcessId()) + "-" +
        std::to_string(std::random_device{}());
    const auto root = std::filesystem::temp_directory_path() /
        ("inputleap-daemon-real-chain-" + unique);
    const auto daemon = root / "input-leapd.exe";
    const auto core = root / "input-leaps.exe";
    const auto capturedArguments = root / "captured-arguments.bin";
    const std::string registrySubkey =
        "Software\\InputLeap\\Tests\\DaemonRealChain-" + unique;
    const std::string startNonce = "0123456789abcdef";
    const std::string reloadNonce = "reload-123456789";
    const std::string stopNonce = "fedcba9876543210";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    std::filesystem::copy_file(
        INPUTLEAP_WATCHDOG_FIXTURE_HELPER_PATH, daemon,
        std::filesystem::copy_options::overwrite_existing);
    std::filesystem::copy_file(
        INPUTLEAP_WATCHDOG_FIXTURE_HELPER_PATH, core,
        std::filesystem::copy_options::overwrite_existing);
    ASSERT_EQ(_putenv_s("INPUTLEAP_WATCHDOG_FIXTURE_WAIT_MS", "30000"), 0);
    ASSERT_EQ(_putenv_s(
        "INPUTLEAP_WATCHDOG_FIXTURE_ARGV_PATH",
        capturedArguments.string().c_str()), 0);

    SocketMultiplexer socketMultiplexer;
    auto serverOwner = listenOnAvailablePort(
        &socketMultiplexer, IpcPeerAuthenticationMode::DisabledForTests);
    auto& server = *serverOwner;
    IpcLogOutputter ipcLogOutputter(server, kIpcClientGui, false);
    FileLogOutputter fileLogOutputter((root / "daemon.log").string().c_str());
    MSWindowsWatchdog watchdog(false, false, server, ipcLogOutputter, daemon);
    struct TestCleanup {
        MSWindowsWatchdog& watchdog;
        std::filesystem::path root;
        std::string registrySubkey;
        ~TestCleanup()
        {
            watchdog.stop();
            _putenv_s("INPUTLEAP_WATCHDOG_FIXTURE_WAIT_MS", "");
            _putenv_s("INPUTLEAP_WATCHDOG_FIXTURE_ARGV_PATH", "");
            RegDeleteTreeA(HKEY_CURRENT_USER, registrySubkey.c_str());
            std::error_code error;
            std::filesystem::remove_all(root, error);
        }
    } cleanup{watchdog, root, registrySubkey};
    watchdog.startAsync();
    ASSERT_TRUE(watchdog.stopCommandAndWait(std::chrono::seconds(3)));

    DaemonApp app;
    DaemonAppRealCommandChainTestAccess::configure(
        app, server, watchdog, ipcLogOutputter, fileLogOutputter, m_events,
        HKEY_CURRENT_USER, registrySubkey, daemon);
    IpcClient gui(
        &m_events, &socketMultiplexer, server.port(), kIpcClientGui);
    bool processActiveAtStartAck = false;
    bool processActiveAtReloadAck = false;
    bool processStoppedAtStopAck = false;
    bool durableStartAtAck = false;
    bool durableReloadAtAck = false;
    bool durableStopAtAck = false;
    bool childArgumentsAtStartAck = false;
    bool childArgumentsAtReloadAck = false;
    std::vector<std::string> acknowledgedNonces;
    const auto profile = root / "service profile";
    const auto config = profile / "runtime.conf";
    const auto requestedLog = root / "requested daemon.log";
    std::filesystem::create_directories(profile);
    std::ofstream(config) << "section: screens\n";
    const std::string injectedName = "safe\t--disable-crypto";
    const std::string command =
        "\"" + core.string() + "\" --config \"" + config.string() +
        "\" --name " + injectedName + " --log \"" + requestedLog.string() + "\"";
    const auto validatedCommand = DaemonCommandPolicy::validateCommandLine(command, daemon);
    ASSERT_TRUE(validatedCommand.has_value());
    const std::string expectedCommand =
        core.string() + " --config \"" + config.string() +
        "\" --name \"" + injectedName + "\" --profile-dir \"" +
        profile.string() + "\"";
    const std::vector<std::string> expectedArguments{
        core.string(), "--config", config.string(), "--name", injectedName,
        "--profile-dir", profile.string()};

    m_events.add_handler(EventType::IPC_CLIENT_CONNECTED, &gui,
                         [&](const Event&) {
        gui.send(IpcStartRequestMessage(startNonce, command, false));
    });
    m_events.add_handler(EventType::IPC_CLIENT_MESSAGE_RECEIVED, &gui,
                         [&](const Event& event) {
        const auto& message = event.get_data_as<IpcMessage>();
        if (message.type() == kIpcCommandApplied) {
            const auto nonce =
                static_cast<const IpcCommandAppliedMessage&>(message).nonce();
            acknowledgedNonces.push_back(nonce);
            if (nonce == startNonce) {
                processActiveAtStartAck = watchdog.isProcessActive();
                childArgumentsAtStartAck =
                    waitForCapturedArguments(capturedArguments, 1) ==
                    std::vector<std::vector<std::string>>{expectedArguments};
                HKEY registryKey = nullptr;
                if (RegOpenKeyExA(
                        HKEY_CURRENT_USER, registrySubkey.c_str(), 0,
                        KEY_READ, &registryKey) == ERROR_SUCCESS) {
                    durableStartAtAck =
                        ArchMiscWindows::readValueString(
                            registryKey, "Command") == expectedCommand &&
                        ArchMiscWindows::readValueString(
                            registryKey, "CommandRequestNonce") == startNonce &&
                        ArchMiscWindows::readValueString(
                            registryKey, "CommandAppliedNonce") == startNonce;
                    RegCloseKey(registryKey);
                }
                gui.send(IpcReloadRequestMessage(reloadNonce, startNonce));
            }
            else if (nonce == reloadNonce) {
                processActiveAtReloadAck = watchdog.isProcessActive();
                childArgumentsAtReloadAck =
                    waitForCapturedArguments(capturedArguments, 2) ==
                    std::vector<std::vector<std::string>>{
                        expectedArguments, expectedArguments};
                HKEY registryKey = nullptr;
                if (RegOpenKeyExA(
                        HKEY_CURRENT_USER, registrySubkey.c_str(), 0,
                        KEY_READ, &registryKey) == ERROR_SUCCESS) {
                    durableReloadAtAck =
                        ArchMiscWindows::readValueString(
                            registryKey, "Command") == expectedCommand &&
                        ArchMiscWindows::readValueString(
                            registryKey, "CommandRequestNonce") == reloadNonce &&
                        ArchMiscWindows::readValueString(
                            registryKey, "CommandAppliedNonce") == reloadNonce &&
                        ArchMiscWindows::readValueString(
                            registryKey, "CommandReloadExpectedNonce") == startNonce;
                    RegCloseKey(registryKey);
                }
                gui.send(IpcStopRequestMessage(stopNonce, reloadNonce));
            }
            else if (nonce == stopNonce) {
                processStoppedAtStopAck = !watchdog.isProcessActive();
                HKEY registryKey = nullptr;
                if (RegOpenKeyExA(
                        HKEY_CURRENT_USER, registrySubkey.c_str(), 0,
                        KEY_READ, &registryKey) == ERROR_SUCCESS) {
                    durableStopAtAck =
                        ArchMiscWindows::readValueString(
                            registryKey, "CommandStopRequestNonce") == stopNonce &&
                        ArchMiscWindows::readValueString(
                            registryKey, "CommandStopExpectedAppliedNonce") == reloadNonce &&
                        ArchMiscWindows::readValueString(
                            registryKey, "CommandStopAppliedNonce") == stopNonce &&
                        ArchMiscWindows::readValueString(
                            registryKey, "CommandStopPolicyVersion") ==
                            DaemonCommandPolicy::persistedStopMarker(
                                stopNonce, reloadNonce);
                    RegCloseKey(registryKey);
                }
                m_events.raiseQuitEvent();
            }
        }
    });

    gui.connect();
    m_events.initQuitTimeout(60);
    m_events.loop();
    m_events.cleanupQuitTimeout();
    gui.disconnect();
    m_events.remove_handler(EventType::IPC_SERVER_MESSAGE_RECEIVED, &server);
    m_events.remove_handler(EventType::IPC_CLIENT_CONNECTED, &gui);
    m_events.remove_handler(EventType::IPC_CLIENT_MESSAGE_RECEIVED, &gui);

    EXPECT_EQ(acknowledgedNonces,
              (std::vector<std::string>{startNonce, reloadNonce, stopNonce}));
    EXPECT_TRUE(processActiveAtStartAck);
    EXPECT_TRUE(processActiveAtReloadAck);
    EXPECT_TRUE(childArgumentsAtStartAck);
    EXPECT_TRUE(childArgumentsAtReloadAck);
    EXPECT_TRUE(durableStartAtAck);
    EXPECT_TRUE(durableReloadAtAck);
    EXPECT_TRUE(processStoppedAtStopAck);
    EXPECT_TRUE(durableStopAtAck);

    HKEY registryKey = nullptr;
    ASSERT_EQ(RegOpenKeyExA(
        HKEY_CURRENT_USER, registrySubkey.c_str(), 0, KEY_READ, &registryKey),
        ERROR_SUCCESS);
    EXPECT_TRUE(ArchMiscWindows::readValueString(registryKey, "Command").empty());
    EXPECT_EQ(ArchMiscWindows::readValueString(registryKey, "Elevate"), "0");
    EXPECT_TRUE(ArchMiscWindows::readValueString(
        registryKey, "CommandRequestNonce").empty());
    EXPECT_TRUE(ArchMiscWindows::readValueString(
        registryKey, "CommandPolicyVersion").empty());
    RegCloseKey(registryKey);

}
#endif

IpcTests::IpcTests() :
m_connectToServer_helloMessageReceived(false),
m_connectToServer_hasClientNode(false),
m_connectToServer_server(nullptr),
m_sendMessageToServer_client(nullptr),
m_sendMessageToClient_server(nullptr)
{
}

IpcTests::~IpcTests()
{
}

std::unique_ptr<IpcServer> IpcTests::listenOnAvailablePort(
    SocketMultiplexer* socketMultiplexer,
    IpcPeerAuthenticationMode authenticationMode,
    const std::filesystem::path& daemonExecutable)
{
    int& selectedPort =
        authenticationMode == IpcPeerAuthenticationMode::DisabledForTests
        ? m_testIpcPort
        : m_authenticatedIpcPort;
    auto server = std::make_unique<IpcServer>(
        &m_events, socketMultiplexer, 0, authenticationMode, daemonExecutable);
    server->listen();
    selectedPort = server->port();
    return server;
}

void IpcTests::connectToServer_handle_message_received(const Event& e)
{
    const auto& m = *e.get_data_as<IpcServerMessage>().message;
    if (m.type() == kIpcHello) {
        m_connectToServer_hasClientNode =
            m_connectToServer_server->hasClients(kIpcClientNode);
        m_connectToServer_helloMessageReceived = true;
        m_events.raiseQuitEvent();
    }
}

void IpcTests::sendMessageToServer_serverHandleMessageReceived(const Event& e)
{
    const auto& m = *e.get_data_as<IpcServerMessage>().message;
    if (m.type() == kIpcHello) {
        LOG_DEBUG("node said hello, sending connection state to server");
        const IpcConnectionStateMessage state(
            IpcConnectionState::Connected, IpcConnectionRole::ClientPeer,
            IpcIdentityPresence::Known, "test");
        EXPECT_EQ(m_sendMessageToServer_client->sendConnectionState(state),
                  IpcClient::SendResult::Sent);
    }
    else if (m.type() == kIpcConnectionState) {
        const auto& state = static_cast<const IpcConnectionStateMessage&>(m);
        LOG_DEBUG("got ipc connection state, %s", state.technicalName().c_str());
        m_sendMessageToServer_receivedString = state.technicalName();
        m_sendMessageToServer_receivedElevate = false;
        m_events.raiseQuitEvent();
    }
}

void IpcTests::sendMessageToClient_server_handle_client_connected(const Event& e)
{
    const auto& m = *e.get_data_as<IpcServerMessage>().message;
    if (m.type() == kIpcHello) {
        LOG_DEBUG("client said hello, sending test to client");
        IpcLogLineMessage msg("test");
        m_sendMessageToClient_server->send(msg, kIpcClientNode);
    }
}

void IpcTests::sendMessageToClient_client_handle_message_received(const Event& e)
{
    const auto& m = e.get_data_as<IpcMessage>();
    if (m.type() == kIpcLogLine) {
        const auto& llm = static_cast<const IpcLogLineMessage&>(m);
        LOG_DEBUG("got ipc log message, %s", llm.logLine().c_str());
        m_sendMessageToClient_receivedString = llm.logLine();
        m_events.raiseQuitEvent();
    }
}

} // namespace inputleap

#endif // WINAPI_CARBON
