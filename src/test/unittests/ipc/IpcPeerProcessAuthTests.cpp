#include "ipc/IpcPeerProcessAuth.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

namespace inputleap {
namespace {

class TemporaryExecutableTree
{
public:
    TemporaryExecutableTree()
    {
        root_ = std::filesystem::temp_directory_path() / "inputleap-ipc-peer-auth";
        std::filesystem::remove_all(root_);
        std::filesystem::create_directories(root_ / "install");
        std::filesystem::create_directories(root_ / "other");
    }

    ~TemporaryExecutableTree()
    {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    std::filesystem::path executable(const std::filesystem::path& directory,
                                     const std::string& name)
    {
        const auto path = root_ / directory / name;
        std::ofstream(path, std::ios::binary).put('\0');
        return path;
    }

    std::filesystem::path copyExecutable(const std::filesystem::path& source,
                                         const std::filesystem::path& directory,
                                         const std::string& name)
    {
        const auto destination = root_ / directory / name;
        std::filesystem::copy_file(
            source, destination, std::filesystem::copy_options::overwrite_existing);
        return destination;
    }

private:
    std::filesystem::path root_;
};

TEST(IpcPeerProcessAuthTests, RecognizesGuiExecutableBesideDaemon)
{
    TemporaryExecutableTree tree;
    const auto daemon = tree.executable("install", "input-leapd.exe");
    const auto gui = tree.executable("install", "input-leap.exe");

    EXPECT_EQ(IpcPeerProcessAuth::classifyExecutable(gui, daemon), kIpcClientGui);
}

TEST(IpcPeerProcessAuthTests, RecognizesTauriGuiExecutableBesideDaemon)
{
    TemporaryExecutableTree tree;
    const auto daemon = tree.executable("install", "input-leapd.exe");
    const auto gui = tree.executable("install", "input-leap-tauri.exe");

    EXPECT_EQ(IpcPeerProcessAuth::classifyExecutable(gui, daemon), kIpcClientGui);
}

TEST(IpcPeerProcessAuthTests, RejectsTauriGuiExecutableOutsideDaemonDirectory)
{
    TemporaryExecutableTree tree;
    const auto daemon = tree.executable("install", "input-leapd.exe");
    const auto impostor = tree.executable("other", "input-leap-tauri.exe");

    EXPECT_EQ(IpcPeerProcessAuth::classifyExecutable(impostor, daemon), kIpcClientUnknown);
}

TEST(IpcPeerProcessAuthTests, RecognizesCoreExecutablesBesideDaemonAsNodes)
{
    TemporaryExecutableTree tree;
    const auto daemon = tree.executable("install", "input-leapd.exe");
    const auto client = tree.executable("install", "input-leapc.exe");
    const auto server = tree.executable("install", "input-leaps.exe");

    EXPECT_EQ(IpcPeerProcessAuth::classifyExecutable(client, daemon), kIpcClientNode);
    EXPECT_EQ(IpcPeerProcessAuth::classifyExecutable(server, daemon), kIpcClientNode);
}

TEST(IpcPeerProcessAuthTests, RejectsAllowedNameOutsideDaemonDirectory)
{
    TemporaryExecutableTree tree;
    const auto daemon = tree.executable("install", "input-leapd.exe");
    const auto impostor = tree.executable("other", "input-leap.exe");

    EXPECT_EQ(IpcPeerProcessAuth::classifyExecutable(impostor, daemon), kIpcClientUnknown);
}

TEST(IpcPeerProcessAuthTests, RejectsArbitraryExecutableBesideDaemon)
{
    TemporaryExecutableTree tree;
    const auto daemon = tree.executable("install", "input-leapd.exe");
    const auto impostor = tree.executable("install", "malware.exe");

    EXPECT_EQ(IpcPeerProcessAuth::classifyExecutable(impostor, daemon), kIpcClientUnknown);
}

TEST(IpcPeerProcessAuthTests, RejectsPeerFromDifferentWindowsSession)
{
    const std::vector<std::uint8_t> userSid{1, 2, 3, 4};
    const std::vector<std::uint8_t> systemSid{1, 2, 3, 5};

    EXPECT_FALSE(IpcPeerProcessAuth::isAuthorizedWindowsIdentity(
        kIpcClientGui, 8, userSid, 7, userSid, systemSid));
}

TEST(IpcPeerProcessAuthTests, RejectsPeerWithDifferentWindowsUserSid)
{
    const std::vector<std::uint8_t> peerSid{1, 2, 3, 4};
    const std::vector<std::uint8_t> activeUserSid{1, 2, 3, 5};
    const std::vector<std::uint8_t> systemSid{1, 2, 3, 6};

    EXPECT_FALSE(IpcPeerProcessAuth::isAuthorizedWindowsIdentity(
        kIpcClientGui, 7, peerSid, 7, activeUserSid, systemSid));
}

TEST(IpcPeerProcessAuthTests, AcceptsPeerFromActiveWindowsUserAndSession)
{
    const std::vector<std::uint8_t> userSid{1, 2, 3, 4};
    const std::vector<std::uint8_t> systemSid{1, 2, 3, 5};

    EXPECT_TRUE(IpcPeerProcessAuth::isAuthorizedWindowsIdentity(
        kIpcClientGui, 7, userSid, 7, userSid, systemSid));
}

TEST(IpcPeerProcessAuthTests, RejectsSystemPeerClaimingGuiRole)
{
    const std::vector<std::uint8_t> userSid{1, 2, 3, 4};
    const std::vector<std::uint8_t> systemSid{1, 2, 3, 5};

    EXPECT_FALSE(IpcPeerProcessAuth::isAuthorizedWindowsIdentity(
        kIpcClientGui, 7, systemSid, 7, userSid, systemSid));
}

TEST(IpcPeerProcessAuthTests, AcceptsSystemNodeInActiveWindowsSession)
{
    const std::vector<std::uint8_t> userSid{1, 2, 3, 4};
    const std::vector<std::uint8_t> systemSid{1, 2, 3, 5};

    EXPECT_TRUE(IpcPeerProcessAuth::isAuthorizedWindowsIdentity(
        kIpcClientNode, 7, systemSid, 7, userSid, systemSid));
}

#ifdef _WIN32
TEST(IpcPeerProcessAuthTests, ResolvesOwnerPidOfAcceptedLoopbackSocket)
{
    WSADATA winsock{};
    ASSERT_EQ(WSAStartup(MAKEWORD(2, 2), &winsock), 0);

    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(listener, INVALID_SOCKET);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    ASSERT_EQ(bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)), 0);
    ASSERT_EQ(listen(listener, 1), 0);
    int addressSize = sizeof(address);
    ASSERT_EQ(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &addressSize), 0);

    const SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(client, INVALID_SOCKET);
    ASSERT_EQ(connect(client, reinterpret_cast<const sockaddr*>(&address), sizeof(address)), 0);
    const SOCKET accepted = accept(listener, nullptr, nullptr);
    ASSERT_NE(accepted, INVALID_SOCKET);

    const auto owner = IpcPeerProcessAuth::peerProcessId(
        static_cast<std::uintptr_t>(accepted));
    ASSERT_TRUE(owner.has_value());
    EXPECT_EQ(*owner, GetCurrentProcessId());

    closesocket(accepted);
    closesocket(client);
    closesocket(listener);
    WSACleanup();
}

TEST(IpcPeerProcessAuthTests, ResolvesCurrentProcessExecutablePath)
{
    wchar_t modulePath[32768]{};
    const DWORD moduleLength = GetModuleFileNameW(
        nullptr, modulePath, static_cast<DWORD>(std::size(modulePath)));
    ASSERT_GT(moduleLength, 0u);

    std::error_code error;
    const auto expected = std::filesystem::canonical(
        std::filesystem::path(std::wstring(modulePath, moduleLength)), error);
    ASSERT_FALSE(error);
    const auto actual = std::filesystem::canonical(
        IpcPeerProcessAuth::currentProcessExecutable(), error);
    ASSERT_FALSE(error);
    EXPECT_EQ(actual, expected);
}

TEST(IpcPeerProcessAuthTests, AuthenticatesRealGuiProcessBesideDaemon)
{
    wchar_t modulePath[32768]{};
    const DWORD moduleLength = GetModuleFileNameW(
        nullptr, modulePath, static_cast<DWORD>(std::size(modulePath)));
    ASSERT_GT(moduleLength, 0u);
    const auto helper = std::filesystem::path(modulePath).parent_path() /
        "ipcpeerprocessclienthelper.exe";
    ASSERT_TRUE(std::filesystem::exists(helper));

    TemporaryExecutableTree tree;
    const auto daemon = tree.executable("install", "input-leapd.exe");
    const auto gui = tree.copyExecutable(helper, "install", "input-leap.exe");

    WSADATA winsock{};
    ASSERT_EQ(WSAStartup(MAKEWORD(2, 2), &winsock), 0);
    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(listener, INVALID_SOCKET);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    ASSERT_EQ(bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)), 0);
    ASSERT_EQ(listen(listener, 1), 0);
    int addressSize = sizeof(address);
    ASSERT_EQ(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &addressSize), 0);

    std::wstring commandLine = L"\"" + gui.native() + L"\" " +
        std::to_wstring(ntohs(address.sin_port));
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    ASSERT_TRUE(CreateProcessW(
        gui.native().c_str(), mutableCommand.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, gui.parent_path().native().c_str(),
        &startup, &process));

    const SOCKET accepted = accept(listener, nullptr, nullptr);
    ASSERT_NE(accepted, INVALID_SOCKET);
    const auto identity = IpcPeerProcessAuth::authenticatePeer(
        static_cast<std::uintptr_t>(accepted), daemon);
    ASSERT_TRUE(identity.has_value());
    EXPECT_EQ(identity->type, kIpcClientGui);
    EXPECT_EQ(identity->processId, process.dwProcessId);
    EXPECT_NE(identity->processCreationTime, 0u);

    EXPECT_TRUE(IpcPeerProcessAuth::validatePeer(
        static_cast<std::uintptr_t>(accepted), *identity, daemon));
    ASSERT_TRUE(TerminateProcess(process.hProcess, 0));
    EXPECT_EQ(WaitForSingleObject(process.hProcess, 5000), WAIT_OBJECT_0);
    EXPECT_FALSE(IpcPeerProcessAuth::validatePeer(
        static_cast<std::uintptr_t>(accepted), *identity, daemon));
    closesocket(accepted);
    closesocket(listener);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    WSACleanup();
}
#endif

} // namespace
} // namespace inputleap
