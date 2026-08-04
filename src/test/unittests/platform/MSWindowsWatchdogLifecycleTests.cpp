#define INPUTLEAP_TEST_ENV

#include "platform/MSWindowsWatchdog.h"
#include "platform/MSWindowsWatchdogLifecycle.h"
#include "platform/MSWindowsWatchdogOutputRead.h"
#include "platform/MSWindowsWatchdogProcess.h"
#include "ipc/IpcLogOutputter.h"
#include "ipc/IpcServer.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace inputleap {

class MSWindowsWatchdogTestPeer {
public:
    static void startProcess(
        MSWindowsWatchdog& watchdog,
        std::function<MSWindowsSessionLockState()> sessionLockStateOverride,
        std::function<HANDLE(LPSECURITY_ATTRIBUTES, bool)> userTokenOverride)
    {
        watchdog.startProcess(
            std::move(sessionLockStateOverride), std::move(userTokenOverride));
    }
};

namespace {

TEST(MSWindowsWatchdogLifecycleTests, LaunchElevationUsesKnownSessionLockStateOrExplicitRequest)
{
    EXPECT_FALSE(MSWindowsWatchdogLifecycle::shouldLaunchElevated(
        false, MSWindowsSessionLockState::Unknown));
    EXPECT_FALSE(MSWindowsWatchdogLifecycle::shouldLaunchElevated(
        false, MSWindowsSessionLockState::Unlocked));
    EXPECT_TRUE(MSWindowsWatchdogLifecycle::shouldLaunchElevated(
        false, MSWindowsSessionLockState::Locked));
    EXPECT_TRUE(MSWindowsWatchdogLifecycle::shouldLaunchElevated(
        true, MSWindowsSessionLockState::Unknown));
    EXPECT_TRUE(MSWindowsWatchdogLifecycle::shouldLaunchElevated(
        true, MSWindowsSessionLockState::Unlocked));
}

TEST(MSWindowsWatchdogLifecycleTests, StartProcessPassesFinalElevationDecisionToTokenProvider)
{
    struct TestCase {
        MSWindowsSessionLockState lockState;
        bool explicitlyElevated;
        bool expectedElevation;
    };
    const TestCase cases[] = {
        {MSWindowsSessionLockState::Unknown, false, false},
        {MSWindowsSessionLockState::Unlocked, false, false},
        {MSWindowsSessionLockState::Locked, false, true},
        {MSWindowsSessionLockState::Unknown, true, true},
    };

    for (const auto& testCase : cases) {
        IpcServer ipcServer;
        IpcLogOutputter ipcLogOutputter(ipcServer, kIpcClientGui, false);
        std::optional<bool> observedElevation;
        std::function<MSWindowsSessionLockState()> lockStateProvider = [=] {
            return testCase.lockState;
        };
        std::function<HANDLE(LPSECURITY_ATTRIBUTES, bool)> tokenProvider =
            [&](LPSECURITY_ATTRIBUTES, bool elevated) -> HANDLE {
                observedElevation = elevated;
                throw std::runtime_error("token provider test stop");
            };

        MSWindowsWatchdog watchdog(true, false, ipcServer, ipcLogOutputter);
        watchdog.setCommand("not-launched.exe", testCase.explicitlyElevated);

        EXPECT_THROW(
            MSWindowsWatchdogTestPeer::startProcess(
                watchdog, lockStateProvider, tokenProvider),
            std::runtime_error);
        ASSERT_TRUE(observedElevation.has_value());
        EXPECT_EQ(*observedElevation, testCase.expectedElevation);
    }
}

TEST(MSWindowsWatchdogLifecycleTests, ActiveConsoleSessionLockStateIsQueryable)
{
    MSWindowsSession session;
    session.updateActiveSession();

    EXPECT_NE(session.getActiveSessionLockState(), MSWindowsSessionLockState::Unknown);
}

TEST(MSWindowsWatchdogLifecycleTests, UserTokenDuplicationAlwaysClosesSourceHandle)
{
    HANDLE sourceToken = nullptr;
    ASSERT_TRUE(OpenProcessToken(
        GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
        &sourceToken));
    const HANDLE sourceTokenValue = sourceToken;

    HANDLE duplicateToken =
        MSWindowsSession::duplicateUserTokenAndCloseSource(sourceToken, nullptr);
    ASSERT_NE(duplicateToken, nullptr);
    auto closeDuplicateToken = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
        CloseHandle(duplicateToken);
    });

    DWORD flags = 0;
    EXPECT_FALSE(GetHandleInformation(sourceTokenValue, &flags));
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
    EXPECT_TRUE(GetHandleInformation(duplicateToken, &flags));

    const std::wstring eventName =
        L"Local\\InputLeapTokenOwnershipTest-" + std::to_wstring(GetCurrentProcessId());
    HANDLE nonTokenHandle = CreateEventW(nullptr, TRUE, FALSE, eventName.c_str());
    ASSERT_NE(nonTokenHandle, nullptr);
    EXPECT_THROW(
        MSWindowsSession::duplicateUserTokenAndCloseSource(nonTokenHandle, nullptr),
        std::runtime_error);
    HANDLE reopenedEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, eventName.c_str());
    EXPECT_EQ(reopenedEvent, nullptr);
    if (reopenedEvent != nullptr) {
        CloseHandle(reopenedEvent);
    }
}

TEST(MSWindowsWatchdogLifecycleTests, KeepsOutputDrainAliveUntilMainJoinedAndWriterClosed)
{
    std::vector<std::string> events;
    bool mainJoined = false;
    bool writerClosed = false;
    bool outputStopRequested = false;

    MSWindowsWatchdogLifecycle::join({
        [&] {
            events.emplace_back("main-joined");
            mainJoined = true;
        },
        [&] {
            EXPECT_TRUE(mainJoined);
            events.emplace_back("writer-closed");
            writerClosed = true;
        },
        [&] {
            EXPECT_TRUE(writerClosed);
            events.emplace_back("output-stop-requested");
            outputStopRequested = true;
        },
        [&] {
            EXPECT_TRUE(outputStopRequested);
            events.emplace_back("output-joined");
        }});

    EXPECT_EQ(events, (std::vector<std::string>{
        "main-joined", "writer-closed", "output-stop-requested", "output-joined"}));
}

TEST(MSWindowsWatchdogLifecycleTests, ClosesProcessInformationHandlesAndClearsFieldsIdempotently)
{
    PROCESS_INFORMATION info{};
    ASSERT_TRUE(DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
                                GetCurrentProcess(), &info.hProcess,
                                0, FALSE, DUPLICATE_SAME_ACCESS));
    ASSERT_TRUE(DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
                                GetCurrentProcess(), &info.hThread,
                                0, FALSE, DUPLICATE_SAME_ACCESS));
    const HANDLE processHandle = info.hProcess;
    const HANDLE threadHandle = info.hThread;

    MSWindowsWatchdogLifecycle::closeProcessInformation(info);

    EXPECT_EQ(info.hProcess, nullptr);
    EXPECT_EQ(info.hThread, nullptr);
    EXPECT_EQ(info.dwProcessId, 0u);
    EXPECT_EQ(info.dwThreadId, 0u);
    DWORD flags = 0;
    EXPECT_FALSE(GetHandleInformation(processHandle, &flags));
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
    EXPECT_FALSE(GetHandleInformation(threadHandle, &flags));
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
    EXPECT_NO_THROW(MSWindowsWatchdogLifecycle::closeProcessInformation(info));
}

TEST(MSWindowsWatchdogLifecycleTests, OutputReadReturnsWithoutWaitingForInheritedWriter)
{
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE readHandle = nullptr;
    HANDLE writeHandle = nullptr;
    ASSERT_TRUE(CreatePipe(&readHandle, &writeHandle, &attributes, 0));
    ASSERT_TRUE(SetHandleInformation(readHandle, HANDLE_FLAG_INHERIT, 0));

    HANDLE inheritedWriter = nullptr;
    ASSERT_TRUE(DuplicateHandle(GetCurrentProcess(), writeHandle,
                                GetCurrentProcess(), &inheritedWriter,
                                0, TRUE, DUPLICATE_SAME_ACCESS));
    ASSERT_TRUE(CloseHandle(writeHandle));

    char buffer[16]{};
    DWORD bytesRead = 99;
    EXPECT_EQ(MSWindowsWatchdogOutputRead::readAvailable(
                  readHandle, buffer, sizeof(buffer), bytesRead),
              MSWindowsWatchdogOutputRead::Result::NoData);
    EXPECT_EQ(bytesRead, 0u);

    ASSERT_TRUE(CloseHandle(inheritedWriter));
    EXPECT_EQ(MSWindowsWatchdogOutputRead::readAvailable(
                  readHandle, buffer, sizeof(buffer), bytesRead),
              MSWindowsWatchdogOutputRead::Result::Closed);
    ASSERT_TRUE(CloseHandle(readHandle));
}

TEST(MSWindowsWatchdogLifecycleTests, OutputReadConsumesOnlyAvailableBytes)
{
    HANDLE readHandle = nullptr;
    HANDLE writeHandle = nullptr;
    ASSERT_TRUE(CreatePipe(&readHandle, &writeHandle, nullptr, 0));
    constexpr char payload[] = "watchdog-output";
    DWORD bytesWritten = 0;
    ASSERT_TRUE(WriteFile(writeHandle, payload, DWORD(sizeof(payload) - 1),
                          &bytesWritten, nullptr));
    ASSERT_EQ(bytesWritten, sizeof(payload) - 1);

    char buffer[32]{};
    DWORD bytesRead = 0;
    EXPECT_EQ(MSWindowsWatchdogOutputRead::readAvailable(
                  readHandle, buffer, sizeof(buffer), bytesRead),
              MSWindowsWatchdogOutputRead::Result::Data);
    EXPECT_EQ(bytesRead, sizeof(payload) - 1);
    EXPECT_EQ(std::string(buffer, buffer + bytesRead),
              std::string(payload, payload + sizeof(payload) - 1));

    ASSERT_TRUE(CloseHandle(writeHandle));
    ASSERT_TRUE(CloseHandle(readHandle));
}

TEST(MSWindowsWatchdogLifecycleTests, SelfLaunchInheritsConfiguredOutputPipeOnly)
{
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE readHandle = nullptr;
    HANDLE writeHandle = nullptr;
    ASSERT_TRUE(CreatePipe(&readHandle, &writeHandle, &attributes, 0));
    ASSERT_TRUE(SetHandleInformation(readHandle, HANDLE_FLAG_INHERIT, 0));
    HANDLE unrelatedRead = nullptr;
    HANDLE unrelatedWrite = nullptr;
    ASSERT_TRUE(CreatePipe(&unrelatedRead, &unrelatedWrite, &attributes, 0));
    ASSERT_TRUE(SetHandleInformation(unrelatedRead, HANDLE_FLAG_INHERIT, 0));

    PROCESS_INFORMATION process{};
    std::string command =
        "cmd.exe /d /s /c \"ping -n 3 127.0.0.1 >nul & echo inherited-output\"";
    ASSERT_TRUE(MSWindowsWatchdogProcess::createAsSelf(command, writeHandle, process));
    ASSERT_TRUE(CloseHandle(writeHandle));
    writeHandle = nullptr;
    ASSERT_TRUE(CloseHandle(unrelatedWrite));
    unrelatedWrite = nullptr;
    char unrelatedBuffer[8]{};
    DWORD unrelatedBytes = 0;
    EXPECT_EQ(MSWindowsWatchdogOutputRead::readAvailable(
                  unrelatedRead, unrelatedBuffer, sizeof(unrelatedBuffer),
                  unrelatedBytes),
              MSWindowsWatchdogOutputRead::Result::Closed);
    ASSERT_EQ(WaitForSingleObject(process.hProcess, 10000), WAIT_OBJECT_0);

    std::string output;
    char buffer[128]{};
    for (;;) {
        DWORD bytesRead = 0;
        const auto result = MSWindowsWatchdogOutputRead::readAvailable(
            readHandle, buffer, sizeof(buffer), bytesRead);
        if (result == MSWindowsWatchdogOutputRead::Result::Data)
            output.append(buffer, buffer + bytesRead);
        else if (result == MSWindowsWatchdogOutputRead::Result::Closed)
            break;
        else
            Sleep(10);
    }
    EXPECT_NE(output.find("inherited-output"), std::string::npos);

    MSWindowsWatchdogLifecycle::closeProcessInformation(process);
    ASSERT_TRUE(CloseHandle(unrelatedRead));
    ASSERT_TRUE(CloseHandle(readHandle));
}

TEST(MSWindowsWatchdogLifecycleTests, BackoffWaitIsInterruptedByStopNotification)
{
    std::atomic_bool monitoring{true};
    std::mutex mutex;
    std::condition_variable changed;
    bool stillMonitoring = true;
    const auto started = std::chrono::steady_clock::now();
    std::thread waiter([&] {
        stillMonitoring = MSWindowsWatchdogLifecycle::waitWhileMonitoring(
            changed, mutex, monitoring, std::chrono::seconds(10));
    });
    Sleep(25);
    monitoring = false;
    changed.notify_all();
    waiter.join();

    EXPECT_FALSE(stillMonitoring);
    EXPECT_LT(std::chrono::steady_clock::now() - started,
              std::chrono::milliseconds(500));
}

TEST(MSWindowsWatchdogLifecycleTests, ScopeExitRunsWhenEventLoopThrows)
{
    bool cleaned = false;
    EXPECT_THROW({
        auto cleanup = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
            cleaned = true;
        });
        throw std::runtime_error("event loop failed");
    }, std::runtime_error);
    EXPECT_TRUE(cleaned);
}

TEST(MSWindowsWatchdogLifecycleTests, RejectsUnopenablePackagedCoreProcess)
{
    EXPECT_THROW(
        MSWindowsWatchdogLifecycle::requireCoreProcessHandle(nullptr),
        std::runtime_error);
}

TEST(MSWindowsWatchdogLifecycleTests, RejectsUnqueryablePackagedCoreExecutable)
{
    EXPECT_THROW(
        MSWindowsWatchdogLifecycle::requireCoreProcessExecutable({}),
        std::runtime_error);
}

TEST(MSWindowsWatchdogLifecycleTests, RecognizesOnlyPackagedCoreExecutableNames)
{
    EXPECT_TRUE(MSWindowsWatchdogLifecycle::isCoreProcessName("input-leapc.exe"));
    EXPECT_TRUE(MSWindowsWatchdogLifecycle::isCoreProcessName("INPUT-LEAPS.EXE"));
    EXPECT_FALSE(MSWindowsWatchdogLifecycle::isCoreProcessName("InputLeapc.exe"));
    EXPECT_FALSE(MSWindowsWatchdogLifecycle::isCoreProcessName("InputLeaps.exe"));
}

TEST(MSWindowsWatchdogLifecycleTests, RejectsMatchingCoreBasenameOutsideDaemonDirectory)
{
    const auto root = std::filesystem::temp_directory_path() /
        ("inputleap-watchdog-path-policy-" + std::to_string(GetCurrentProcessId()));
    const auto daemonDirectory = root / "installed";
    const auto otherDirectory = root / "other";
    std::filesystem::create_directories(daemonDirectory);
    std::filesystem::create_directories(otherDirectory);
    const auto daemon = daemonDirectory / "input-leapd.exe";
    const auto installedCore = daemonDirectory / "input-leaps.exe";
    const auto unrelatedCore = otherDirectory / "input-leaps.exe";
    std::ofstream(daemon, std::ios::binary).put('\0');
    std::ofstream(installedCore, std::ios::binary).put('\0');
    std::ofstream(unrelatedCore, std::ios::binary).put('\0');
    const auto cleanup = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
        std::error_code error;
        std::filesystem::remove_all(root, error);
    });

    EXPECT_TRUE(MSWindowsWatchdogLifecycle::isManagedCorePath(installedCore, daemon));
    EXPECT_FALSE(MSWindowsWatchdogLifecycle::isManagedCorePath(unrelatedCore, daemon));
}

TEST(MSWindowsWatchdogLifecycleTests, TreatsUncanonicalizableCandidateAsUnmanaged)
{
    const auto root = std::filesystem::temp_directory_path() /
        ("inputleap-watchdog-missing-path-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(root);
    const auto daemon = root / "input-leapd.exe";
    const auto missingCore = root / "input-leaps.exe";
    std::ofstream(daemon, std::ios::binary).put('\0');
    const auto cleanup = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
        std::error_code error;
        std::filesystem::remove_all(root, error);
    });

    EXPECT_FALSE(MSWindowsWatchdogLifecycle::isManagedCorePath(missingCore, daemon));
}

TEST(MSWindowsWatchdogLifecycleTests, StartRevisionWaitsUntilFixtureProcessIsActive)
{
    const auto root = std::filesystem::temp_directory_path() /
        ("inputleap-watchdog-start-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::remove_all(root);
    ASSERT_TRUE(std::filesystem::create_directories(root));
    const auto daemon = root / "input-leapd.exe";
    const auto core = root / "input-leaps.exe";
    std::ofstream(daemon, std::ios::binary).put('\0');
    ASSERT_TRUE(std::filesystem::copy_file(
        INPUTLEAP_WATCHDOG_FIXTURE_HELPER_PATH, core,
        std::filesystem::copy_options::overwrite_existing));

    IpcServer ipcServer;
    IpcLogOutputter ipcLogOutputter(ipcServer, kIpcClientGui, false);
    MSWindowsWatchdog watchdog(false, false, ipcServer, ipcLogOutputter, daemon);
    const auto cleanup = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
        watchdog.stop();
        std::error_code error;
        std::filesystem::remove_all(root, error);
    });
    watchdog.startAsync();
    ASSERT_TRUE(watchdog.stopCommandAndWait(std::chrono::seconds(2)));

    const std::string command = "\"" + core.string() + "\" --wait";
    EXPECT_TRUE(watchdog.setCommandAndWait(command, false, std::chrono::seconds(5)));
    EXPECT_TRUE(watchdog.isProcessActive());
}

TEST(MSWindowsWatchdogLifecycleTests, FailedManagedCoreShutdownDoesNotApplyStopRevision)
{
    const auto root = std::filesystem::temp_directory_path() /
        ("inputleap-watchdog-behavior-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::remove_all(root);
    ASSERT_TRUE(std::filesystem::create_directories(root));
    const auto daemon = root / "input-leapd.exe";
    const auto core = root / "input-leaps.exe";
    std::ofstream(daemon, std::ios::binary).put('\0');
    ASSERT_TRUE(std::filesystem::copy_file(
        INPUTLEAP_WATCHDOG_FIXTURE_HELPER_PATH, core,
        std::filesystem::copy_options::overwrite_existing));

    PROCESS_INFORMATION coreProcess{};
    const auto cleanup = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
        if (coreProcess.hProcess != nullptr) {
            TerminateProcess(coreProcess.hProcess, 0);
            WaitForSingleObject(coreProcess.hProcess, 5000);
        }
        MSWindowsWatchdogLifecycle::closeProcessInformation(coreProcess);
        std::error_code error;
        std::filesystem::remove_all(root, error);
    });

    IpcServer ipcServer;
    IpcLogOutputter ipcLogOutputter(ipcServer, kIpcClientGui, false);
    std::atomic_bool shutdownAttempted{false};
    MSWindowsWatchdog watchdog(
        false, false, ipcServer, ipcLogOutputter, daemon,
        [&](HANDLE, DWORD, int) {
            shutdownAttempted = true;
            throw std::runtime_error("injected managed core shutdown failure");
        });
    watchdog.startAsync();
    ASSERT_TRUE(watchdog.stopCommandAndWait(std::chrono::seconds(2)));

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    std::wstring command = L"\"" + core.wstring() + L"\" --wait";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    ASSERT_TRUE(CreateProcessW(
        nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, root.wstring().c_str(),
        &startup, &coreProcess));

    EXPECT_FALSE(watchdog.stopCommandAndWait(std::chrono::milliseconds(2500)));
    EXPECT_TRUE(shutdownAttempted.load());
    DWORD exitCode = 0;
    ASSERT_TRUE(GetExitCodeProcess(coreProcess.hProcess, &exitCode));
    EXPECT_EQ(exitCode, STILL_ACTIVE);
    watchdog.stop();
}

TEST(MSWindowsWatchdogLifecycleTests, UnopenableHomonymDoesNotBlockStopRevision)
{
    const auto root = std::filesystem::temp_directory_path() /
        ("inputleap-watchdog-inspection-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::remove_all(root);
    ASSERT_TRUE(std::filesystem::create_directories(root));
    const auto daemon = root / "input-leapd.exe";
    const auto core = root / "input-leapc.exe";
    std::ofstream(daemon, std::ios::binary).put('\0');
    ASSERT_TRUE(std::filesystem::copy_file(
        INPUTLEAP_WATCHDOG_FIXTURE_HELPER_PATH, core,
        std::filesystem::copy_options::overwrite_existing));

    PROCESS_INFORMATION coreProcess{};
    const auto cleanup = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
        if (coreProcess.hProcess != nullptr) {
            TerminateProcess(coreProcess.hProcess, 0);
            WaitForSingleObject(coreProcess.hProcess, 5000);
        }
        MSWindowsWatchdogLifecycle::closeProcessInformation(coreProcess);
        std::error_code error;
        std::filesystem::remove_all(root, error);
    });

    IpcServer ipcServer;
    IpcLogOutputter ipcLogOutputter(ipcServer, kIpcClientGui, false);
    std::atomic_bool inspectionAttempted{false};
    MSWindowsWatchdog watchdog(
        false, false, ipcServer, ipcLogOutputter, daemon,
        std::function<void(HANDLE, DWORD, int)>{},
        [&](DWORD) -> HANDLE {
            inspectionAttempted = true;
            return nullptr;
        });
    watchdog.startAsync();
    ASSERT_TRUE(watchdog.stopCommandAndWait(std::chrono::seconds(2)));

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    std::wstring command = L"\"" + core.wstring() + L"\" --wait";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    ASSERT_TRUE(CreateProcessW(
        nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, root.wstring().c_str(),
        &startup, &coreProcess));

    EXPECT_TRUE(watchdog.stopCommandAndWait(std::chrono::milliseconds(2500)));
    EXPECT_TRUE(inspectionAttempted.load());
    DWORD exitCode = 0;
    ASSERT_TRUE(GetExitCodeProcess(coreProcess.hProcess, &exitCode));
    EXPECT_EQ(exitCode, STILL_ACTIVE);
    watchdog.stop();
}

TEST(MSWindowsWatchdogLifecycleTests, UnqueryableHomonymDoesNotBlockStopRevision)
{
    const auto root = std::filesystem::temp_directory_path() /
        ("inputleap-watchdog-query-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::remove_all(root);
    ASSERT_TRUE(std::filesystem::create_directories(root));
    const auto daemon = root / "input-leapd.exe";
    const auto core = root / "input-leaps.exe";
    std::ofstream(daemon, std::ios::binary).put('\0');
    ASSERT_TRUE(std::filesystem::copy_file(
        INPUTLEAP_WATCHDOG_FIXTURE_HELPER_PATH, core,
        std::filesystem::copy_options::overwrite_existing));

    PROCESS_INFORMATION coreProcess{};
    const auto cleanup = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
        if (coreProcess.hProcess != nullptr) {
            TerminateProcess(coreProcess.hProcess, 0);
            WaitForSingleObject(coreProcess.hProcess, 5000);
        }
        MSWindowsWatchdogLifecycle::closeProcessInformation(coreProcess);
        std::error_code error;
        std::filesystem::remove_all(root, error);
    });

    IpcServer ipcServer;
    IpcLogOutputter ipcLogOutputter(ipcServer, kIpcClientGui, false);
    std::atomic_bool queryAttempted{false};
    MSWindowsWatchdog watchdog(
        false, false, ipcServer, ipcLogOutputter, daemon,
        std::function<void(HANDLE, DWORD, int)>{},
        std::function<HANDLE(DWORD)>{},
        [&](HANDLE) -> std::filesystem::path {
            queryAttempted = true;
            return {};
        });
    watchdog.startAsync();
    ASSERT_TRUE(watchdog.stopCommandAndWait(std::chrono::seconds(2)));

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    std::wstring command = L"\"" + core.wstring() + L"\" --wait";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    ASSERT_TRUE(CreateProcessW(
        nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, root.wstring().c_str(),
        &startup, &coreProcess));

    EXPECT_TRUE(watchdog.stopCommandAndWait(std::chrono::milliseconds(2500)));
    EXPECT_TRUE(queryAttempted.load());
    DWORD exitCode = 0;
    ASSERT_TRUE(GetExitCodeProcess(coreProcess.hProcess, &exitCode));
    EXPECT_EQ(exitCode, STILL_ACTIVE);
    watchdog.stop();
}

TEST(MSWindowsWatchdogLifecycleTests, UncanonicalizableManagedCoreDoesNotApplyStopRevision)
{
    const auto root = std::filesystem::temp_directory_path() /
        ("inputleap-watchdog-canonical-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::remove_all(root);
    ASSERT_TRUE(std::filesystem::create_directories(root));
    const auto daemon = root / "input-leapd.exe";
    const auto core = root / "input-leapc.exe";
    std::ofstream(daemon, std::ios::binary).put('\0');
    ASSERT_TRUE(std::filesystem::copy_file(
        INPUTLEAP_WATCHDOG_FIXTURE_HELPER_PATH, core,
        std::filesystem::copy_options::overwrite_existing));

    PROCESS_INFORMATION coreProcess{};
    const auto cleanup = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
        if (coreProcess.hProcess != nullptr) {
            TerminateProcess(coreProcess.hProcess, 0);
            WaitForSingleObject(coreProcess.hProcess, 5000);
        }
        MSWindowsWatchdogLifecycle::closeProcessInformation(coreProcess);
        std::error_code error;
        std::filesystem::remove_all(root, error);
    });

    IpcServer ipcServer;
    IpcLogOutputter ipcLogOutputter(ipcServer, kIpcClientGui, false);
    MSWindowsWatchdog watchdog(false, false, ipcServer, ipcLogOutputter, daemon);
    watchdog.startAsync();
    ASSERT_TRUE(watchdog.stopCommandAndWait(std::chrono::seconds(2)));

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    std::wstring command = L"\"" + core.wstring() + L"\" --wait";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    ASSERT_TRUE(CreateProcessW(
        nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, root.wstring().c_str(),
        &startup, &coreProcess));
    ASSERT_TRUE(std::filesystem::remove(daemon));

    EXPECT_FALSE(watchdog.stopCommandAndWait(std::chrono::milliseconds(2500)));
    DWORD exitCode = 0;
    ASSERT_TRUE(GetExitCodeProcess(coreProcess.hProcess, &exitCode));
    EXPECT_EQ(exitCode, STILL_ACTIVE);
    watchdog.stop();
}

TEST(MSWindowsWatchdogLifecycleTests, ExternalMatchingCoreRemainsActiveAfterStopRevision)
{
    const auto root = std::filesystem::temp_directory_path() /
        ("inputleap-watchdog-external-" + std::to_string(GetCurrentProcessId()));
    const auto daemonDir = root / "installed";
    const auto externalDir = root / "external";
    std::filesystem::remove_all(root);
    ASSERT_TRUE(std::filesystem::create_directories(daemonDir));
    ASSERT_TRUE(std::filesystem::create_directories(externalDir));
    const auto daemon = daemonDir / "input-leapd.exe";
    const auto externalCore = externalDir / "input-leaps.exe";
    std::ofstream(daemon, std::ios::binary).put('\0');
    ASSERT_TRUE(std::filesystem::copy_file(
        INPUTLEAP_WATCHDOG_FIXTURE_HELPER_PATH, externalCore,
        std::filesystem::copy_options::overwrite_existing));

    PROCESS_INFORMATION coreProcess{};
    const auto cleanup = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
        if (coreProcess.hProcess != nullptr) {
            TerminateProcess(coreProcess.hProcess, 0);
            WaitForSingleObject(coreProcess.hProcess, 5000);
        }
        MSWindowsWatchdogLifecycle::closeProcessInformation(coreProcess);
        std::error_code error;
        std::filesystem::remove_all(root, error);
    });

    IpcServer ipcServer;
    IpcLogOutputter ipcLogOutputter(ipcServer, kIpcClientGui, false);
    std::atomic_bool shutdownAttempted{false};
    MSWindowsWatchdog watchdog(
        false, false, ipcServer, ipcLogOutputter, daemon,
        [&](HANDLE handle, DWORD, int) {
            shutdownAttempted = true;
            TerminateProcess(handle, 0);
            WaitForSingleObject(handle, 5000);
        });
    watchdog.startAsync();
    ASSERT_TRUE(watchdog.stopCommandAndWait(std::chrono::seconds(2)));

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    std::wstring command = L"\"" + externalCore.wstring() + L"\" --wait";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    ASSERT_TRUE(CreateProcessW(
        nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, externalDir.wstring().c_str(),
        &startup, &coreProcess));

    EXPECT_TRUE(watchdog.stopCommandAndWait(std::chrono::seconds(2)));
    EXPECT_FALSE(shutdownAttempted.load());
    DWORD exitCode = 0;
    ASSERT_TRUE(GetExitCodeProcess(coreProcess.hProcess, &exitCode));
    EXPECT_EQ(exitCode, STILL_ACTIVE);
    watchdog.stop();
}

} // namespace
} // namespace inputleap
