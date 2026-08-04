/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2009 Chris Schoeneman
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

#include "platform/MSWindowsWatchdog.h"
#include "platform/MSWindowsWatchdogLifecycle.h"
#include "platform/MSWindowsWatchdogOutputRead.h"
#include "platform/MSWindowsWatchdogProcess.h"

#include "ipc/IpcLogOutputter.h"
#include "ipc/IpcServer.h"
#include "ipc/IpcMessage.h"
#include "ipc/Ipc.h"
#include "inputleap/App.h"
#include "inputleap/ArgsBase.h"
#include "mt/Thread.h"
#include "arch/win32/ArchDaemonWindows.h"
#include "arch/win32/XArchWindows.h"
#include "arch/Arch.h"
#include "base/log_outputters.h"
#include "base/Log.h"
#include "base/Time.h"
#include "common/Version.h"

#include <sstream>
#include <UserEnv.h>
#include <Shellapi.h>

namespace inputleap {

#define MAXIMUM_WAIT_TIME 3
enum {
    kOutputBufferSize = 4096
};

typedef VOID (WINAPI *SendSas)(BOOL asUser);

MSWindowsWatchdog::MSWindowsWatchdog(
    bool daemonized,
    bool autoDetectCommand,
    IpcServer& ipcServer,
    IpcLogOutputter& ipcLogOutputter,
    std::filesystem::path daemonExecutableOverride,
    std::function<void(HANDLE, DWORD, int)> shutdownProcessOverride,
    std::function<HANDLE(DWORD)> openProcessOverride,
    std::function<std::filesystem::path(HANDLE)> processExecutableOverride) :
    m_thread(nullptr),
    m_autoDetectCommand(autoDetectCommand),
    m_monitoring(true),
    m_outputMonitoring(false),
    m_commandChanged(false),
    m_stdOutWrite(nullptr),
    m_stdOutRead(nullptr),
    m_outputThread(nullptr),
    m_ipcServer(ipcServer),
    m_ipcLogOutputter(ipcLogOutputter),
    m_elevateProcess(false),
    m_processFailures(0),
    m_processRunning(false),
    m_fileLogOutputter(nullptr),
    m_daemonized(daemonized),
    m_daemonExecutableOverride(std::move(daemonExecutableOverride)),
    m_shutdownProcessOverride(std::move(shutdownProcessOverride)),
    m_openProcessOverride(std::move(openProcessOverride)),
    m_processExecutableOverride(std::move(processExecutableOverride))
{
    ZeroMemory(&m_processInfo, sizeof(m_processInfo));
}

MSWindowsWatchdog::~MSWindowsWatchdog()
{
    stop();
}

void
MSWindowsWatchdog::startAsync()
{
    if (m_thread != nullptr || m_outputThread != nullptr) return;

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    if (!CreatePipe(&m_stdOutRead, &m_stdOutWrite, &attributes, 0)) {
        throw std::runtime_error(error_code_to_string_windows(GetLastError()));
    }
    if (!SetHandleInformation(m_stdOutRead, HANDLE_FLAG_INHERIT, 0)) {
        const DWORD error = GetLastError();
        CloseHandle(m_stdOutRead);
        CloseHandle(m_stdOutWrite);
        m_stdOutRead = nullptr;
        m_stdOutWrite = nullptr;
        throw std::runtime_error(error_code_to_string_windows(error));
    }

    m_monitoring = true;
    m_outputMonitoring = true;
    try {
        m_outputThread = new Thread([this](){ output_loop(); });
        m_thread = new Thread([this](){ main_loop(); });
    }
    catch (...) {
        m_monitoring = false;
        m_outputMonitoring = false;
        if (m_outputThread != nullptr) {
            m_outputThread->wait();
            delete m_outputThread;
            m_outputThread = nullptr;
        }
        CloseHandle(m_stdOutRead);
        CloseHandle(m_stdOutWrite);
        m_stdOutRead = nullptr;
        m_stdOutWrite = nullptr;
        throw;
    }
}

void
MSWindowsWatchdog::stop()
{
    m_monitoring = false;
    m_stateChanged.notify_all();

    MSWindowsWatchdogLifecycle::join({
        [this] {
            if (m_thread != nullptr) m_thread->wait();
        },
        [this] {
            if (m_stdOutWrite != nullptr && m_stdOutWrite != INVALID_HANDLE_VALUE) {
                CloseHandle(m_stdOutWrite);
                m_stdOutWrite = nullptr;
            }
        },
        [this] {
            m_outputMonitoring = false;
        },
        [this] {
            if (m_outputThread != nullptr) m_outputThread->wait();
        }});
    delete m_thread;
    m_thread = nullptr;
    delete m_outputThread;
    m_outputThread = nullptr;
    if (m_stdOutRead != nullptr && m_stdOutRead != INVALID_HANDLE_VALUE) {
        CloseHandle(m_stdOutRead);
        m_stdOutRead = nullptr;
    }
    closeProcessInformation();
}

void MSWindowsWatchdog::closeProcessInformation() noexcept
{
    MSWindowsWatchdogLifecycle::closeProcessInformation(m_processInfo);
}

HANDLE
MSWindowsWatchdog::duplicateProcessToken(HANDLE process, LPSECURITY_ATTRIBUTES security)
{
    HANDLE sourceToken;

    BOOL tokenRet = OpenProcessToken(
        process,
        TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS,
        &sourceToken);

    if (!tokenRet) {
        LOG_ERR("could not open token, process handle: %d", process);
        throw std::runtime_error(error_code_to_string_windows(GetLastError()));
    }
    auto closeSourceToken = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
        CloseHandle(sourceToken);
    });

    LOG_DEBUG("got token %i, duplicating", sourceToken);

    HANDLE newToken;
    BOOL duplicateRet = DuplicateTokenEx(
        sourceToken, TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS, security,
        SecurityImpersonation, TokenPrimary, &newToken);

    if (!duplicateRet) {
        LOG_ERR("could not duplicate token %i", sourceToken);
        throw std::runtime_error(error_code_to_string_windows(GetLastError()));
    }

    LOG_DEBUG("duplicated, new token: %i", newToken);
    return newToken;
}

HANDLE
MSWindowsWatchdog::getUserToken(LPSECURITY_ATTRIBUTES security, bool launchElevated)
{
    // always elevate if we are at the vista/7 login screen. we could also
    // elevate for the uac dialog (consent.exe) but this would be pointless,
    // since InputLeap would re-launch as non-elevated after the desk switch,
    // and so would be unusable with the new elevated process taking focus.
    if (launchElevated) {
        LOG_DEBUG("getting elevated token");

        HANDLE process;
        if (!m_session.isProcessInSession("winlogon.exe", &process)) {
            throw XMSWindowsWatchdogError("cannot get user token without winlogon.exe");
        }
        auto closeProcess = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
            CloseHandle(process);
        });
        return duplicateProcessToken(process, security);
    } else {
        LOG_DEBUG("getting non-elevated token");
        return m_session.getUserToken(security);
    }
}

void MSWindowsWatchdog::main_loop()
{
    shutdownExistingProcesses();

    SendSas sendSasFunc = nullptr;
    HINSTANCE sasLib = LoadLibrary("sas.dll");
    auto freeSasLibrary = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
        if (sasLib != nullptr) FreeLibrary(sasLib);
    });
    if (sasLib) {
        LOG_DEBUG("found sas.dll");
        sendSasFunc = (SendSas)GetProcAddress(sasLib, "SendSAS");
    }

    ZeroMemory(&m_processInfo, sizeof(PROCESS_INFORMATION));

    while (m_monitoring) {
        try {
            std::uint64_t stopRevision = 0;
            {
                std::lock_guard<std::mutex> lock(m_stateMutex);
                if (m_command.empty() && m_appliedRevision < m_commandRevision)
                    stopRevision = m_commandRevision;
            }
            if (stopRevision != 0) {
                LOG_INFO("applying correlated empty command, shutting down core");
                shutdownExistingProcesses();
                m_processRunning = false;
                {
                    std::lock_guard<std::mutex> lock(m_stateMutex);
                    m_appliedRevision = (std::max)(m_appliedRevision, stopRevision);
                }
                m_stateChanged.notify_all();
                continue;
            }

            if (m_processFailures != 0) {
                // increasing backoff period, maximum of 10 seconds.
                int timeout = (m_processFailures * 2) < 10 ? (m_processFailures * 2) : 10;
                LOG_INFO("backing off, wait=%ds, failures=%d", timeout, m_processFailures.load());
                if (!MSWindowsWatchdogLifecycle::waitWhileMonitoring(
                        m_stateChanged, m_stateMutex, m_monitoring,
                        std::chrono::seconds(timeout))) {
                    break;
                }
            }

            if (m_monitoring && !getCommand().empty() &&
                ((m_processFailures != 0) || m_session.hasChanged() || m_commandChanged)) {
                startProcess();
            }

            if (m_processRunning && !isProcessActive()) {

                m_processFailures++;
                m_processRunning = false;

                LOG_WARN("detected application not running, pid=%d",
                    m_processInfo.dwProcessId);
                closeProcessInformation();
            }

            if (sendSasFunc != nullptr) {

                HANDLE sendSasEvent = CreateEvent(nullptr, FALSE, FALSE, "Global\\SendSAS");
                if (sendSasEvent != nullptr) {

                    // use SendSAS event to wait for next session (timeout 1 second).
                    if (WaitForSingleObject(sendSasEvent, 1000) == WAIT_OBJECT_0) {
                        LOG_DEBUG("calling SendSAS");
                        sendSasFunc(FALSE);
                    }

                    CloseHandle(sendSasEvent);
                    continue;
                }
            }

            // if the sas event failed, wait by sleeping.
            if (!MSWindowsWatchdogLifecycle::waitWhileMonitoring(
                    m_stateChanged, m_stateMutex, m_monitoring,
                    std::chrono::seconds(1))) {
                break;
            }

        }
        catch (std::exception& e) {
            LOG_ERR("failed to launch, error: %s", e.what());
            m_processFailures++;
            m_processRunning = false;
            continue;
        }
        catch (...) {
            LOG_ERR("failed to launch, unknown error.");
            m_processFailures++;
            m_processRunning = false;
            continue;
        }
    }

    if (m_processRunning) {
        LOG_DEBUG("terminated running process on exit");
        shutdownProcess(m_processInfo.hProcess, m_processInfo.dwProcessId, 20);
    }
    closeProcessInformation();

    LOG_DEBUG("watchdog main thread finished");
}

bool
MSWindowsWatchdog::isProcessActive()
{
    if (!m_processRunning.load()) return false;
    DWORD exitCode;
    GetExitCodeProcess(m_processInfo.hProcess, &exitCode);
    return exitCode == STILL_ACTIVE;
}

void
MSWindowsWatchdog::setFileLogOutputter(FileLogOutputter* outputter)
{
    std::lock_guard<std::mutex> lock(m_fileLogMutex);
    m_fileLogOutputter = outputter;
}

void
MSWindowsWatchdog::startProcess(
    std::function<MSWindowsSessionLockState()> sessionLockStateOverride,
    std::function<HANDLE(LPSECURITY_ATTRIBUTES, bool)> userTokenOverride)
{
    std::string command = getCommand();
    bool elevateProcess = false;
    std::uint64_t startRevision = 0;
    {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        if (!m_autoDetectCommand || m_commandRevision != 0)
            command = m_command;
        elevateProcess = m_elevateProcess;
        startRevision = m_commandRevision;
        m_commandChanged = false;
    }
    if (command.empty()) {
        throw XMSWindowsWatchdogError("cannot start process, command is empty");
    }

    if (m_processRunning) {
        LOG_DEBUG("closing existing process to make way for new one");
        shutdownProcess(m_processInfo.hProcess, m_processInfo.dwProcessId, 20);
        m_processRunning = false;
    }
    closeProcessInformation();

    m_session.updateActiveSession();

    BOOL createRet;
    bool launchedElevated = elevateProcess;
    if (!m_daemonized) {
        createRet = doStartProcessAsSelf(command);
    } else {
        const auto lockState = sessionLockStateOverride ?
            sessionLockStateOverride() : m_session.getActiveSessionLockState();
        launchedElevated = MSWindowsWatchdogLifecycle::shouldLaunchElevated(
            elevateProcess, lockState);
        if (lockState == MSWindowsSessionLockState::Unknown) {
            LOG_WARN("could not identify active session lock state; automatic elevation disabled");
        }

        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        HANDLE userToken = userTokenOverride ?
            userTokenOverride(&sa, launchedElevated) :
            getUserToken(&sa, launchedElevated);
        auto closeUserToken = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
            CloseHandle(userToken);
        });

        // patch by Jack Zhou and Henry Tung
        // set UIAccess to fix Windows 8 GUI interaction
        // http://symless.com/spit/issues/details/3338/#c70
        DWORD uiAccess = 1;
        SetTokenInformation(userToken, TokenUIAccess, &uiAccess, sizeof(DWORD));

        createRet = doStartProcessAsUser(command, userToken, &sa);
    }

    if (!createRet) {
        const DWORD error = GetLastError();
        LOG_ERR("could not launch");
        closeProcessInformation();
        throw std::runtime_error(error_code_to_string_windows(error));
    }
    else {
        // wait for program to fail.
        inputleap::this_thread_sleep(1);
        DWORD initialExitCode = 0;
        if (!GetExitCodeProcess(m_processInfo.hProcess, &initialExitCode) ||
            initialExitCode != STILL_ACTIVE) {
            closeProcessInformation();
            throw XMSWindowsWatchdogError("process immediately stopped");
        }

        if (m_processInfo.hThread != nullptr) {
            CloseHandle(m_processInfo.hThread);
            m_processInfo.hThread = nullptr;
            m_processInfo.dwThreadId = 0;
        }

        m_processRunning = true;
        m_processFailures = 0;
        {
            std::lock_guard<std::mutex> lock(m_stateMutex);
            m_appliedRevision = (std::max)(m_appliedRevision, startRevision);
        }
        m_stateChanged.notify_all();

        LOG_DEBUG("started process, session=%i, elevated: %s, command=%s",
            m_session.getActiveSessionId(),
            launchedElevated ? "yes" : "no",
            command.c_str());
    }
}

BOOL MSWindowsWatchdog::doStartProcessAsSelf(std::string& command)
{
    LOG_INFO("starting new process as self");
    return MSWindowsWatchdogProcess::createAsSelf(
        command, m_stdOutWrite, m_processInfo);
}

BOOL MSWindowsWatchdog::doStartProcessAsUser(std::string& command, HANDLE userToken,
                                             LPSECURITY_ATTRIBUTES sa)
{
    LPVOID environment;
    BOOL blockRet = CreateEnvironmentBlock(&environment, userToken, FALSE);
    if (!blockRet) {
        LOG_ERR("could not create environment block");
        throw std::runtime_error(error_code_to_string_windows(GetLastError()));
    }
    auto destroyEnvironment = MSWindowsWatchdogLifecycle::makeScopeExit([&] {
        DestroyEnvironmentBlock(environment);
    });

    // re-launch in current active user session
    LOG_INFO("starting new process as privileged user");
    (void)sa;
    BOOL createRet = MSWindowsWatchdogProcess::createAsUser(
        command, m_stdOutWrite, userToken, environment, m_processInfo);

    return createRet;
}

void
MSWindowsWatchdog::setCommand(const std::string& command, bool elevate)
{
    (void)updateCommand(command, elevate);
}

bool MSWindowsWatchdog::setCommandAndWait(
    const std::string& command, bool elevate, std::chrono::milliseconds timeout)
{
    const std::uint64_t revision = updateCommand(command, elevate);
    std::unique_lock<std::mutex> lock(m_stateMutex);
    return m_stateChanged.wait_for(lock, timeout, [&] {
        return m_appliedRevision >= revision || !m_monitoring.load();
    }) && m_appliedRevision >= revision;
}

std::uint64_t MSWindowsWatchdog::updateCommand(const std::string& command, bool elevate)
{
    LOG_INFO("service command updated");
    std::lock_guard<std::mutex> lock(m_stateMutex);
    m_command = command;
    m_elevateProcess = elevate;
    m_commandChanged = true;
    m_processFailures = 0;
    const std::uint64_t revision = ++m_commandRevision;
    m_stateChanged.notify_all();
    return revision;
}

bool MSWindowsWatchdog::stopCommandAndWait(std::chrono::milliseconds timeout)
{
    const std::uint64_t revision = updateCommand(std::string(), false);
    std::unique_lock<std::mutex> lock(m_stateMutex);
    return m_stateChanged.wait_for(lock, timeout, [&] {
        return m_appliedRevision >= revision || !m_monitoring.load();
    }) && m_appliedRevision >= revision;
}

std::string
MSWindowsWatchdog::getCommand() const
{
    {
        std::lock_guard<std::mutex> lock(m_stateMutex);
        if (!m_autoDetectCommand || m_commandRevision != 0) {
            return m_command;
        }
    }

    // seems like a fairly convoluted way to get the process name
    const char* launchName = App::instance().argsBase().m_exename.c_str();
    std::string args = ARCH->commandLine();

    // build up a full command line
    std::stringstream cmdTemp;
    cmdTemp << launchName << args;

    std::string cmd = cmdTemp.str();

    size_t i;
    std::string find = "--relaunch";
    while ((i = cmd.find(find)) != std::string::npos) {
        cmd.replace(i, find.length(), "");
    }

    return cmd;
}

void MSWindowsWatchdog::output_loop()
{
    // +1 char for \0
    CHAR buffer[kOutputBufferSize + 1];
    const HANDLE readHandle = m_stdOutRead;

    while (true) {
        DWORD bytesRead = 0;
        const auto result = MSWindowsWatchdogOutputRead::readAvailable(
            readHandle, buffer, kOutputBufferSize, bytesRead);
        if (result == MSWindowsWatchdogOutputRead::Result::Data) {
            buffer[bytesRead] = '\0';
            m_ipcLogOutputter.write(kINFO, buffer);
            std::lock_guard<std::mutex> lock(m_fileLogMutex);
            if (m_fileLogOutputter != nullptr) {
                m_fileLogOutputter->write(kINFO, buffer);
            }
        }
        else {
            if (!m_outputMonitoring) break;
            inputleap::this_thread_sleep(0.05);
        }
    }
}

void
MSWindowsWatchdog::shutdownProcess(HANDLE handle, DWORD pid, int timeout)
{
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE)
        throw std::runtime_error("could not open core process for shutdown");

    DWORD exitCode = STILL_ACTIVE;
    if (!GetExitCodeProcess(handle, &exitCode))
        throw std::runtime_error(error_code_to_string_windows(GetLastError()));
    if (exitCode != STILL_ACTIVE) return;

    IpcShutdownMessage shutdown;
    m_ipcServer.send(shutdown, kIpcClientNode);

    const double start = inputleap::current_time_seconds();
    while (true) {
        if (!GetExitCodeProcess(handle, &exitCode))
            throw std::runtime_error(error_code_to_string_windows(GetLastError()));
        if (exitCode != STILL_ACTIVE) {
            LOG_INFO("process %d was shutdown gracefully", pid);
            break;
        }

        const double elapsed = inputleap::current_time_seconds() - start;
        if (elapsed > timeout) {
            LOG_WARN("shutdown timed out after %d secs, forcefully terminating", (int)elapsed);
            if (!TerminateProcess(handle, kExitSuccess))
                throw std::runtime_error(error_code_to_string_windows(GetLastError()));
            if (WaitForSingleObject(handle, 5000) != WAIT_OBJECT_0)
                throw std::runtime_error("core process termination was not confirmed");
            break;
        }
        inputleap::this_thread_sleep(1);
    }

    if (!GetExitCodeProcess(handle, &exitCode) || exitCode == STILL_ACTIVE)
        throw std::runtime_error("core process is still active after shutdown");
}

void
MSWindowsWatchdog::shutdownExistingProcesses()
{
    const auto daemonExecutable = m_daemonExecutableOverride.empty()
        ? MSWindowsWatchdogLifecycle::currentProcessExecutable()
        : m_daemonExecutableOverride;
    if (daemonExecutable.empty()) {
        throw std::runtime_error("could not resolve daemon executable for core shutdown");
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        LOG_ERR("could not get process snapshot");
        throw std::runtime_error(error_code_to_string_windows(GetLastError()));
    }

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    BOOL gotEntry = Process32First(snapshot, &entry);
    if (!gotEntry) {
        const DWORD error = GetLastError();
        CloseHandle(snapshot);
        LOG_ERR("could not get first process entry");
        throw std::runtime_error(error_code_to_string_windows(error));
    }

    try {
        while (gotEntry) {
            if (entry.th32ProcessID != 0 &&
                MSWindowsWatchdogLifecycle::isCoreProcessName(entry.szExeFile)) {
                HANDLE handle = m_openProcessOverride
                    ? m_openProcessOverride(entry.th32ProcessID)
                    : OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
                        FALSE, entry.th32ProcessID);
                if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
                    LOG_WARN("ignored uninspectable core-name candidate pid=%d",
                             entry.th32ProcessID);
                }
                else {
                    try {
                        const auto candidate = m_processExecutableOverride
                            ? m_processExecutableOverride(handle)
                            : MSWindowsWatchdogLifecycle::processExecutable(handle);
                        if (candidate.empty()) {
                            LOG_WARN("ignored core-name candidate with unresolved path pid=%d",
                                     entry.th32ProcessID);
                        }
                        else if (MSWindowsWatchdogLifecycle::isManagedCorePath(
                                     candidate, daemonExecutable)) {
                            if (m_shutdownProcessOverride) {
                                m_shutdownProcessOverride(handle, entry.th32ProcessID, 10);
                            }
                            else {
                                shutdownProcess(handle, entry.th32ProcessID, 10);
                            }
                        }
                        CloseHandle(handle);
                    }
                    catch (...) {
                        CloseHandle(handle);
                        throw;
                    }
                }
            }

            gotEntry = Process32Next(snapshot, &entry);
            if (!gotEntry) {
                const DWORD error = GetLastError();
                if (error != ERROR_NO_MORE_FILES) {
                    LOG_ERR("could not get subsequent process entry");
                    throw std::runtime_error(error_code_to_string_windows(error));
                }
            }
        }
    }
    catch (...) {
        CloseHandle(snapshot);
        throw;
    }

    CloseHandle(snapshot);
    m_processRunning = false;
}

} // namespace inputleap
