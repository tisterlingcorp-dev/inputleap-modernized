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

#pragma once

#include "platform/MSWindowsSession.h"
#include "base/Fwd.h"
#include "inputleap/Exceptions.h"
#include "arch/IArchMultithread.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <list>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>

namespace inputleap {

class Thread;
class IpcLogOutputter;
class IpcServer;

class MSWindowsWatchdog {
public:
    MSWindowsWatchdog(
        bool daemonized,
        bool autoDetectCommand,
        IpcServer& ipcServer,
        IpcLogOutputter& ipcLogOutputter,
        std::filesystem::path daemonExecutableOverride = {},
        std::function<void(HANDLE, DWORD, int)> shutdownProcessOverride = {},
        std::function<HANDLE(DWORD)> openProcessOverride = {},
        std::function<std::filesystem::path(HANDLE)> processExecutableOverride = {});
    ~MSWindowsWatchdog();

    void startAsync();
    std::string getCommand() const;
    void setCommand(const std::string& command, bool elevate);
    bool setCommandAndWait(const std::string& command, bool elevate,
                           std::chrono::milliseconds timeout);
    bool stopCommandAndWait(std::chrono::milliseconds timeout);
    void stop();
    bool isProcessActive();
    void setFileLogOutputter(FileLogOutputter* outputter);

private:
    friend class MSWindowsWatchdogTestPeer;

    void main_loop();
    void output_loop();
    void shutdownProcess(HANDLE handle, DWORD pid, int timeout);
    void shutdownExistingProcesses();
    HANDLE duplicateProcessToken(HANDLE process, LPSECURITY_ATTRIBUTES security);
    HANDLE getUserToken(LPSECURITY_ATTRIBUTES security, bool launchElevated);
    void startProcess(
        std::function<MSWindowsSessionLockState()> sessionLockStateOverride = {},
        std::function<HANDLE(LPSECURITY_ATTRIBUTES, bool)> userTokenOverride = {});
    void closeProcessInformation() noexcept;
    BOOL doStartProcessAsUser(std::string& command, HANDLE userToken, LPSECURITY_ATTRIBUTES sa);
    BOOL doStartProcessAsSelf(std::string& command);
    std::uint64_t updateCommand(const std::string& command, bool elevate);

private:
    Thread* m_thread;
    bool m_autoDetectCommand;
    mutable std::mutex m_stateMutex;
    std::condition_variable m_stateChanged;
    std::string m_command;
    std::uint64_t m_commandRevision{0};
    std::uint64_t m_appliedRevision{0};
    std::atomic_bool m_monitoring;
    std::atomic_bool m_outputMonitoring;
    std::atomic_bool m_commandChanged;
    HANDLE m_stdOutWrite;
    HANDLE m_stdOutRead;
    Thread* m_outputThread;
    IpcServer& m_ipcServer;
    IpcLogOutputter& m_ipcLogOutputter;
    bool m_elevateProcess;
    MSWindowsSession m_session;
    PROCESS_INFORMATION m_processInfo;
    std::atomic_int m_processFailures;
    std::atomic_bool m_processRunning;
    std::mutex m_fileLogMutex;
    FileLogOutputter* m_fileLogOutputter;
    bool m_daemonized;
    const std::filesystem::path m_daemonExecutableOverride;
    const std::function<void(HANDLE, DWORD, int)> m_shutdownProcessOverride;
    const std::function<HANDLE(DWORD)> m_openProcessOverride;
    const std::function<std::filesystem::path(HANDLE)> m_processExecutableOverride;
};

//! Relauncher error
/*!
An error occurred in the process watchdog.
*/
class XMSWindowsWatchdogError : public XBase {
public:
    XMSWindowsWatchdogError(const std::string& msg) : XBase(msg) { }

    // XBase overrides
    virtual std::string getWhat() const noexcept { return what(); }
};

} // namespace inputleap
