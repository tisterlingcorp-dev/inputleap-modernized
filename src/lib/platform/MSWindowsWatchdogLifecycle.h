#pragma once

#include "platform/MSWindowsSession.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace inputleap {

class MSWindowsWatchdogLifecycle {
public:
    static bool shouldLaunchElevated(
        bool elevationRequested,
        MSWindowsSessionLockState lockState) noexcept
    {
        return elevationRequested || lockState == MSWindowsSessionLockState::Locked;
    }

    template<class Function>
    class ScopeExit {
    public:
        explicit ScopeExit(Function function) : function_(std::move(function)) { }
        ScopeExit(const ScopeExit&) = delete;
        ScopeExit& operator=(const ScopeExit&) = delete;
        ScopeExit(ScopeExit&& other) noexcept :
            function_(std::move(other.function_)), active_(other.active_)
        {
            other.active_ = false;
        }
        ~ScopeExit() noexcept
        {
            if (!active_) return;
            try { function_(); }
            catch (...) { }
        }

    private:
        Function function_;
        bool active_{true};
    };

    template<class Function>
    static ScopeExit<Function> makeScopeExit(Function function)
    {
        return ScopeExit<Function>(std::move(function));
    }

    struct Operations {
        std::function<void()> joinMain;
        std::function<void()> closeOutputWriter;
        std::function<void()> requestOutputStop;
        std::function<void()> joinOutput;
    };

    static void join(Operations operations)
    {
        operations.joinMain();
        operations.closeOutputWriter();
        operations.requestOutputStop();
        operations.joinOutput();
    }

    static void closeProcessInformation(PROCESS_INFORMATION& info) noexcept
    {
        if (info.hThread != nullptr && info.hThread != INVALID_HANDLE_VALUE)
            CloseHandle(info.hThread);
        if (info.hProcess != nullptr && info.hProcess != INVALID_HANDLE_VALUE)
            CloseHandle(info.hProcess);
        info = {};
    }

    static std::filesystem::path currentProcessExecutable()
    {
        std::vector<wchar_t> buffer(512);
        for (;;) {
            const DWORD size = GetModuleFileNameW(
                nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
            if (size == 0) return {};
            if (size < buffer.size() - 1)
                return std::filesystem::path(std::wstring(buffer.data(), size));
            if (buffer.size() >= 32768) return {};
            buffer.resize(buffer.size() * 2);
        }
    }

    static std::filesystem::path processExecutable(HANDLE process)
    {
        std::vector<wchar_t> buffer(512);
        for (;;) {
            DWORD size = static_cast<DWORD>(buffer.size());
            if (QueryFullProcessImageNameW(process, 0, buffer.data(), &size))
                return std::filesystem::path(std::wstring(buffer.data(), size));
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || buffer.size() >= 32768)
                return {};
            buffer.resize(buffer.size() * 2);
        }
    }

    static bool isManagedCorePath(const std::filesystem::path& candidate,
                                  const std::filesystem::path& daemon)
    {
        std::error_code error;
        const auto canonicalDaemon = std::filesystem::canonical(daemon, error);
        if (error) {
            throw std::runtime_error("could not canonicalize daemon executable");
        }
        const auto canonicalCandidate = std::filesystem::canonical(candidate, error);
        if (error) {
            return false;
        }
        if (_wcsicmp(canonicalCandidate.parent_path().native().c_str(),
                     canonicalDaemon.parent_path().native().c_str()) != 0) {
            return false;
        }
        const auto filename = canonicalCandidate.filename().native();
        return _wcsicmp(filename.c_str(), L"input-leaps.exe") == 0 ||
               _wcsicmp(filename.c_str(), L"input-leapc.exe") == 0;
    }

    static bool isCoreProcessName(const char* name) noexcept
    {
        return name != nullptr &&
               (_stricmp(name, "input-leaps.exe") == 0 ||
                _stricmp(name, "input-leapc.exe") == 0);
    }

    static void requireCoreProcessHandle(HANDLE process)
    {
        if (process == nullptr || process == INVALID_HANDLE_VALUE)
            throw std::runtime_error("could not inspect packaged core process");
    }

    static void requireCoreProcessExecutable(const std::filesystem::path& executable)
    {
        if (executable.empty())
            throw std::runtime_error("could not resolve packaged core executable");
    }

    template<class Rep, class Period>
    static bool waitWhileMonitoring(
        std::condition_variable& changed, std::mutex& mutex,
        const std::atomic_bool& monitoring,
        const std::chrono::duration<Rep, Period>& timeout)
    {
        std::unique_lock<std::mutex> lock(mutex);
        changed.wait_for(lock, timeout, [&monitoring] {
            return !monitoring.load();
        });
        return monitoring.load();
    }
};

} // namespace inputleap
