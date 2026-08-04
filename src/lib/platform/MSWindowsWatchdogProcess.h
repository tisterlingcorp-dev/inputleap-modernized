#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <UserEnv.h>

#include <string>
#include <vector>

namespace inputleap {

class MSWindowsWatchdogProcess {
public:
    static BOOL createAsSelf(const std::string& command, HANDLE output,
                             PROCESS_INFORMATION& process)
    {
        return create(command, output, nullptr, nullptr, process);
    }

    static BOOL createAsUser(const std::string& command, HANDLE output,
                             HANDLE userToken, LPVOID environment,
                             PROCESS_INFORMATION& process)
    {
        return create(command, output, userToken, environment, process);
    }

private:
    static std::string workingDirectory(const std::string& command)
    {
        const std::size_t first = command.find_first_not_of(" \t");
        if (first == std::string::npos) return {};

        const bool quoted = command[first] == '"';
        const std::size_t executableStart = quoted ? first + 1 : first;
        const std::size_t executableEnd = quoted
            ? command.find('"', executableStart)
            : command.find_first_of(" \t", executableStart);
        if (executableEnd == std::string::npos || executableEnd <= executableStart) return {};

        std::string executable = command.substr(
            executableStart, executableEnd - executableStart);
        char fullPath[MAX_PATH]{};
        const DWORD length = GetFullPathNameA(
            executable.c_str(), static_cast<DWORD>(sizeof(fullPath)), fullPath, nullptr);
        if (length == 0 || length >= sizeof(fullPath)) return {};

        std::string path(fullPath, length);
        const std::size_t separator = path.find_last_of("\\/");
        return separator == std::string::npos ? std::string() : path.substr(0, separator);
    }

    static BOOL create(const std::string& command, HANDLE output,
                       HANDLE userToken, LPVOID environment,
                       PROCESS_INFORMATION& process)
    {
        STARTUPINFOEXA startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.lpDesktop = const_cast<char*>("winsta0\\Default");
        startup.StartupInfo.hStdError = output;
        startup.StartupInfo.hStdOutput = output;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;

        SIZE_T attributeBytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeBytes);
        if (attributeBytes == 0) return FALSE;
        std::vector<unsigned char> attributes(attributeBytes);
        startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
            attributes.data());
        if (!InitializeProcThreadAttributeList(
                startup.lpAttributeList, 1, 0, &attributeBytes)) {
            return FALSE;
        }

        HANDLE inheritedHandles[] = {output};
        if (!UpdateProcThreadAttribute(
                startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                inheritedHandles, sizeof(inheritedHandles), nullptr, nullptr)) {
            const DWORD error = GetLastError();
            DeleteProcThreadAttributeList(startup.lpAttributeList);
            SetLastError(error);
            return FALSE;
        }

        std::vector<char> mutableCommand(command.begin(), command.end());
        mutableCommand.push_back('\0');
        const std::string currentDirectory = workingDirectory(command);
        constexpr DWORD flags = ABOVE_NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW |
                                CREATE_UNICODE_ENVIRONMENT |
                                EXTENDED_STARTUPINFO_PRESENT;
        BOOL created = FALSE;
        if (userToken == nullptr) {
            created = CreateProcessA(
                nullptr, mutableCommand.data(), nullptr, nullptr, TRUE, flags,
                nullptr, currentDirectory.empty() ? nullptr : currentDirectory.c_str(),
                &startup.StartupInfo, &process);
        }
        else {
            created = CreateProcessAsUserA(
                userToken, nullptr, mutableCommand.data(), nullptr, nullptr,
                TRUE, flags, environment,
                currentDirectory.empty() ? nullptr : currentDirectory.c_str(),
                &startup.StartupInfo, &process);
        }
        const DWORD error = created ? ERROR_SUCCESS : GetLastError();
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        if (!created) SetLastError(error);
        return created;
    }
};

} // namespace inputleap
