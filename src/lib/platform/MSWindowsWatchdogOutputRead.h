#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <algorithm>

namespace inputleap {

class MSWindowsWatchdogOutputRead
{
public:
    enum class Result { Data, NoData, Closed, Error };

    static Result readAvailable(HANDLE readHandle, char* buffer, DWORD capacity,
                                DWORD& bytesRead)
    {
        bytesRead = 0;
        if (readHandle == nullptr || readHandle == INVALID_HANDLE_VALUE ||
            buffer == nullptr || capacity == 0) {
            return Result::Error;
        }

        DWORD available = 0;
        if (!PeekNamedPipe(readHandle, nullptr, 0, nullptr, &available, nullptr)) {
            return GetLastError() == ERROR_BROKEN_PIPE ? Result::Closed
                                                       : Result::Error;
        }
        if (available == 0) return Result::NoData;

        const DWORD requested = (std::min)(available, capacity);
        if (!ReadFile(readHandle, buffer, requested, &bytesRead, nullptr)) {
            return GetLastError() == ERROR_BROKEN_PIPE ? Result::Closed
                                                       : Result::Error;
        }
        return bytesRead == 0 ? Result::Closed : Result::Data;
    }
};

} // namespace inputleap
