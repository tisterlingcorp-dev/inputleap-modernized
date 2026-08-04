#include "WindowsStagedPackageGuard.h"

#define NOMINMAX
#include <Windows.h>

#include <QDir>
#include <QFileInfo>

namespace {

bool isReparsePoint(const QString& path)
{
    const DWORD attributes = GetFileAttributesW(
        reinterpret_cast<LPCWSTR>(path.utf16()));
    return attributes == INVALID_FILE_ATTRIBUTES ||
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

bool pathContainsReparsePoint(const QString& path)
{
    QString current = QFileInfo(path).absoluteFilePath();
    if (current.isEmpty())
        return true;
    for (;;) {
        if (isReparsePoint(current))
            return true;
        const QString parent = QFileInfo(current).dir().absolutePath();
        if (parent == current)
            return false;
        current = parent;
    }
}

bool identity(HANDLE handle, quint64* volume, quint64* high, quint64* low)
{
    BY_HANDLE_FILE_INFORMATION information{};
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandle(handle, &information) ||
        (information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                                         FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        information.nNumberOfLinks != 1) {
        return false;
    }
    *volume = information.dwVolumeSerialNumber;
    *high = information.nFileIndexHigh;
    *low = information.nFileIndexLow;
    return true;
}

HANDLE openLocked(const QString& path)
{
    return CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()), GENERIC_READ,
                       FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                       nullptr);
}

}

WindowsStagedPackageGuard::~WindowsStagedPackageGuard()
{
    release();
}

bool WindowsStagedPackageGuard::lock(const QString& path)
{
    release();
    if (pathContainsReparsePoint(path))
        return false;
    HANDLE handle = openLocked(path);
    if (handle == INVALID_HANDLE_VALUE)
        return false;
    quint64 volume = 0;
    quint64 high = 0;
    quint64 low = 0;
    if (!identity(handle, &volume, &high, &low)) {
        CloseHandle(handle);
        return false;
    }
    primaryHandle_ = handle;
    path_ = QFileInfo(path).absoluteFilePath();
    volumeSerial_ = volume;
    fileIdHigh_ = high;
    fileIdLow_ = low;
    return !path_.isEmpty();
}

bool WindowsStagedPackageGuard::revalidatePath()
{
    if (!isLocked() || pathContainsReparsePoint(path_))
        return false;
    if (validationHandle_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(validationHandle_));
        validationHandle_ = nullptr;
    }
    HANDLE handle = openLocked(path_);
    if (handle == INVALID_HANDLE_VALUE)
        return false;
    quint64 volume = 0;
    quint64 high = 0;
    quint64 low = 0;
    if (!identity(handle, &volume, &high, &low) ||
        volume != volumeSerial_ || high != fileIdHigh_ || low != fileIdLow_) {
        CloseHandle(handle);
        return false;
    }
    validationHandle_ = handle;
    return true;
}

void WindowsStagedPackageGuard::release()
{
    if (validationHandle_ != nullptr)
        CloseHandle(static_cast<HANDLE>(validationHandle_));
    if (primaryHandle_ != nullptr)
        CloseHandle(static_cast<HANDLE>(primaryHandle_));
    validationHandle_ = nullptr;
    primaryHandle_ = nullptr;
    path_.clear();
    volumeSerial_ = 0;
    fileIdHigh_ = 0;
    fileIdLow_ = 0;
}

bool WindowsStagedPackageGuard::isLocked() const
{
    return primaryHandle_ != nullptr;
}
