#include "platform/MSWindowsClipboardFileListConverter.h"

#include "base/Unicode.h"

#include <Shlobj.h>
#include <shellapi.h>
#include <cstring>
#include <numeric>
#include <vector>

namespace inputleap {

IClipboard::EFormat MSWindowsClipboardFileListConverter::getFormat() const
{
    return IClipboard::kFileList;
}

UINT MSWindowsClipboardFileListConverter::getWin32Format() const
{
    return CF_HDROP;
}

HANDLE MSWindowsClipboardFileListConverter::fromIClipboard(const std::string& data) const
{
    std::vector<std::wstring> paths;
    size_t start = 0;
    while (start <= data.size()) {
        const size_t end = data.find('\n', start);
        std::string path = data.substr(start, end == std::string::npos ? end : end - start);
        if (!path.empty() && path.back() == '\r') {
            path.pop_back();
        }
        if (!path.empty()) {
            const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                                   path.data(), static_cast<int>(path.size()),
                                                   nullptr, 0);
            if (length <= 0) {
                return nullptr;
            }
            std::wstring wide(static_cast<size_t>(length), L'\0');
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                path.data(), static_cast<int>(path.size()),
                                wide.data(), length);
            paths.push_back(std::move(wide));
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }

    if (paths.empty()) {
        return nullptr;
    }

    const SIZE_T bytes = sizeof(DROPFILES) +
        (std::accumulate(paths.begin(), paths.end(), SIZE_T{0},
            [](SIZE_T total, const std::wstring& path) {
                return total + (path.size() + 1) * sizeof(wchar_t);
            }) + sizeof(wchar_t));
    HGLOBAL handle = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, bytes);
    if (handle == nullptr) {
        return nullptr;
    }

    auto* drop = static_cast<DROPFILES*>(GlobalLock(handle));
    if (drop == nullptr) {
        GlobalFree(handle);
        return nullptr;
    }
    drop->pFiles = sizeof(DROPFILES);
    drop->fWide = TRUE;
    auto* destination = reinterpret_cast<wchar_t*>(reinterpret_cast<char*>(drop) + drop->pFiles);
    for (const std::wstring& path : paths) {
        std::memcpy(destination, path.c_str(), (path.size() + 1) * sizeof(wchar_t));
        destination += path.size() + 1;
    }
    *destination = L'\0';
    GlobalUnlock(handle);
    return handle;
}

std::string MSWindowsClipboardFileListConverter::toIClipboard(HANDLE data) const
{
    HDROP drop = static_cast<HDROP>(data);
    const UINT count = DragQueryFileW(drop, 0xffffffff, nullptr, 0);
    std::string result;
    for (UINT index = 0; index < count; ++index) {
        const UINT length = DragQueryFileW(drop, index, nullptr, 0);
        // DragQueryFileW's buffer size includes the terminating NUL.  The
        // previous allocation had room for the path but not for that NUL,
        // which could corrupt the clipboard payload before packaging.
        std::wstring path(static_cast<size_t>(length) + 1, L'\0');
        if (DragQueryFileW(drop, index, path.data(), length + 1) != length) {
            continue;
        }
        path.resize(length);
        if (!result.empty()) {
            result.push_back('\n');
        }
        const std::string utf16(reinterpret_cast<const char*>(path.data()),
                                path.size() * sizeof(wchar_t));
        result += Unicode::UTF16ToUTF8(utf16);
    }
    return result;
}

} // namespace inputleap
