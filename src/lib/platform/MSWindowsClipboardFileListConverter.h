/*
 * InputLeap -- mouse and keyboard sharing utility
 *
 * Clipboard file-list converter for Windows CF_HDROP.
 */
#pragma once

#include "platform/MSWindowsClipboard.h"

namespace inputleap {

class MSWindowsClipboardFileListConverter final : public IMSWindowsClipboardConverter {
public:
    IClipboard::EFormat getFormat() const override;
    UINT getWin32Format() const override;
    HANDLE fromIClipboard(const std::string& data) const override;
    std::string toIClipboard(HANDLE data) const override;
};

} // namespace inputleap
