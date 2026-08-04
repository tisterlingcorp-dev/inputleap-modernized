/*
 * InputLeap -- mouse and keyboard sharing utility
 *
 * Clipboard file-list converter for X11 text/uri-list.
 */
#pragma once

#include "platform/XWindowsClipboard.h"

namespace inputleap {

class XWindowsClipboardFileListConverter final : public IXWindowsClipboardConverter {
public:
    explicit XWindowsClipboardFileListConverter(Display* display,
                                                const char* atomName = "text/uri-list",
                                                bool gnomeFormat = false);
    IClipboard::EFormat getFormat() const override;
    Atom getAtom() const override;
    int getDataSize() const override;
    std::string fromIClipboard(const std::string& data) const override;
    std::string toIClipboard(const std::string& data) const override;

private:
    Atom m_atom;
    bool m_gnomeFormat;
};

} // namespace inputleap
