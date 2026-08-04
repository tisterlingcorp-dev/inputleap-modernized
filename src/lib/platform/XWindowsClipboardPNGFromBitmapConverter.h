/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2004 Chris Schoeneman
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 */

#pragma once

#include "platform/XWindowsClipboard.h"

namespace inputleap {

//! Convert the canonical clipboard bitmap into PNG for X11 consumers.
class XWindowsClipboardPNGFromBitmapConverter :
                public IXWindowsClipboardConverter {
public:
    explicit XWindowsClipboardPNGFromBitmapConverter(Display* display);
    ~XWindowsClipboardPNGFromBitmapConverter() override;

    IClipboard::EFormat getFormat() const override;
    Atom getAtom() const override;
    int getDataSize() const override;
    std::string fromIClipboard(const std::string& data) const override;
    bool canConvertFromIClipboard(const std::string& data) const override;
    std::string toIClipboard(const std::string& data) const override;
    bool canConvertToIClipboard() const override;

    static std::string encode(const std::string& data);

private:
    Atom m_atom;
};

} // namespace inputleap
