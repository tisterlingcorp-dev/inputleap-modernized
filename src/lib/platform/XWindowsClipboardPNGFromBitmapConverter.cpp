/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2004 Chris Schoeneman
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 */

#include "platform/XWindowsClipboardPNGFromBitmapConverter.h"

#include "base/BitUtilities.h"

#include <png.h>

#include <cstdint>
#include <limits>
#include <vector>

namespace inputleap {

namespace {

struct DibInfo {
    std::int32_t width;
    std::int32_t signedHeight;
    std::uint16_t bitCount;
    std::uint64_t height;
    std::uint64_t rowStride;
    std::uint64_t rgbSize;
};

bool parseDib(const std::string& data, DibInfo& info)
{
    constexpr std::size_t headerSize = 40;
    if (data.size() < headerSize) {
        return false;
    }

    const auto* header = reinterpret_cast<const std::uint8_t*>(data.data());
    const std::uint32_t dibHeaderSize = load_little_endian_u32(header);
    info.width = load_little_endian_s32(header + 4);
    info.signedHeight = load_little_endian_s32(header + 8);
    const std::uint16_t planes = load_little_endian_u16(header + 12);
    info.bitCount = load_little_endian_u16(header + 14);
    const std::uint32_t compression = load_little_endian_u32(header + 16);

    if (dibHeaderSize != headerSize || info.width <= 0 || info.signedHeight == 0 ||
        info.signedHeight == std::numeric_limits<std::int32_t>::min() ||
        planes != 1 || compression != 0 || (info.bitCount != 24 && info.bitCount != 32)) {
        return false;
    }

    info.height = info.signedHeight < 0
        ? static_cast<std::uint64_t>(-static_cast<std::int64_t>(info.signedHeight))
        : static_cast<std::uint64_t>(info.signedHeight);
    info.rowStride =
        ((static_cast<std::uint64_t>(info.width) * info.bitCount + 31u) / 32u) * 4u;
    const std::uint64_t pixelBytes = info.rowStride * info.height;
    if (pixelBytes > data.size() - headerSize) {
        return false;
    }

    info.rgbSize = static_cast<std::uint64_t>(info.width) * info.height * 3u;
    return info.rgbSize <= std::numeric_limits<std::size_t>::max();
}

} // namespace

XWindowsClipboardPNGFromBitmapConverter::XWindowsClipboardPNGFromBitmapConverter(
                Display* display) :
    m_atom(display == nullptr ? None : XInternAtom(display, "image/png", False))
{
}

XWindowsClipboardPNGFromBitmapConverter::~XWindowsClipboardPNGFromBitmapConverter() = default;

IClipboard::EFormat XWindowsClipboardPNGFromBitmapConverter::getFormat() const
{
    return IClipboard::kBitmap;
}

Atom XWindowsClipboardPNGFromBitmapConverter::getAtom() const
{
    return m_atom;
}

int XWindowsClipboardPNGFromBitmapConverter::getDataSize() const
{
    return 8;
}

std::string XWindowsClipboardPNGFromBitmapConverter::fromIClipboard(const std::string& data) const
{
    return encode(data);
}

bool XWindowsClipboardPNGFromBitmapConverter::canConvertFromIClipboard(const std::string& data) const
{
    DibInfo info{};
    return parseDib(data, info);
}

std::string XWindowsClipboardPNGFromBitmapConverter::toIClipboard(const std::string&) const
{
    // Native PNG input is handled by XWindowsClipboardPNGConverter.
    return {};
}

bool XWindowsClipboardPNGFromBitmapConverter::canConvertToIClipboard() const
{
    return false;
}

std::string XWindowsClipboardPNGFromBitmapConverter::encode(const std::string& data)
{
    DibInfo info{};
    if (!parseDib(data, info)) {
        return {};
    }

    constexpr std::size_t headerSize = 40;
    const auto* header = reinterpret_cast<const std::uint8_t*>(data.data());
    std::vector<std::uint8_t> rgb(static_cast<std::size_t>(info.rgbSize));
    const auto* pixels = header + headerSize;
    const std::size_t sourcePixelSize = info.bitCount / 8u;
    for (std::uint64_t y = 0; y < info.height; ++y) {
        const std::uint64_t sourceY = info.signedHeight > 0 ? info.height - 1u - y : y;
        const auto* sourceRow = pixels + sourceY * info.rowStride;
        auto* destinationRow = rgb.data() + y * static_cast<std::uint64_t>(info.width) * 3u;
        for (std::int32_t x = 0; x < info.width; ++x) {
            const auto* source = sourceRow + static_cast<std::size_t>(x) * sourcePixelSize;
            auto* destination = destinationRow + static_cast<std::size_t>(x) * 3u;
            destination[0] = source[2];
            destination[1] = source[1];
            destination[2] = source[0];
        }
    }

    png_image image{};
    image.version = PNG_IMAGE_VERSION;
    image.width = static_cast<png_uint_32>(info.width);
    image.height = static_cast<png_uint_32>(info.height);
    image.format = PNG_FORMAT_RGB;

    png_alloc_size_t outputSize = 0;
    if (!png_image_write_to_memory(&image, nullptr, &outputSize, 0, rgb.data(), 0, nullptr)) {
        png_image_free(&image);
        return {};
    }

    std::string output(static_cast<std::size_t>(outputSize), '\0');
    if (!png_image_write_to_memory(
            &image, output.data(), &outputSize, 0, rgb.data(), 0, nullptr)) {
        png_image_free(&image);
        return {};
    }

    png_image_free(&image);
    output.resize(static_cast<std::size_t>(outputSize));
    return output;
}

} // namespace inputleap
