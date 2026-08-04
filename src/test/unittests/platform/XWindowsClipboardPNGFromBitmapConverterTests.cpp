/*
 * InputLeap -- mouse and keyboard sharing utility
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 */

#include <gtest/gtest.h>
#include <png.h>

#include "platform/XWindowsClipboardPNGFromBitmapConverter.h"

#include <cstdint>
#include <string>
#include <vector>

namespace inputleap {
namespace {

void storeLittleEndian16(std::string& data, std::size_t offset, std::uint16_t value)
{
    data[offset] = static_cast<char>(value & 0xffu);
    data[offset + 1] = static_cast<char>((value >> 8u) & 0xffu);
}

void storeLittleEndian32(std::string& data, std::size_t offset, std::uint32_t value)
{
    data[offset] = static_cast<char>(value & 0xffu);
    data[offset + 1] = static_cast<char>((value >> 8u) & 0xffu);
    data[offset + 2] = static_cast<char>((value >> 16u) & 0xffu);
    data[offset + 3] = static_cast<char>((value >> 24u) & 0xffu);
}

std::vector<unsigned char> decodePngRgb(
    const std::string& png, png_uint_32& width, png_uint_32& height)
{
    png_image image{};
    image.version = PNG_IMAGE_VERSION;
    EXPECT_NE(png_image_begin_read_from_memory(&image, png.data(), png.size()), 0);
    width = image.width;
    height = image.height;
    image.format = PNG_FORMAT_RGB;
    std::vector<unsigned char> pixels(PNG_IMAGE_SIZE(image));
    EXPECT_NE(png_image_finish_read(&image, nullptr, pixels.data(), 0, nullptr), 0);
    png_image_free(&image);
    return pixels;
}

TEST(XWindowsClipboardPNGFromBitmapConverterTests, encode_validBottomUpDib_returnsOpaquePng)
{
    std::string dib(48, '\0');
    storeLittleEndian32(dib, 0, 40); // BITMAPINFOHEADER size
    storeLittleEndian32(dib, 4, 2);  // width
    storeLittleEndian32(dib, 8, 1);  // positive height: bottom-up
    storeLittleEndian16(dib, 12, 1); // planes
    storeLittleEndian16(dib, 14, 32);
    storeLittleEndian32(dib, 20, 8); // pixel bytes

    // Windows BI_RGB 32-bit pixels are BGRX; the filler byte is not alpha.
    dib[40] = 0;
    dib[41] = 0;
    dib[42] = static_cast<char>(255);
    dib[43] = 0;
    dib[44] = 0;
    dib[45] = static_cast<char>(255);
    dib[46] = 0;
    dib[47] = 0;

    const std::string png = XWindowsClipboardPNGFromBitmapConverter::encode(dib);

    ASSERT_GE(png.size(), 8u);
    EXPECT_EQ(static_cast<unsigned char>(png[0]), 0x89u);
    EXPECT_EQ(png.substr(1, 3), "PNG");

    png_image image{};
    image.version = PNG_IMAGE_VERSION;
    ASSERT_NE(png_image_begin_read_from_memory(&image, png.data(), png.size()), 0);
    EXPECT_EQ(image.width, 2u);
    EXPECT_EQ(image.height, 1u);

    image.format = PNG_FORMAT_RGB;
    std::vector<unsigned char> pixels(PNG_IMAGE_SIZE(image));
    ASSERT_NE(png_image_finish_read(&image, nullptr, pixels.data(), 0, nullptr), 0);
    ASSERT_EQ(pixels.size(), 6u);
    EXPECT_EQ(pixels[0], 255u);
    EXPECT_EQ(pixels[1], 0u);
    EXPECT_EQ(pixels[2], 0u);
    EXPECT_EQ(pixels[3], 0u);
    EXPECT_EQ(pixels[4], 255u);
    EXPECT_EQ(pixels[5], 0u);
    png_image_free(&image);
}

TEST(XWindowsClipboardPNGFromBitmapConverterTests, truncatedDibIsNotConvertible)
{
    XWindowsClipboardPNGFromBitmapConverter converter(nullptr);
    const std::string truncatedDib(39, '\0');

    EXPECT_FALSE(converter.canConvertFromIClipboard(truncatedDib));
    EXPECT_TRUE(converter.fromIClipboard(truncatedDib).empty());
}

TEST(XWindowsClipboardPNGFromBitmapConverterTests, converterIsExportOnly)
{
    XWindowsClipboardPNGFromBitmapConverter converter(nullptr);

    EXPECT_FALSE(converter.canConvertToIClipboard());
}

TEST(XWindowsClipboardPNGFromBitmapConverterTests, encode_bottomUpDibWithTwoRows_flipsRowsAndIgnoresBgrxFiller)
{
    std::string dib(48, '\0');
    storeLittleEndian32(dib, 0, 40);
    storeLittleEndian32(dib, 4, 1);
    storeLittleEndian32(dib, 8, 2);
    storeLittleEndian16(dib, 12, 1);
    storeLittleEndian16(dib, 14, 32);
    storeLittleEndian32(dib, 20, 8);

    // Bottom row is blue; top row is red. BGRX filler must not become alpha.
    dib[40] = static_cast<char>(255);
    dib[43] = static_cast<char>(17);
    dib[46] = static_cast<char>(255);
    dib[47] = static_cast<char>(231);

    png_uint_32 width = 0;
    png_uint_32 height = 0;
    const auto pixels = decodePngRgb(
        XWindowsClipboardPNGFromBitmapConverter::encode(dib), width, height);

    EXPECT_EQ(width, 1u);
    EXPECT_EQ(height, 2u);
    EXPECT_EQ(pixels, (std::vector<unsigned char>{255, 0, 0, 0, 0, 255}));
}

TEST(XWindowsClipboardPNGFromBitmapConverterTests, encode_topDown24BitDib_preservesRowsAndIgnoresPadding)
{
    std::string dib(48, '\0');
    storeLittleEndian32(dib, 0, 40);
    storeLittleEndian32(dib, 4, 1);
    storeLittleEndian32(dib, 8, static_cast<std::uint32_t>(-2));
    storeLittleEndian16(dib, 12, 1);
    storeLittleEndian16(dib, 14, 24);
    storeLittleEndian32(dib, 20, 8);

    // Top row is green, bottom row is blue; each 3-byte row has one padding byte.
    dib[41] = static_cast<char>(255);
    dib[43] = static_cast<char>(99);
    dib[44] = static_cast<char>(255);
    dib[47] = static_cast<char>(77);

    png_uint_32 width = 0;
    png_uint_32 height = 0;
    const auto pixels = decodePngRgb(
        XWindowsClipboardPNGFromBitmapConverter::encode(dib), width, height);

    EXPECT_EQ(width, 1u);
    EXPECT_EQ(height, 2u);
    EXPECT_EQ(pixels, (std::vector<unsigned char>{0, 255, 0, 0, 0, 255}));
}

TEST(XWindowsClipboardPNGFromBitmapConverterTests, malformedDibsAreNotConvertible)
{
    XWindowsClipboardPNGFromBitmapConverter converter(nullptr);
    std::string valid(48, '\0');
    storeLittleEndian32(valid, 0, 40);
    storeLittleEndian32(valid, 4, 2);
    storeLittleEndian32(valid, 8, 1);
    storeLittleEndian16(valid, 12, 1);
    storeLittleEndian16(valid, 14, 32);

    std::vector<std::string> malformed;
    malformed.emplace_back(39, '\0');
    malformed.push_back(valid.substr(0, 47));

    auto wrongHeaderSize = valid;
    storeLittleEndian32(wrongHeaderSize, 0, 12);
    malformed.push_back(wrongHeaderSize);

    auto zeroWidth = valid;
    storeLittleEndian32(zeroWidth, 4, 0);
    malformed.push_back(zeroWidth);

    auto negativeWidth = valid;
    storeLittleEndian32(negativeWidth, 4, static_cast<std::uint32_t>(-1));
    malformed.push_back(negativeWidth);

    auto zeroHeight = valid;
    storeLittleEndian32(zeroHeight, 8, 0);
    malformed.push_back(zeroHeight);

    auto minimumHeight = valid;
    storeLittleEndian32(minimumHeight, 8, 0x80000000u);
    malformed.push_back(minimumHeight);

    auto wrongPlanes = valid;
    storeLittleEndian16(wrongPlanes, 12, 2);
    malformed.push_back(wrongPlanes);

    auto unsupportedDepth = valid;
    storeLittleEndian16(unsupportedDepth, 14, 16);
    malformed.push_back(unsupportedDepth);

    auto compressed = valid;
    storeLittleEndian32(compressed, 16, 1);
    malformed.push_back(compressed);

    auto extremeWidth = valid;
    storeLittleEndian32(extremeWidth, 4, 0x7fffffffu);
    malformed.push_back(extremeWidth);

    for (const auto& dib : malformed) {
        SCOPED_TRACE(dib.size());
        EXPECT_FALSE(converter.canConvertFromIClipboard(dib));
        EXPECT_TRUE(converter.fromIClipboard(dib).empty());
    }
}

} // namespace
} // namespace inputleap
