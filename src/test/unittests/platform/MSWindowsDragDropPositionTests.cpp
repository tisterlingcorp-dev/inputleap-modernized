/*
 * InputLeap -- mouse and keyboard sharing utility
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 */

#include "platform/MSWindowsDragDropPosition.h"

#include <gtest/gtest.h>

namespace inputleap {
namespace {

TEST(MSWindowsDragDropPositionTests, PreservesNegativeVirtualDesktopOrigin)
{
    EXPECT_EQ(-144, calculateDropWindowOrigin(-144, -144, 1920, 20));
}

} // namespace
} // namespace inputleap
