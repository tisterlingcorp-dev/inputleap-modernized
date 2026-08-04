/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#include "io/filesystem.h"

#include <gtest/gtest.h>

TEST(FilesystemTests, ConvertsPathToUtf8StringUnderCpp20)
{
    const auto path = inputleap::path_from_utf8("InputLeap/arquivo.txt");
    EXPECT_EQ(inputleap::path_to_utf8(path), "InputLeap/arquivo.txt");
}
