#include "inputleap/DragInformation.h"
#include "io/filesystem.h"

#include <gtest/gtest.h>

#include <fstream>

namespace inputleap {

TEST(DragInformationTests, packageAndUnpackFileList_roundTripsContent)
{
    const fs::path root = fs::temp_directory_path() / "inputleap-drag-information-test";
    const fs::path source = root / "source.txt";
    const fs::path destination = root / "destination";
    fs::remove_all(root);
    fs::create_directories(destination);

    {
        std::ofstream stream(source.string(), std::ios::binary);
        stream << "InputLeap transfer test\n";
    }

    std::string package;
    ASSERT_TRUE(DragInformation::packageFileList(path_to_utf8(source), package));
    ASSERT_TRUE(DragInformation::isFilePackage(package));

    std::string fileList;
    ASSERT_TRUE(DragInformation::unpackFilePackage(package, path_to_utf8(destination), fileList));
    EXPECT_EQ(path_to_utf8(destination / "source.txt"), fileList);

    {
        std::ifstream result(destination / "source.txt", std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(result)), std::istreambuf_iterator<char>());
        EXPECT_EQ("InputLeap transfer test\n", content);
    }

    fs::remove_all(root);
}

TEST(DragInformationTests, packageAndUnpackDirectory_returnsDirectoryRoot)
{
    const fs::path root = fs::temp_directory_path() / "inputleap-drag-directory-test";
    const fs::path source = root / "source-folder";
    const fs::path nested = source / "nested";
    const fs::path destination = root / "destination";
    fs::remove_all(root);
    fs::create_directories(nested);
    fs::create_directories(destination);

    {
        std::ofstream stream(nested / "content.txt", std::ios::binary);
        stream << "nested content\n";
    }

    std::string package;
    ASSERT_TRUE(DragInformation::packageFileList(path_to_utf8(source), package));
    EXPECT_NE(std::string::npos, package.find("source-folder/nested/content.txt"));

    std::string fileList;
    ASSERT_TRUE(DragInformation::unpackFilePackage(package, path_to_utf8(destination), fileList));
    EXPECT_EQ(path_to_utf8(destination / "source-folder"), fileList);

    {
        std::ifstream result(destination / "source-folder" / "nested" / "content.txt", std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(result)), std::istreambuf_iterator<char>());
        EXPECT_EQ("nested content\n", content);
    }

    fs::remove_all(root);
}

TEST(DragInformationTests, unpackFilePackage_rejectsPathTraversal)
{
    std::string package("ILFILE1\0", 8);
    package.push_back('\0');
    package.push_back('\0');
    package.push_back('\0');
    package.push_back('\1');
    package.push_back('\0');
    package.push_back('\0');
    package.push_back('\0');
    package.push_back('\3');
    package.push_back('\0');
    package.push_back('\0');
    package.push_back('\0');
    package.push_back('\0');
    package.push_back('\0');
    package.push_back('\0');
    package.push_back('\0');
    package.push_back('\0');
    package += "../x";

    std::string fileList;
    EXPECT_FALSE(DragInformation::unpackFilePackage(package, ".", fileList));
}

} // namespace inputleap
