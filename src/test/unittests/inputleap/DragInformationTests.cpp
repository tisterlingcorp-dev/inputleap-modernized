#include "inputleap/DragInformation.h"
#include "io/filesystem.h"

#include <gtest/gtest.h>

#include <fstream>

namespace inputleap {

namespace {

void appendU32(std::string& output, std::uint32_t value)
{
    output.push_back(static_cast<char>((value >> 24) & 0xff));
    output.push_back(static_cast<char>((value >> 16) & 0xff));
    output.push_back(static_cast<char>((value >> 8) & 0xff));
    output.push_back(static_cast<char>(value & 0xff));
}

std::string packageWithName(const std::string& name)
{
    std::string package("ILFILE1\0", 8);
    appendU32(package, 1);
    appendU32(package, static_cast<std::uint32_t>(name.size()));
    package.append(8, '\0'); // empty file content
    package += name;
    return package;
}

} // namespace

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

TEST(DragInformationTests, unpackFilePackage_doesNotPublishMalformedPackage)
{
    const fs::path root = fs::temp_directory_path() / "inputleap-drag-malformed-test";
    const fs::path source = root / "source.txt";
    const fs::path destination = root / "destination";
    fs::remove_all(root);
    fs::create_directories(destination);
    {
        std::ofstream stream(source, std::ios::binary);
        stream << "complete file";
    }

    std::string package;
    ASSERT_TRUE(DragInformation::packageFileList(path_to_utf8(source), package));
    package.push_back('!'); // trailing bytes invalidate the package after its file entry

    std::string fileList;
    EXPECT_FALSE(DragInformation::unpackFilePackage(package, path_to_utf8(destination), fileList));
    EXPECT_FALSE(fs::exists(destination / "source.txt"));
    EXPECT_EQ(fs::directory_iterator(destination), fs::directory_iterator());
    fs::remove_all(root);
}

TEST(DragInformationTests, unpackFilePackage_doesNotOverwriteExistingRoot)
{
    const fs::path root = fs::temp_directory_path() / "inputleap-drag-collision-test";
    const fs::path source = root / "source.txt";
    const fs::path destination = root / "destination";
    fs::remove_all(root);
    fs::create_directories(destination);
    {
        std::ofstream stream(source, std::ios::binary);
        stream << "incoming";
    }
    {
        std::ofstream stream(destination / "source.txt", std::ios::binary);
        stream << "keep existing";
    }

    std::string package;
    ASSERT_TRUE(DragInformation::packageFileList(path_to_utf8(source), package));

    std::string fileList;
    EXPECT_FALSE(DragInformation::unpackFilePackage(package, path_to_utf8(destination), fileList));
    std::ifstream existing(destination / "source.txt", std::ios::binary);
    const std::string content((std::istreambuf_iterator<char>(existing)),
                              std::istreambuf_iterator<char>());
    EXPECT_EQ("keep existing", content);
    fs::remove_all(root);
}

TEST(DragInformationTests, unpackFilePackage_rejectsUnsafeWindowsNames)
{
    const fs::path destination = fs::temp_directory_path() / "inputleap-drag-unsafe-name-test";
    fs::remove_all(destination);
    fs::create_directories(destination);

    for (const char* name : {"NUL.txt", "NUL .txt", "CONOUT$", "COM1.log", "bad?.txt", "trailing.", "trailing "}) {
        std::string fileList;
        EXPECT_FALSE(DragInformation::unpackFilePackage(packageWithName(name),
                                                        path_to_utf8(destination), fileList))
            << "accepted unsafe file name: " << name;
    }
    EXPECT_EQ(fs::directory_iterator(destination), fs::directory_iterator());
    fs::remove_all(destination);
}

TEST(DragInformationTests, unpackFilePackage_rejectsCaseInsensitiveDuplicateNames)
{
    std::string package = packageWithName("Report.txt");
    const std::string duplicate = packageWithName("report.txt");
    package.append(duplicate.data() + 8, duplicate.size() - 8);
    package[8] = 0;
    package[9] = 0;
    package[10] = 0;
    package[11] = 2;

    const fs::path destination = fs::temp_directory_path() / "inputleap-drag-duplicate-test";
    fs::remove_all(destination);
    fs::create_directories(destination);

    std::string fileList;
    EXPECT_FALSE(DragInformation::unpackFilePackage(package, path_to_utf8(destination), fileList));
    EXPECT_EQ(fs::directory_iterator(destination), fs::directory_iterator());
    fs::remove_all(destination);
}

} // namespace inputleap
