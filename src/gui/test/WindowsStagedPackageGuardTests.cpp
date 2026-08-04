#include "WindowsStagedPackageGuard.h"

#include <gtest/gtest.h>

#include <QFile>
#include <QTemporaryDir>

#define NOMINMAX
#include <Windows.h>

TEST(WindowsStagedPackageGuardTests,
     LockPreventsMutationAndRevalidatesTheSameFileIdentity)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("package.msi"));
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    ASSERT_EQ(file.write("immutable package"), 17);
    file.close();

    WindowsStagedPackageGuard guard;
    ASSERT_TRUE(guard.lock(path));
    EXPECT_TRUE(guard.isLocked());
    EXPECT_TRUE(guard.revalidatePath());

    QFile writer(path);
    EXPECT_FALSE(writer.open(QIODevice::WriteOnly | QIODevice::Truncate));
    EXPECT_FALSE(QFile::remove(path));
    EXPECT_TRUE(guard.revalidatePath());

    guard.release();
    EXPECT_FALSE(guard.isLocked());
    EXPECT_TRUE(QFile::remove(path));
}

TEST(WindowsStagedPackageGuardTests, RejectsFilesWithAnotherHardLink)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("package.msi"));
    const QString alias = directory.filePath(QStringLiteral("alias.msi"));
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    ASSERT_EQ(file.write("linked package"), 14);
    file.close();
    ASSERT_TRUE(CreateHardLinkW(reinterpret_cast<LPCWSTR>(alias.utf16()),
                                reinterpret_cast<LPCWSTR>(path.utf16()),
                                nullptr));

    WindowsStagedPackageGuard guard;
    EXPECT_FALSE(guard.lock(path));
    EXPECT_FALSE(guard.isLocked());
}
