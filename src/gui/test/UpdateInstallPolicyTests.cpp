#include "UpdateInstallPolicy.h"

#include <gtest/gtest.h>

#include <QCryptographicHash>
#include <QFile>
#include <QTemporaryDir>

namespace {
struct PackageFixture {
    QTemporaryDir directory;
    QByteArray body = QByteArrayLiteral("synthetic-private-msi");
    QString path;
    UpdateService::Release release;

    PackageFixture()
    {
        path = directory.filePath(QStringLiteral("inputleap.msi"));
        QFile file(path);
        EXPECT_TRUE(file.open(QIODevice::WriteOnly));
        EXPECT_EQ(file.write(body), body.size());
        file.close();
        release.installable = true;
        release.packageType = UpdateService::PackageType::WindowsMsi;
        release.version = QStringLiteral("4.0.0");
        release.size = body.size();
        release.sha256 = QCryptographicHash::hash(body, QCryptographicHash::Sha256);
        release.packageUrl = QUrl(QStringLiteral("https://updates.example/inputleap.msi"));
    }

    UpdateInstallPolicy::Input allowedInput() const
    {
        return {release, QStringLiteral("3.1.0-modernized"), path,
                false, true, false, true};
    }
};
}

TEST(UpdateInstallPolicyTests, AllowsOnlyNewerVerifiedMsiAfterConfirmedStop)
{
    PackageFixture fixture;
    EXPECT_EQ(UpdateInstallPolicy::evaluate(fixture.allowedInput()),
              UpdateInstallPolicy::Decision::Allowed);

    for (const QString& version : {QStringLiteral("4.0.0"), QStringLiteral("4.0.1"),
                                   QStringLiteral("invalid")}) {
        auto input = fixture.allowedInput();
        input.currentVersion = version;
        EXPECT_EQ(UpdateInstallPolicy::evaluate(input),
                  UpdateInstallPolicy::Decision::NotANewerInstallableMsi);
    }

    auto displayOnly = fixture.allowedInput();
    displayOnly.release.installable = false;
    EXPECT_EQ(UpdateInstallPolicy::evaluate(displayOnly),
              UpdateInstallPolicy::Decision::NotANewerInstallableMsi);
}

TEST(UpdateInstallPolicyTests, AcceptsLocalBuildDescriptorsButRequiresStableRemoteVersion)
{
    PackageFixture fixture;
    for (const QString& current : {
             QStringLiteral("3.7.0-modernized"),
             QStringLiteral("3.7.0-release"),
             QStringLiteral("3.7.0-git-2026-07-22-deadbee"),
             QStringLiteral("3.7.0-unknown")}) {
        auto input = fixture.allowedInput();
        input.currentVersion = current;
        EXPECT_EQ(UpdateInstallPolicy::evaluate(input),
                  UpdateInstallPolicy::Decision::Allowed) << current.toStdString();
    }

    for (const QString& current : {
             QStringLiteral("3.7.0-'git-2026-07-22-deadbee'"),
             QStringLiteral("3.7.0-"),
             QStringLiteral("03.7.0")}) {
        auto input = fixture.allowedInput();
        input.currentVersion = current;
        EXPECT_EQ(UpdateInstallPolicy::evaluate(input),
                  UpdateInstallPolicy::Decision::NotANewerInstallableMsi)
            << current.toStdString();
    }

    auto prereleaseFeed = fixture.allowedInput();
    prereleaseFeed.release.version = QStringLiteral("4.0.0-modernized");
    EXPECT_EQ(UpdateInstallPolicy::evaluate(prereleaseFeed),
              UpdateInstallPolicy::Decision::NotANewerInstallableMsi);
}

TEST(UpdateInstallPolicyTests, BlocksEachRuntimePreconditionIndependently)
{
    PackageFixture fixture;
    auto input = fixture.allowedInput();
    input.activeTransfers = true;
    EXPECT_EQ(UpdateInstallPolicy::evaluate(input),
              UpdateInstallPolicy::Decision::ActiveTransfers);

    input = fixture.allowedInput();
    input.configurationValid = false;
    EXPECT_EQ(UpdateInstallPolicy::evaluate(input),
              UpdateInstallPolicy::Decision::InvalidConfiguration);

    input = fixture.allowedInput();
    input.stopPending = true;
    EXPECT_EQ(UpdateInstallPolicy::evaluate(input),
              UpdateInstallPolicy::Decision::StopPending);

    input = fixture.allowedInput();
    input.stopConfirmed = false;
    EXPECT_EQ(UpdateInstallPolicy::evaluate(input),
              UpdateInstallPolicy::Decision::StopNotConfirmed);
}

TEST(UpdateInstallPolicyTests, RejectsAlteredWrongSizeWrongExtensionAndRelativePackage)
{
    PackageFixture fixture;
    ASSERT_TRUE(UpdateInstallPolicy::verifyStagedPackage(fixture.path, fixture.release));

    QFile altered(fixture.path);
    ASSERT_TRUE(altered.open(QIODevice::Append));
    ASSERT_EQ(altered.write("x"), 1);
    altered.close();
    EXPECT_FALSE(UpdateInstallPolicy::verifyStagedPackage(fixture.path, fixture.release));

    PackageFixture wrongExtension;
    const QString renamed = wrongExtension.directory.filePath(QStringLiteral("inputleap.exe"));
    ASSERT_TRUE(QFile::rename(wrongExtension.path, renamed));
    EXPECT_FALSE(UpdateInstallPolicy::verifyStagedPackage(renamed, wrongExtension.release));
    EXPECT_FALSE(UpdateInstallPolicy::verifyStagedPackage(
        QStringLiteral("relative.msi"), wrongExtension.release));
}

TEST(UpdateInstallPolicyTests, RejectsSymlinkWhenPlatformCanCreateIt)
{
    PackageFixture fixture;
    const QString link = fixture.directory.filePath(QStringLiteral("linked.msi"));
    if (!QFile::link(fixture.path, link))
        GTEST_SKIP() << "platform did not permit creating the link fixture";
    EXPECT_FALSE(UpdateInstallPolicy::verifyStagedPackage(link, fixture.release));
}

TEST(UpdateInstallPolicyTests, MapsWindowsInstallerTransactionResultsHonestly)
{
    using Outcome = UpdateInstallPolicy::MsiOutcome;
    EXPECT_EQ(UpdateInstallPolicy::classifyMsiExitCode(0), Outcome::Success);
    EXPECT_EQ(UpdateInstallPolicy::classifyMsiExitCode(3010),
              Outcome::SuccessRestartRequired);
    EXPECT_EQ(UpdateInstallPolicy::classifyMsiExitCode(1602), Outcome::Cancelled);
    EXPECT_EQ(UpdateInstallPolicy::classifyMsiExitCode(1603),
              Outcome::Failed);
    EXPECT_EQ(UpdateInstallPolicy::classifyMsiExitCode(42),
              Outcome::Failed);
    EXPECT_TRUE(UpdateInstallPolicy::transactionCompleted(Outcome::Success));
    EXPECT_TRUE(UpdateInstallPolicy::transactionCompleted(Outcome::SuccessRestartRequired));
    EXPECT_FALSE(UpdateInstallPolicy::transactionCompleted(Outcome::Cancelled));
    EXPECT_FALSE(UpdateInstallPolicy::transactionCompleted(Outcome::Failed));
#if defined(Q_OS_WIN)
    EXPECT_TRUE(UpdateInstallPolicy::platformSupportsInstallation());
#else
    EXPECT_FALSE(UpdateInstallPolicy::platformSupportsInstallation());
#endif
}
