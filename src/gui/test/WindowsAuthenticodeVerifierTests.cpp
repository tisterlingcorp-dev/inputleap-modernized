#include "WindowsAuthenticodeVerifier.h"

#include <gtest/gtest.h>

#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#define NOMINMAX
#include <Windows.h>

namespace {

QString systemExecutable(const QString& name)
{
    wchar_t directory[MAX_PATH + 1]{};
    const UINT length = GetSystemDirectoryW(directory, MAX_PATH);
    if (length == 0 || length > MAX_PATH)
        return {};
    return QDir(QString::fromWCharArray(directory)).filePath(name);
}

}

TEST(WindowsAuthenticodeVerifierTests,
     TrustedWindowsBinaryRequiresTheExactValidatedPublisherPin)
{
    const QStringList candidates{
        QStringLiteral(
            "C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"),
        systemExecutable(QStringLiteral(
            "WindowsPowerShell/v1.0/powershell.exe")),
        systemExecutable(QStringLiteral("msiexec.exe"))};
    QString path;
    WindowsAuthenticode::Verification verification;
    for (const QString& candidate : candidates) {
        if (!QFile::exists(candidate))
            continue;
        const auto inspected = WindowsAuthenticode::inspect(candidate);
        if (inspected.trusted) {
            path = candidate;
            verification = inspected;
            break;
        }
        verification = inspected;
    }
    ASSERT_FALSE(path.isEmpty())
        << "No embedded trusted fixture; last WinVerifyTrust status="
        << std::hex << verification.nativeTrustStatus;
    ASSERT_TRUE(verification.trusted)
        << "WinVerifyTrust status=" << std::hex
        << verification.nativeTrustStatus
        << ", signer bytes=" << verification.signerSha256.size();
    ASSERT_EQ(verification.signerSha256.size(), 32);
    EXPECT_TRUE(WindowsAuthenticode::verifyPinnedPublisher(
        path, verification.signerSha256));

    QByteArray wrongPin = verification.signerSha256;
    wrongPin[0] = char(uchar(wrongPin.at(0)) ^ 0x80U);
    EXPECT_FALSE(WindowsAuthenticode::verifyPinnedPublisher(path, wrongPin));
    EXPECT_FALSE(WindowsAuthenticode::verifyPinnedPublisher(path, QByteArray(20, 'x')));
}

TEST(WindowsAuthenticodeVerifierTests, UnsignedFileFailsClosed)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("unsigned.msi"));
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    ASSERT_EQ(file.write("not an Authenticode package"), 27);
    file.close();

    const auto verification = WindowsAuthenticode::inspect(path);
    EXPECT_FALSE(verification.trusted);
    EXPECT_TRUE(verification.signerSha256.isEmpty());
    EXPECT_FALSE(WindowsAuthenticode::verifyPinnedPublisher(
        path, QByteArray(32, 'x')));
}
