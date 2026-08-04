/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#include "../src/FileTransferService.h"

#include <gtest/gtest.h>

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QTemporaryDir>
#include <QThread>

#include <atomic>
#include <thread>

namespace
{
bool waitFor(const std::atomic_bool& complete, int timeoutMs)
{
    QElapsedTimer timer;
    timer.start();
    while (!complete.load() && timer.elapsed() < timeoutMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
        QThread::msleep(5);
    }
    return complete.load();
}
}

TEST(FileTransferPolicyTests, BlocksDangerousFilesFromAutomaticOpening)
{
    EXPECT_FALSE(FileTransferService::isSafeToOpenAutomatically("installer.exe"));
    EXPECT_FALSE(FileTransferService::isSafeToOpenAutomatically("installer.MSI"));
    EXPECT_FALSE(FileTransferService::isSafeToOpenAutomatically("script.bat"));
    EXPECT_FALSE(FileTransferService::isSafeToOpenAutomatically("script.cmd"));
    EXPECT_FALSE(FileTransferService::isSafeToOpenAutomatically("script.ps1"));
    EXPECT_FALSE(FileTransferService::isSafeToOpenAutomatically("script.vbs"));
    EXPECT_FALSE(FileTransferService::isSafeToOpenAutomatically("script.js"));
    EXPECT_FALSE(FileTransferService::isSafeToOpenAutomatically("shortcut.lnk"));
}

TEST(FileTransferPolicyTests, AllowsOrdinaryDocumentsAndMediaToOpenAutomatically)
{
    EXPECT_TRUE(FileTransferService::isSafeToOpenAutomatically("photo.png"));
    EXPECT_TRUE(FileTransferService::isSafeToOpenAutomatically("document.pdf"));
    EXPECT_TRUE(FileTransferService::isSafeToOpenAutomatically("notes.txt"));
    EXPECT_TRUE(FileTransferService::isSafeToOpenAutomatically("archive.zip"));
}

TEST(FileTransferPairingTests, DerivesTheSameKeyForEquivalentPairingCodes)
{
    EXPECT_EQ(FileTransferService::pairingKeyForCode(" private-lan-code "),
              FileTransferService::pairingKeyForCode("private-lan-code"));
    EXPECT_FALSE(FileTransferService::pairingKeyForCode("private-lan-code").isEmpty());
    EXPECT_TRUE(FileTransferService::pairingKeyForCode("   ").isEmpty());
}

TEST(FileTransferPairingTests, UsesOnlyPskCiphersThatDoNotRequireDiffieHellmanParameters)
{
    const QStringList cipherNames = FileTransferService::tlsPskCipherNames();

    ASSERT_FALSE(cipherNames.isEmpty());
    for (const QString& cipherName : cipherNames) {
        EXPECT_TRUE(cipherName.startsWith("PSK-")) << cipherName.toStdString();
        EXPECT_FALSE(cipherName.contains("DHE")) << cipherName.toStdString();
        EXPECT_FALSE(cipherName.contains("ECDHE")) << cipherName.toStdString();
        EXPECT_FALSE(cipherName.contains("RSA")) << cipherName.toStdString();
    }
}

TEST(FileTransferPairingTests, TransfersOverTlsPskWhenBothPeersUseTheSameCode)
{
    QTemporaryDir temporaryDirectory;
    ASSERT_TRUE(temporaryDirectory.isValid());

    const QString sourcePath = temporaryDirectory.filePath("source.txt");
    QFile source(sourcePath);
    ASSERT_TRUE(source.open(QIODevice::WriteOnly));
    ASSERT_GT(source.write("TLS-PSK protected file transfer"), 0);
    source.close();

    FileTransferService receiver;
    const QUuid peerUuid = QUuid::createUuid();
    const QByteArray psk(32, 't');
    receiver.setReceivePermissionCallback([](const QUuid& uuid) { return !uuid.isNull(); });
    receiver.setDevicePreSharedKey(peerUuid, psk);
    receiver.setReceiveDirectory(temporaryDirectory.filePath("received"));
    QString listenError;
    ASSERT_TRUE(receiver.startListening(0, &listenError)) << listenError.toStdString();

    std::atomic_bool completed = false;
    bool sent = false;
    QString sendError;
    std::thread sender([&]() {
        sent = FileTransferService::sendFiles("127.0.0.1", receiver.port(), {sourcePath}, &sendError, {}, {},
                                              {}, peerUuid, psk, true);
        completed.store(true);
    });

    EXPECT_TRUE(waitFor(completed, 10000));
    sender.join();
    EXPECT_TRUE(sent) << sendError.toStdString();
    EXPECT_TRUE(QFile::exists(temporaryDirectory.filePath("received/source.txt")));
}

TEST(FileTransferPairingTests, RejectsTransfersWithAnIncorrectPairingCode)
{
    QTemporaryDir temporaryDirectory;
    ASSERT_TRUE(temporaryDirectory.isValid());

    const QString sourcePath = temporaryDirectory.filePath("source.txt");
    QFile source(sourcePath);
    ASSERT_TRUE(source.open(QIODevice::WriteOnly));
    ASSERT_GT(source.write("must not be received"), 0);
    source.close();

    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid& uuid) { return !uuid.isNull(); });
    receiver.setReceiveDirectory(temporaryDirectory.filePath("received"));
    receiver.setPairingCode("receiver-code");
    QString listenError;
    ASSERT_TRUE(receiver.startListening(0, &listenError)) << listenError.toStdString();

    std::atomic_bool completed = false;
    bool sent = true;
    QString sendError;
    std::thread sender([&]() {
        sent = FileTransferService::sendFiles("127.0.0.1", receiver.port(), {sourcePath}, &sendError, {}, {},
                                              "incorrect-code");
        completed.store(true);
    });

    EXPECT_TRUE(waitFor(completed, 10000));
    sender.join();
    EXPECT_FALSE(sent);
    EXPECT_FALSE(QFile::exists(temporaryDirectory.filePath("received/source.txt")));
}

namespace
{
bool sendWithDeviceKey(FileTransferService& receiver, const QString& sourcePath,
                       const QUuid& senderUuid, const QByteArray& key, QString* error)
{
    std::atomic_bool completed = false;
    bool sent = false;
    std::thread sender([&] {
        sent = FileTransferService::sendFiles("127.0.0.1", receiver.port(), {sourcePath}, error,
                                              {}, {}, {}, senderUuid, key, true);
        completed.store(true);
    });
    const bool timely = waitFor(completed, 10000);
    sender.join();
    return timely && sent;
}
}

TEST(FileTransferPairingTests, SelectsDeviceKeyStrictlyByCanonicalSenderIdentity)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString sourcePath = directory.filePath("device-key.txt");
    QFile source(sourcePath);
    ASSERT_TRUE(source.open(QIODevice::WriteOnly));
    ASSERT_GT(source.write("device-bound TLS PSK"), 0);
    source.close();
    const QUuid senderA("{aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}");
    const QUuid senderB("{bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb}");
    const QByteArray keyA(32, 'a'), keyB(32, 'b');
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid& uuid) { return !uuid.isNull(); });
    receiver.setReceiveDirectory(directory.filePath("received"));
    receiver.setDevicePreSharedKey(senderA, keyA);
    receiver.setDevicePreSharedKey(senderB, keyB);
    ASSERT_TRUE(receiver.startListening(0));
    QString error;
    EXPECT_TRUE(sendWithDeviceKey(receiver, sourcePath, senderA, keyA, &error)) << error.toStdString();
    QElapsedTimer publishTimer; publishTimer.start();
    const QString receivedPath=directory.filePath("received/device-key.txt");
    while(!QFile::exists(receivedPath)&&publishTimer.elapsed()<3000){QCoreApplication::processEvents(QEventLoop::AllEvents,20);QThread::msleep(5);}
    ASSERT_TRUE(QFile::exists(receivedPath));
    bool removed=false; QElapsedTimer removeTimer; removeTimer.start();
    while(!removed&&removeTimer.elapsed()<3000){removed=QFile::remove(receivedPath);if(!removed){QCoreApplication::processEvents(QEventLoop::AllEvents,20);QThread::msleep(5);}}
    ASSERT_TRUE(removed);
    error.clear();
    EXPECT_FALSE(sendWithDeviceKey(receiver, sourcePath, senderA, keyB, &error));
    EXPECT_FALSE(QFile::exists(directory.filePath("received/device-key.txt")));
    error.clear();
    EXPECT_FALSE(sendWithDeviceKey(receiver, sourcePath, senderB, keyA, &error));
}
