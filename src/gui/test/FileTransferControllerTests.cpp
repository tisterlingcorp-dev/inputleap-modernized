/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#include "../src/FileTransferController.h"
#include "../src/FileTransferCancellation.h"
#include "../src/FileTransferWorker.h"

#include <gtest/gtest.h>

#include <QFile>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QSignalSpy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QTest>
#include <QThread>

#include <memory>

TEST(FileTransferControllerTests, CancellationHandleOutlivesWorkerObject)
{
    FileTransferCancellation cancellation;
    auto worker = std::make_unique<FileTransferWorker>(
        QStringLiteral("127.0.0.1"), 1,
        QList<FileTransferService::TransferItem>{}, QString(), QUuid(),
        QByteArray(), false, 0, false, cancellation);
    worker.reset();

    EXPECT_NO_THROW(cancellation.cancel());
    EXPECT_TRUE(cancellation.isCancelled());
}

TEST(FileTransferControllerTests, CompletesSuccessfulTransferWithoutUiOwnership)
{
    QTemporaryDir temporaryDirectory;
    ASSERT_TRUE(temporaryDirectory.isValid());

    const QString sourcePath = temporaryDirectory.filePath("source.txt");
    QFile source(sourcePath);
    ASSERT_TRUE(source.open(QIODevice::WriteOnly));
    ASSERT_GT(source.write("controller transfer"), 0);
    source.close();

    FileTransferService receiver;
    const QUuid peerUuid = QUuid::createUuid();
    const QByteArray psk(32, 'c');
    receiver.setReceivePermissionCallback([](const QUuid& uuid) { return !uuid.isNull(); });
    receiver.setDevicePreSharedKey(peerUuid, psk);
    receiver.setReceiveDirectory(temporaryDirectory.filePath("received"));
    QString listenError;
    ASSERT_TRUE(receiver.startListening(0, &listenError)) << listenError.toStdString();

    FileTransferController controller;
    QSignalSpy startedSpy(&controller, &FileTransferController::started);
    QSignalSpy finishedSpy(&controller, &FileTransferController::finished);

    const QList<FileTransferService::TransferItem> items = {
        {sourcePath, QStringLiteral("source.txt")}
    };
    ASSERT_TRUE(controller.start("127.0.0.1", receiver.port(), items, {}, peerUuid, psk, true));
    EXPECT_TRUE(controller.isRunning());
    ASSERT_TRUE(finishedSpy.wait(10000));

    EXPECT_EQ(startedSpy.count(), 1);
    ASSERT_EQ(finishedSpy.count(), 1);
    EXPECT_TRUE(finishedSpy.at(0).at(0).toBool());
    EXPECT_FALSE(finishedSpy.at(0).at(2).toBool());
    EXPECT_FALSE(controller.isRunning());
    EXPECT_TRUE(QFile::exists(temporaryDirectory.filePath("received/source.txt")));
}

TEST(FileTransferControllerTests, RejectsASecondConcurrentStart)
{
    QTemporaryDir temporaryDirectory;
    ASSERT_TRUE(temporaryDirectory.isValid());

    const QString sourcePath = temporaryDirectory.filePath("source.txt");
    QFile source(sourcePath);
    ASSERT_TRUE(source.open(QIODevice::WriteOnly));
    ASSERT_GT(source.write("single active transfer"), 0);
    source.close();

    FileTransferService receiver;
    const QUuid peerUuid = QUuid::createUuid();
    const QByteArray psk(32, 'c');
    receiver.setReceivePermissionCallback([](const QUuid& uuid) { return !uuid.isNull(); });
    receiver.setDevicePreSharedKey(peerUuid, psk);
    receiver.setReceiveDirectory(temporaryDirectory.filePath("received"));
    QString listenError;
    ASSERT_TRUE(receiver.startListening(0, &listenError)) << listenError.toStdString();

    FileTransferController controller;
    QSignalSpy finishedSpy(&controller, &FileTransferController::finished);
    const QList<FileTransferService::TransferItem> items = {
        {sourcePath, QStringLiteral("source.txt")}
    };

    ASSERT_TRUE(controller.start("127.0.0.1", receiver.port(), items, {}, peerUuid, psk, true));
    EXPECT_FALSE(controller.start("127.0.0.1", receiver.port(), items, {}, peerUuid, psk, true));
    ASSERT_TRUE(finishedSpy.wait(10000));
}

TEST(FileTransferControllerTests, CancelInterruptsBlockedNetworkWaitPromptly)
{
    QTemporaryDir temporaryDirectory;
    ASSERT_TRUE(temporaryDirectory.isValid());
    const QString sourcePath = temporaryDirectory.filePath("source.txt");
    QFile source(sourcePath);
    ASSERT_TRUE(source.open(QIODevice::WriteOnly));
    ASSERT_GT(source.write("blocked transfer"), 0);
    source.close();

    QTcpServer blackhole;
    ASSERT_TRUE(blackhole.listen(QHostAddress::LocalHost, 0));
    FileTransferController controller;
    QSignalSpy finishedSpy(&controller, &FileTransferController::finished);
    ASSERT_TRUE(controller.start("127.0.0.1", blackhole.serverPort(),
                                 {{sourcePath, QStringLiteral("source.txt")}}, {}));
    QElapsedTimer connectionTimer;
    connectionTimer.start();
    while (!blackhole.hasPendingConnections() && connectionTimer.elapsed() < 3000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
        QThread::msleep(5);
    }
    ASSERT_TRUE(blackhole.hasPendingConnections());
    QTcpSocket* peer = blackhole.nextPendingConnection();
    ASSERT_NE(peer, nullptr);

    QElapsedTimer cancelTimer;
    cancelTimer.start();
    controller.cancel();
    const bool cancelledPromptly = finishedSpy.wait(1000);
    if (!cancelledPromptly) {
        peer->abort();
        ASSERT_TRUE(finishedSpy.wait(5000));
    }
    EXPECT_TRUE(cancelledPromptly);
    EXPECT_LT(cancelTimer.elapsed(), 1500);
    ASSERT_EQ(finishedSpy.count(), 1);
    EXPECT_TRUE(finishedSpy.at(0).at(2).toBool());
    QTest::qWait(200);
    EXPECT_FALSE(blackhole.hasPendingConnections());
    peer->deleteLater();
}

TEST(FileTransferControllerTests, DestructionCancelsAndJoinsBlockedWorker)
{
    QTemporaryDir temporaryDirectory;
    ASSERT_TRUE(temporaryDirectory.isValid());
    const QString sourcePath = temporaryDirectory.filePath("source.txt");
    QFile source(sourcePath);
    ASSERT_TRUE(source.open(QIODevice::WriteOnly));
    ASSERT_GT(source.write("destroy blocked transfer"), 0);
    source.close();

    QTcpServer blackhole;
    ASSERT_TRUE(blackhole.listen(QHostAddress::LocalHost, 0));
    auto controller = std::make_unique<FileTransferController>();
    ASSERT_TRUE(controller->start("127.0.0.1", blackhole.serverPort(),
                                  {{sourcePath, QStringLiteral("source.txt")}}, {}));
    QElapsedTimer connectionTimer;
    connectionTimer.start();
    while (!blackhole.hasPendingConnections() && connectionTimer.elapsed() < 3000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
        QThread::msleep(5);
    }
    ASSERT_TRUE(blackhole.hasPendingConnections());
    QTcpSocket* peer = blackhole.nextPendingConnection();
    ASSERT_NE(peer, nullptr);

    QElapsedTimer destructionTimer;
    destructionTimer.start();
    controller.reset();
    EXPECT_LT(destructionTimer.elapsed(), 1500);
    peer->deleteLater();
}
