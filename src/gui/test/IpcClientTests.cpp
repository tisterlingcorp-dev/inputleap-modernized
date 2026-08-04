#include "IpcClient.h"
#include "Ipc.h"

#include <QHostAddress>
#include <QElapsedTimer>
#include <QPointer>
#include <QTcpServer>
#include <QTcpSocket>
#include <QtEndian>
#include <QtTest>

namespace {
QByteArray stopNonce(const QByteArray& wire)
{
    const qsizetype offset = wire.startsWith(QByteArrayLiteral("ISTP")) ? 0 : 5;
    if (wire.size() < offset + 8 ||
        wire.mid(offset, 4) != QByteArrayLiteral("ISTP")) return {};
    const auto length = qFromBigEndian<quint32>(
        reinterpret_cast<const uchar*>(wire.constData() + offset + 4));
    if (length != 16 || wire.size() < offset + 8 + static_cast<int>(length)) return {};
    return wire.mid(offset + 8, static_cast<int>(length));
}

QByteArray startNonce(const QByteArray& wire)
{
    const qsizetype offset = wire.startsWith(QByteArrayLiteral("ISTR")) ? 0 : 5;
    if (wire.size() < offset + 8 ||
        wire.mid(offset, 4) != QByteArrayLiteral("ISTR")) return {};
    const auto length = qFromBigEndian<quint32>(
        reinterpret_cast<const uchar*>(wire.constData() + offset + 4));
    if (length != 16 || wire.size() < offset + 8 + static_cast<int>(length)) return {};
    return wire.mid(offset + 8, static_cast<int>(length));
}

QByteArray acknowledgement(const QByteArray& nonce)
{
    QByteArray frame = QByteArrayLiteral("IACK");
    const quint32 length = static_cast<quint32>(nonce.size());
    frame.append(char((length >> 24) & 0xff));
    frame.append(char((length >> 16) & 0xff));
    frame.append(char((length >> 8) & 0xff));
    frame.append(char(length & 0xff));
    frame.append(nonce);
    return frame;
}

QByteArray logMessage(const QByteArray& text)
{
    QByteArray frame = QByteArrayLiteral("ILOG");
    const quint32 length = static_cast<quint32>(text.size());
    frame.append(char((length >> 24) & 0xff));
    frame.append(char((length >> 16) & 0xff));
    frame.append(char((length >> 8) & 0xff));
    frame.append(char(length & 0xff));
    frame.append(text);
    return frame;
}

QByteArray stringField(const QByteArray& text)
{
    QByteArray field;
    const quint32 length = static_cast<quint32>(text.size());
    field.append(char((length >> 24) & 0xff));
    field.append(char((length >> 16) & 0xff));
    field.append(char((length >> 8) & 0xff));
    field.append(char(length & 0xff));
    field.append(text);
    return field;
}

QByteArray stateMessage()
{
    return QByteArrayLiteral("ISTS")
        + char(static_cast<quint8>(IpcConnectionState::Connected))
        + char(static_cast<quint8>(IpcConnectionRole::ClientPeer))
        + char(static_cast<quint8>(IpcIdentityPresence::Known))
        + stringField(QByteArrayLiteral("peer-a"))
        + stringField(QByteArrayLiteral("connected"));
}
}

class IpcClientTests : public QObject
{
    Q_OBJECT

private slots:
    void synchronousStopWaitsForAppliedAcknowledgement()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));
        QPointer<QTcpSocket> peer;
        connect(&server, &QTcpServer::newConnection, &server, [&] {
            peer = server.nextPendingConnection();
            QTimer::singleShot(1200, peer, [peer] {
                if (!peer) return;
                const QByteArray nonce = stopNonce(peer->readAll());
                if (!nonce.isEmpty()) peer->write(acknowledgement(nonce));
            });
        });

        IpcClient client(server.serverPort());
        QElapsedTimer elapsed;
        elapsed.start();
        QVERIFY(client.requestServiceStopAndWait(ElevateNever, 3000));
        QVERIFY(elapsed.elapsed() >= 1000);
        QVERIFY(peer);
    }

    void stopWaitsForDaemonAcknowledgementBeforeDisconnecting()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy applied(&client, &IpcClient::commandApplied);
        client.requestServiceStopAndDisconnect(ElevateNever);

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> peer(server.nextPendingConnection());
        QVERIFY(peer);
        QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= 29, 3000);
        const QByteArray nonce = stopNonce(peer->readAll());
        QCOMPARE(nonce.size(), 16);
        QTest::qWait(1200);
        QCOMPARE(peer->state(), QAbstractSocket::ConnectedState);
        QCOMPARE(applied.count(), 0);

        const QByteArray wrongNonce(16, 'x');
        QCOMPARE(peer->write(acknowledgement(wrongNonce)), qint64(24));
        QVERIFY(peer->waitForBytesWritten(1000));
        QTest::qWait(100);
        QCOMPARE(applied.count(), 0);
        QCOMPARE(peer->state(), QAbstractSocket::ConnectedState);

        QCOMPARE(peer->write(acknowledgement(nonce)), qint64(24));
        QVERIFY(peer->waitForBytesWritten(1000));
        QTRY_COMPARE_WITH_TIMEOUT(applied.count(), 1, 3000);
        QTRY_COMPARE_WITH_TIMEOUT(peer->state(), QAbstractSocket::UnconnectedState, 3000);
    }

    void repeatedStopRequestKeepsFirstInFlightNonce()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy applied(&client, &IpcClient::commandApplied);
        client.requestServiceStopAndDisconnect(ElevateNever);

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> peer(server.nextPendingConnection());
        QVERIFY(peer);
        QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= 29, 3000);
        const QByteArray firstNonce = stopNonce(peer->readAll());
        QCOMPARE(firstNonce.size(), 16);

        client.requestServiceStopAndDisconnect(ElevateNever);
        QTest::qWait(100);
        QCOMPARE(peer->bytesAvailable(), qint64(0));

        QCOMPARE(peer->write(acknowledgement(firstNonce)), qint64(24));
        QVERIFY(peer->waitForBytesWritten(1000));
        QTRY_COMPARE_WITH_TIMEOUT(applied.count(), 1, 3000);
        QTRY_COMPARE_WITH_TIMEOUT(peer->state(), QAbstractSocket::UnconnectedState, 3000);
    }

    void timedOutRepeatedWaitKeepsFirstStopInFlight()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy applied(&client, &IpcClient::commandApplied);
        client.requestServiceStopAndDisconnect(ElevateNever);

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> peer(server.nextPendingConnection());
        QVERIFY(peer);
        QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= 29, 3000);
        const QByteArray firstNonce = stopNonce(peer->readAll());
        QCOMPARE(firstNonce.size(), 16);

        QVERIFY(!client.requestServiceStopAndWait(ElevateNever, 50));
        QCOMPARE(peer->state(), QAbstractSocket::ConnectedState);
        QCOMPARE(peer->bytesAvailable(), qint64(0));
        QCOMPARE(applied.count(), 0);

        QCOMPARE(peer->write(acknowledgement(firstNonce)), qint64(24));
        QVERIFY(peer->waitForBytesWritten(1000));
        QTRY_COMPARE_WITH_TIMEOUT(applied.count(), 1, 3000);
        QTRY_COMPARE_WITH_TIMEOUT(peer->state(), QAbstractSocket::UnconnectedState, 3000);
    }

    void stopSuppressesLogFramesUntilAppliedAcknowledgement()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy logs(&client, &IpcClient::readLogLine);
        QSignalSpy applied(&client, &IpcClient::commandApplied);
        client.requestServiceStopAndDisconnect(ElevateNever);

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> peer(server.nextPendingConnection());
        QVERIFY(peer);
        QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= 29, 3000);
        const QByteArray nonce = stopNonce(peer->readAll());
        QCOMPARE(nonce.size(), 16);

        QCOMPARE(peer->write(logMessage("accepted client connection from 192.0.2.44")), qint64(50));
        QVERIFY(peer->waitForBytesWritten(1000));
        QTest::qWait(100);
        QCOMPARE(logs.count(), 0);
        QCOMPARE(applied.count(), 0);

        QCOMPARE(peer->write(acknowledgement(nonce)), qint64(24));
        QVERIFY(peer->waitForBytesWritten(1000));
        QTRY_COMPARE_WITH_TIMEOUT(applied.count(), 1, 3000);
    }

    void stopSuppressesStateFramesUntilAppliedAcknowledgement()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy states(&client, &IpcClient::readConnectionState);
        QSignalSpy applied(&client, &IpcClient::commandApplied);
        client.requestServiceStopAndDisconnect(ElevateNever);

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> peer(server.nextPendingConnection());
        QVERIFY(peer);
        QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= 29, 3000);
        const QByteArray nonce = stopNonce(peer->readAll());
        QCOMPARE(nonce.size(), 16);

        const QByteArray state = stateMessage();
        QCOMPARE(peer->write(state), qint64(state.size()));
        QVERIFY(peer->waitForBytesWritten(1000));
        QTest::qWait(100);
        QCOMPARE(states.count(), 0);
        QCOMPARE(applied.count(), 0);

        QCOMPARE(peer->write(acknowledgement(nonce)), qint64(24));
        QVERIFY(peer->waitForBytesWritten(1000));
        QTRY_COMPARE_WITH_TIMEOUT(applied.count(), 1, 3000);
    }

    void coalescedAcknowledgementSuppressesTrailingOldTransportFrames()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy logs(&client, &IpcClient::readLogLine);
        QSignalSpy states(&client, &IpcClient::readConnectionState);
        QSignalSpy applied(&client, &IpcClient::commandApplied);
        client.requestServiceStopAndDisconnect(ElevateNever);

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> peer(server.nextPendingConnection());
        QVERIFY(peer);
        QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= 29, 3000);
        const QByteArray nonce = stopNonce(peer->readAll());
        QCOMPARE(nonce.size(), 16);

        const QByteArray frames = acknowledgement(nonce)
            + logMessage("stale old-transport log") + stateMessage();
        QCOMPARE(peer->write(frames), qint64(frames.size()));
        QVERIFY(peer->waitForBytesWritten(1000));
        QTRY_COMPARE_WITH_TIMEOUT(applied.count(), 1, 3000);
        QCOMPARE(logs.count(), 0);
        QCOMPARE(states.count(), 0);
        QTRY_COMPARE_WITH_TIMEOUT(peer->state(), QAbstractSocket::UnconnectedState, 3000);
    }

    void stopDisconnectsOldTransportBeforePublishingAppliedAcknowledgement()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy applied(&client, &IpcClient::commandApplied);
        connect(&client, &IpcClient::commandApplied, &client, [&client] {
            client.connectToHost();
        });
        client.requestServiceStopAndDisconnect(ElevateNever);

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> oldPeer(server.nextPendingConnection());
        QVERIFY(oldPeer);
        QTRY_VERIFY_WITH_TIMEOUT(oldPeer->bytesAvailable() >= 29, 3000);
        const QByteArray nonce = stopNonce(oldPeer->readAll());
        QCOMPARE(nonce.size(), 16);

        QCOMPARE(oldPeer->write(acknowledgement(nonce)), qint64(24));
        QVERIFY(oldPeer->waitForBytesWritten(1000));
        QTRY_COMPARE_WITH_TIMEOUT(applied.count(), 1, 3000);
        QTRY_COMPARE_WITH_TIMEOUT(oldPeer->state(), QAbstractSocket::UnconnectedState, 3000);
        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);

        QScopedPointer<QTcpSocket> newPeer(server.nextPendingConnection());
        QVERIFY(newPeer);
        QTRY_COMPARE_WITH_TIMEOUT(newPeer->state(), QAbstractSocket::ConnectedState, 3000);
        client.disconnectFromHost();
    }

    void repeatedStopCannotInvalidateAcceptedAcknowledgement()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy applied(&client, &IpcClient::commandApplied);
        client.requestServiceStopAndDisconnect(ElevateNever);

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> peer(server.nextPendingConnection());
        QVERIFY(peer);
        QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= 29, 3000);
        const QByteArray nonce = stopNonce(peer->readAll());
        QCOMPARE(nonce.size(), 16);

        QVERIFY(QMetaObject::invokeMethod(
            &client, "handleCommandApplied", Qt::DirectConnection,
            Q_ARG(QByteArray, nonce)));
        client.requestServiceStopAndDisconnect(ElevateNever);
        QCoreApplication::processEvents(QEventLoop::AllEvents);

        QCOMPARE(applied.count(), 1);
        QTRY_COMPARE_WITH_TIMEOUT(peer->state(), QAbstractSocket::UnconnectedState, 3000);
    }

    void staleAppliedCallbackCannotCloseReplacementConnection()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy applied(&client, &IpcClient::commandApplied);
        client.requestServiceStopAndDisconnect(ElevateNever);

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> oldPeer(server.nextPendingConnection());
        QVERIFY(oldPeer);
        QTRY_VERIFY_WITH_TIMEOUT(oldPeer->bytesAvailable() >= 29, 3000);
        const QByteArray nonce = stopNonce(oldPeer->readAll());
        QCOMPARE(nonce.size(), 16);

        QVERIFY(QMetaObject::invokeMethod(
            &client, "handleCommandApplied", Qt::DirectConnection,
            Q_ARG(QByteArray, nonce)));
        client.disconnectFromHost();
        client.connectToHost();
        QCoreApplication::processEvents(QEventLoop::AllEvents);

        QCOMPARE(applied.count(), 0);
        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> newPeer(server.nextPendingConnection());
        QVERIFY(newPeer);
        QTRY_COMPARE_WITH_TIMEOUT(newPeer->state(), QAbstractSocket::ConnectedState, 3000);
        QTRY_VERIFY_WITH_TIMEOUT(newPeer->bytesAvailable() >= 29, 3000);
        const QByteArray replacementNonce = stopNonce(newPeer->readAll());
        QCOMPARE(replacementNonce, nonce);

        QCOMPARE(newPeer->write(acknowledgement(replacementNonce)), qint64(24));
        QVERIFY(newPeer->waitForBytesWritten(1000));
        QTRY_COMPARE_WITH_TIMEOUT(applied.count(), 1, 3000);
        QTRY_COMPARE_WITH_TIMEOUT(newPeer->state(), QAbstractSocket::UnconnectedState, 3000);
    }

    void queuedAcknowledgementFromOldReaderCannotCloseReplacementConnection()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy applied(&client, &IpcClient::commandApplied);
        client.requestServiceStopAndDisconnect(ElevateNever);

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> oldPeer(server.nextPendingConnection());
        QVERIFY(oldPeer);
        QTRY_VERIFY_WITH_TIMEOUT(oldPeer->bytesAvailable() >= 29, 3000);
        const QByteArray nonce = stopNonce(oldPeer->readAll());
        QCOMPARE(nonce.size(), 16);

        QVERIFY(QMetaObject::invokeMethod(
            &client, "handleCommandAppliedForGeneration", Qt::QueuedConnection,
            Q_ARG(QByteArray, nonce), Q_ARG(quint64, quint64(1))));
        client.disconnectFromHost();
        client.connectToHost();
        QCoreApplication::processEvents(QEventLoop::AllEvents);

        QCOMPARE(applied.count(), 0);
        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> newPeer(server.nextPendingConnection());
        QVERIFY(newPeer);
        QTRY_COMPARE_WITH_TIMEOUT(newPeer->state(), QAbstractSocket::ConnectedState, 3000);
        QTRY_VERIFY_WITH_TIMEOUT(newPeer->bytesAvailable() >= 29, 3000);
        const QByteArray replacementNonce = stopNonce(newPeer->readAll());
        QCOMPARE(replacementNonce, nonce);

        QCOMPARE(newPeer->write(acknowledgement(replacementNonce)), qint64(24));
        QVERIFY(newPeer->waitForBytesWritten(1000));
        QTRY_COMPARE_WITH_TIMEOUT(applied.count(), 1, 3000);
        QTRY_COMPARE_WITH_TIMEOUT(newPeer->state(), QAbstractSocket::UnconnectedState, 3000);
    }

    void queuedLogFromOldReaderCannotReachReplacementConnection()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy logs(&client, &IpcClient::readLogLine);
        client.connectToHost();
        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> oldPeer(server.nextPendingConnection());
        QVERIFY(oldPeer);

        QVERIFY(QMetaObject::invokeMethod(
            &client, "handleReadLogLineForGeneration", Qt::QueuedConnection,
            Q_ARG(QString, QStringLiteral("stale-old-transport")),
            Q_ARG(quint64, quint64(1))));
        client.disconnectFromHost();
        client.connectToHost();
        QCoreApplication::processEvents(QEventLoop::AllEvents);

        QCOMPARE(logs.count(), 0);
        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> newPeer(server.nextPendingConnection());
        QVERIFY(newPeer);
        client.disconnectFromHost();
    }

    void queuedStateFromOldReaderCannotReachReplacementConnection()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy states(&client, &IpcClient::readConnectionState);
        client.connectToHost();
        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> oldPeer(server.nextPendingConnection());
        QVERIFY(oldPeer);

        QVERIFY(QMetaObject::invokeMethod(
            &client, "handleReadConnectionStateForGeneration", Qt::QueuedConnection,
            Q_ARG(IpcConnectionState, IpcConnectionState::Connected),
            Q_ARG(IpcConnectionRole, IpcConnectionRole::ClientPeer),
            Q_ARG(QString, QStringLiteral("old-peer")),
            Q_ARG(QString, QStringLiteral("stale-old-transport")),
            Q_ARG(IpcIdentityPresence, IpcIdentityPresence::Known),
            Q_ARG(quint64, quint64(1))));
        client.disconnectFromHost();
        client.connectToHost();
        QCoreApplication::processEvents(QEventLoop::AllEvents);

        QCOMPARE(states.count(), 0);
        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> newPeer(server.nextPendingConnection());
        QVERIFY(newPeer);
        client.disconnectFromHost();
    }

    void repeatedConnectToHostKeepsActiveReaderGeneration()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy logs(&client, &IpcClient::readLogLine);
        client.connectToHost();

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> peer(server.nextPendingConnection());
        QVERIFY(peer);
        QTRY_COMPARE_WITH_TIMEOUT(peer->state(), QAbstractSocket::ConnectedState, 3000);
        QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= 5, 3000);
        peer->readAll();

        client.connectToHost();
        QCOMPARE(peer->write(logMessage("active-transport")), qint64(24));
        QVERIFY(peer->waitForBytesWritten(1000));

        QTRY_COMPARE_WITH_TIMEOUT(logs.count(), 1, 3000);
        QCOMPARE(logs.at(0).at(0).toString(), QStringLiteral("active-transport"));
        client.disconnectFromHost();
    }

    void failedInitialConnectionRetryRefreshesReaderGeneration()
    {
        QTcpServer portProbe;
        QVERIFY(portProbe.listen(QHostAddress::LocalHost, 0));
        const quint16 port = portProbe.serverPort();
        portProbe.close();

        IpcClient client(port);
        QSignalSpy errors(&client, &IpcClient::errorMessage);
        QSignalSpy ready(&client, &IpcClient::connectionReady);
        QSignalSpy logs(&client, &IpcClient::readLogLine);
        auto* clientSocket = client.findChild<QTcpSocket*>();
        QVERIFY(clientSocket);
        client.connectToHost();
        QTRY_VERIFY_WITH_TIMEOUT(errors.count() >= 1, 5000);
        QTRY_COMPARE_WITH_TIMEOUT(
            clientSocket->state(), QAbstractSocket::UnconnectedState, 5000);

        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, port));
        QTRY_COMPARE_WITH_TIMEOUT(ready.count(), 1, 5000);

        // The abandoned SYN from the refused attempt may still be accepted after listen().
        // Select the live retry transport by its GUI hello instead of assuming FIFO pending order.
        QList<QPointer<QTcpSocket>> peers;
        QPointer<QTcpSocket> peer;
        QElapsedTimer peerDeadline;
        peerDeadline.start();
        while (!peer && peerDeadline.elapsed() < 5000) {
            while (server.hasPendingConnections()) {
                peers.append(server.nextPendingConnection());
            }
            for (const auto& candidate : peers) {
                if (candidate && candidate->state() == QAbstractSocket::ConnectedState &&
                    (candidate->bytesAvailable() >= 5 || candidate->waitForReadyRead(50))) {
                    peer = candidate;
                    break;
                }
            }
            if (!peer) QTest::qWait(10);
        }
        QVERIFY(peer);
        peer->readAll();

        QCOMPARE(peer->write(logMessage("retry-transport")), qint64(23));
        QVERIFY(peer->waitForBytesWritten(1000));
        QTRY_COMPARE_WITH_TIMEOUT(logs.count(), 1, 3000);
        QCOMPARE(logs.at(0).at(0).toString(), QStringLiteral("retry-transport"));
        client.disconnectFromHost();
    }

    void staleRetryFromStoppedTransportCannotReconnectNewAttempt()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy info(&client, &IpcClient::infoMessage);
        QSignalSpy errors(&client, &IpcClient::errorMessage);
        client.connectToHost();

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> oldPeer(server.nextPendingConnection());
        QVERIFY(oldPeer);
        QTRY_COMPARE_WITH_TIMEOUT(oldPeer->state(), QAbstractSocket::ConnectedState, 3000);

        oldPeer->abort();
        QTRY_VERIFY_WITH_TIMEOUT(errors.count() >= 1, 3000);
        client.disconnectFromHost();
        client.connectToHost();
        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);

        QScopedPointer<QTcpSocket> newPeer(server.nextPendingConnection());
        QVERIFY(newPeer);
        QTRY_COMPARE_WITH_TIMEOUT(newPeer->state(), QAbstractSocket::ConnectedState, 3000);
        QTest::qWait(2500);

        int connectingCount = 0;
        for (const auto& arguments : info) {
            if (arguments.at(0).toString() == QStringLiteral("connecting to service..."))
                ++connectingCount;
        }
        QCOMPARE(connectingCount, 2);
        client.disconnectFromHost();
    }

    void partialFrameFromDisconnectedTransportCannotCompleteOnReplacementConnection()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy logs(&client, &IpcClient::readLogLine);
        client.connectToHost();

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> oldPeer(server.nextPendingConnection());
        QVERIFY(oldPeer);
        QTRY_COMPARE_WITH_TIMEOUT(oldPeer->state(), QAbstractSocket::ConnectedState, 3000);
        QTRY_VERIFY_WITH_TIMEOUT(oldPeer->bytesAvailable() >= 5, 3000);
        oldPeer->readAll();

        const QByteArray complete = logMessage(QByteArrayLiteral("old-new"));
        const qsizetype split = complete.size() - 3;
        QCOMPARE(oldPeer->write(complete.left(split)), qint64(split));
        QVERIFY(oldPeer->waitForBytesWritten(1000));
        oldPeer->disconnectFromHost();
        QTRY_COMPARE_WITH_TIMEOUT(oldPeer->state(), QAbstractSocket::UnconnectedState, 1000);

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 4000);
        QScopedPointer<QTcpSocket> newPeer(server.nextPendingConnection());
        QVERIFY(newPeer);
        QTRY_COMPARE_WITH_TIMEOUT(newPeer->state(), QAbstractSocket::ConnectedState, 3000);
        QTRY_VERIFY_WITH_TIMEOUT(newPeer->bytesAvailable() >= 5, 3000);
        newPeer->readAll();

        QCOMPARE(newPeer->write(complete.right(3)), qint64(3));
        QVERIFY(newPeer->waitForBytesWritten(1000));
        QTest::qWait(100);

        QCOMPARE(logs.count(), 0);
        client.disconnectFromHost();
    }

    void daemonDisconnectPublishesTransportUnavailable()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy unavailable(&client, &IpcClient::transportUnavailable);
        client.connectToHost();

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> peer(server.nextPendingConnection());
        QVERIFY(peer);
        QTRY_COMPARE_WITH_TIMEOUT(peer->state(), QAbstractSocket::ConnectedState, 3000);

        peer->abort();

        QTRY_COMPARE_WITH_TIMEOUT(unavailable.count(), 1, 3000);
        client.disconnectFromHost();
    }

    void deliberateDisconnectCannotPublishStaleUnavailableAfterImmediateReconnect()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy unavailable(&client, &IpcClient::transportUnavailable);
        client.connectToHost();

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> oldPeer(server.nextPendingConnection());
        QVERIFY(oldPeer);
        QTRY_COMPARE_WITH_TIMEOUT(oldPeer->state(), QAbstractSocket::ConnectedState, 3000);

        client.disconnectFromHost();
        client.connectToHost();

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> replacementPeer(server.nextPendingConnection());
        QVERIFY(replacementPeer);
        QTRY_COMPARE_WITH_TIMEOUT(replacementPeer->state(), QAbstractSocket::ConnectedState, 3000);

        auto* clientSocket = client.findChild<QTcpSocket*>();
        QVERIFY(clientSocket);
        QVERIFY(QMetaObject::invokeMethod(clientSocket, "disconnected", Qt::DirectConnection));
        QCoreApplication::processEvents(QEventLoop::AllEvents);

        QCOMPARE(unavailable.count(), 0);
        client.disconnectFromHost();
    }

    void immediateReconnectDoesNotDiscardBufferedLegacyCommand()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        client.connectToHost();
        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> oldPeer(server.nextPendingConnection());
        QVERIFY(oldPeer);
        QTRY_VERIFY_WITH_TIMEOUT(oldPeer->bytesAvailable() >= 5, 3000);
        oldPeer->readAll();

        client.sendCommand(QString(512 * 1024, QLatin1Char('x')), ElevateNever);
        client.sendCommand(QString(), ElevateNever);
        auto* clientSocket = client.findChild<QTcpSocket*>();
        QVERIFY(clientSocket);
        QTRY_VERIFY_WITH_TIMEOUT(clientSocket->bytesToWrite() > 0, 3000);

        client.disconnectFromHost();
        client.connectToHost();

        QByteArray oldWire;
        QElapsedTimer drainDeadline;
        drainDeadline.start();
        while (drainDeadline.elapsed() < 5000 &&
               oldPeer->state() != QAbstractSocket::UnconnectedState) {
            if (oldPeer->waitForReadyRead(50)) oldWire += oldPeer->readAll();
            QCoreApplication::processEvents(QEventLoop::AllEvents);
        }
        oldWire += oldPeer->readAll();
        const QByteArray emptyCommand = QByteArrayLiteral("ICMD")
            + QByteArray(4, char(0)) + QByteArray(1, char(0));
        QVERIFY(oldWire.contains(emptyCommand));
        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);

        QScopedPointer<QTcpSocket> replacementPeer(server.nextPendingConnection());
        QVERIFY(replacementPeer);
        client.disconnectFromHost();
    }

    void pendingStartCanBeReplacedByStopBeforeConnect()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        client.sendCommand(QStringLiteral("start-command"), ElevateNever);
        client.cancelPendingCommand();
        client.sendCommand(QString(), ElevateNever);
        client.connectToHost();

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> peer(server.nextPendingConnection());
        QVERIFY(peer);
        constexpr qsizetype expectedSize = 5 + 4 + 4 + 1;
        QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= expectedSize ||
                                 peer->waitForReadyRead(50), 3000);
        QByteArray wire = peer->readAll();
        while (wire.size() < expectedSize && peer->waitForReadyRead(100))
            wire += peer->readAll();

        QByteArray expected;
        expected.append(kIpcMsgHello, 4);
        expected.append(char(kIpcClientGui));
        expected.append(kIpcMsgCommand, 4);
        expected.append(QByteArray(4, char(0)));
        expected.append(char(0));
        QCOMPARE(wire, expected);
        client.disconnectFromHost();
    }

    void commandQueuedWhileConnectingIsSentAfterGuiHello()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        client.sendCommand(QStringLiteral("queued-command"), ElevateNever);
        client.connectToHost();

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> peer(server.nextPendingConnection());
        QVERIFY(peer);

        const QByteArray command = QByteArrayLiteral("queued-command");
        const qsizetype expectedSize = 5 + 4 + 4 + command.size() + 1;
        QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= expectedSize || peer->waitForReadyRead(50), 3000);
        QByteArray wire = peer->readAll();
        while (wire.size() < expectedSize && peer->waitForReadyRead(100)) {
            wire += peer->readAll();
        }

        QByteArray expected;
        expected.append(kIpcMsgHello, 4);
        expected.append(char(kIpcClientGui));
        expected.append(kIpcMsgStartRequest, 4);
        expected.append(QByteArrayLiteral("\0\0\0\x10"));
        const QByteArray nonce = startNonce(wire);
        QCOMPARE(nonce.size(), 16);
        expected.append(nonce);
        const quint32 length = static_cast<quint32>(command.size());
        expected.append(char((length >> 24) & 0xff));
        expected.append(char((length >> 16) & 0xff));
        expected.append(char((length >> 8) & 0xff));
        expected.append(char(length & 0xff));
        expected.append(command);
        expected.append(char(0));

        QCOMPARE(wire, expected);
        client.disconnectFromHost();
    }

    void startWaitsForItsCorrelatedAppliedAcknowledgement()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy applied(&client, &IpcClient::startCommandApplied);
        client.sendCommand(QStringLiteral("queued-command"), ElevateNever);
        client.connectToHost();

        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> peer(server.nextPendingConnection());
        QVERIFY(peer);
        QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= 29 ||
                                 peer->waitForReadyRead(50), 3000);
        QByteArray wire = peer->readAll();
        while (startNonce(wire).isEmpty() && peer->waitForReadyRead(100)) {
            wire += peer->readAll();
        }
        const QByteArray nonce = startNonce(wire);
        QCOMPARE(nonce.size(), 16);

        QCOMPARE(peer->write(acknowledgement(QByteArray(16, 'x'))), qint64(24));
        QVERIFY(peer->waitForBytesWritten(1000));
        QTest::qWait(100);
        QCOMPARE(applied.count(), 0);

        QCOMPARE(peer->write(acknowledgement(nonce)), qint64(24));
        QVERIFY(peer->waitForBytesWritten(1000));
        QTRY_COMPARE_WITH_TIMEOUT(applied.count(), 1, 3000);
        client.disconnectFromHost();
    }

    void staleRetryFromOldTransportDoesNotReconnectNewTransport()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost, 0));

        IpcClient client(server.serverPort());
        QSignalSpy info(&client, &IpcClient::infoMessage);
        QSignalSpy errors(&client, &IpcClient::errorMessage);
        client.connectToHost();
        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> oldPeer(server.nextPendingConnection());
        QVERIFY(oldPeer);
        QTRY_COMPARE_WITH_TIMEOUT(oldPeer->state(), QAbstractSocket::ConnectedState, 3000);

        oldPeer->abort();
        QTRY_VERIFY_WITH_TIMEOUT(errors.count() >= 1, 3000);

        client.disconnectFromHost();
        client.connectToHost();
        QTRY_VERIFY_WITH_TIMEOUT(server.hasPendingConnections(), 3000);
        QScopedPointer<QTcpSocket> newPeer(server.nextPendingConnection());
        QVERIFY(newPeer);
        QTRY_COMPARE_WITH_TIMEOUT(newPeer->state(), QAbstractSocket::ConnectedState, 3000);
        QTRY_VERIFY_WITH_TIMEOUT(info.count() >= 5, 3000);
        const int messagesAfterNewConnection = info.count();

        QTest::qWait(1200);
        QCOMPARE(info.count(), messagesAfterNewConnection);
        QCOMPARE(newPeer->state(), QAbstractSocket::ConnectedState);
        client.disconnectFromHost();
    }
};

QTEST_GUILESS_MAIN(IpcClientTests)
#include "IpcClientTests.moc"
