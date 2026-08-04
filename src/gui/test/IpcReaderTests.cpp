#include "IpcReader.h"

#include <QSignalSpy>
#include <QtTest>

namespace {
QByteArray stringField(const QByteArray& value)
{
    QByteArray result;
    const auto length = static_cast<quint32>(value.size());
    result.append(char((length >> 24) & 0xff));
    result.append(char((length >> 16) & 0xff));
    result.append(char((length >> 8) & 0xff));
    result.append(char(length & 0xff));
    result.append(value);
    return result;
}

QByteArray stateMessage(quint8 state, quint8 role, quint8 presence,
                        const QByteArray& name, const QByteArray& detail)
{
    return QByteArrayLiteral("ISTS") + char(state) + char(role) + char(presence)
        + stringField(name) + stringField(detail);
}

QByteArray logMessage(const QByteArray& text)
{
    return QByteArrayLiteral("ILOG") + stringField(text);
}
}

class IpcReaderTests : public QObject
{
    Q_OBJECT

private slots:
    void parsesCommandAppliedAcknowledgement()
    {
        IpcReader reader(nullptr);
        QSignalSpy applied(&reader, &IpcReader::commandApplied);
        const QByteArray nonce = QByteArray::fromHex("00112233445566778899aabbccddeeff");
        const QByteArray wire = QByteArrayLiteral("IACK") + stringField(nonce);

        for (char byte : wire) {
            reader.appendData(QByteArray(1, byte));
        }

        QCOMPARE(applied.count(), 1);
        QCOMPARE(applied.at(0).at(0).toByteArray(), nonce);
    }

    void reentrantRestartCannotRelabelOldAcknowledgement()
    {
        IpcReader reader(nullptr);
        reader.start(1);
        QSignalSpy applied(&reader, &IpcReader::commandAppliedForGeneration);
        connect(&reader, &IpcReader::commandApplied, &reader, [&reader] {
            reader.stop();
            reader.start(2);
        }, Qt::DirectConnection);
        const QByteArray nonce = QByteArray::fromHex("00112233445566778899aabbccddeeff");

        reader.appendData(QByteArrayLiteral("IACK") + stringField(nonce));

        QCOMPARE(applied.count(), 1);
        QCOMPARE(applied.at(0).at(0).toByteArray(), nonce);
        QCOMPARE(applied.at(0).at(1).toULongLong(), quint64(1));
    }

    void reentrantRestartCannotRelabelOldLogLine()
    {
        IpcReader reader(nullptr);
        reader.start(1);
        QSignalSpy logs(&reader, &IpcReader::readLogLineForGeneration);
        connect(&reader, &IpcReader::readLogLine, &reader, [&reader] {
            reader.stop();
            reader.start(2);
        }, Qt::DirectConnection);

        reader.appendData(logMessage("old-transport"));

        QCOMPARE(logs.count(), 1);
        QCOMPARE(logs.at(0).at(0).toString(), QStringLiteral("old-transport"));
        QCOMPARE(logs.at(0).at(1).toULongLong(), quint64(1));
    }

    void reentrantRestartCannotRelabelOldConnectionState()
    {
        IpcReader reader(nullptr);
        reader.start(1);
        QSignalSpy states(&reader, &IpcReader::readConnectionStateForGeneration);
        connect(&reader, &IpcReader::readConnectionState, &reader, [&reader] {
            reader.stop();
            reader.start(2);
        }, Qt::DirectConnection);

        reader.appendData(stateMessage(1, 0, 0, "old-peer", "connected"));

        QCOMPARE(states.count(), 1);
        QCOMPARE(states.at(0).at(2).toString(), QStringLiteral("old-peer"));
        QCOMPARE(states.at(0).at(5).toULongLong(), quint64(1));
    }

    void parsesConcatenatedLogAndTypedState()
    {
        IpcReader reader(nullptr);
        QSignalSpy logs(&reader, &IpcReader::readLogLine);
        QSignalSpy states(&reader, &IpcReader::readConnectionState);

        reader.appendData(logMessage("hello") +
                          stateMessage(1, 0, 0, QString::fromUtf8("escritório-猫").toUtf8(), "ok"));

        QCOMPARE(logs.count(), 1);
        QCOMPARE(logs.at(0).at(0).toString(), QStringLiteral("hello"));
        QCOMPARE(states.count(), 1);
        QCOMPARE(states.at(0).at(0).value<IpcConnectionState>(), IpcConnectionState::Connected);
        QCOMPARE(states.at(0).at(1).value<IpcConnectionRole>(), IpcConnectionRole::ClientPeer);
        QCOMPARE(states.at(0).at(2).toString(), QString::fromUtf8("escritório-猫"));
        QCOMPARE(states.at(0).at(3).toString(), QStringLiteral("ok"));
        QCOMPARE(states.at(0).at(4).value<IpcIdentityPresence>(), IpcIdentityPresence::Known);
    }

    void waitsIncrementallyForFragmentedMessage()
    {
        IpcReader reader(nullptr);
        QSignalSpy states(&reader, &IpcReader::readConnectionState);
        const QByteArray wire = stateMessage(2, 1, 0, "server-a", "network lost");

        for (char byte : wire) {
            reader.appendData(QByteArray(1, byte));
        }

        QCOMPARE(states.count(), 1);
        QCOMPARE(states.at(0).at(0).value<IpcConnectionState>(), IpcConnectionState::Disconnected);
    }

    void rejectsMalformedAndRecoversOnNextMessage()
    {
        IpcReader reader(nullptr);
        QSignalSpy states(&reader, &IpcReader::readConnectionState);
        reader.appendData(stateMessage(99, 0, 0, "bad", ""));
        QCOMPARE(states.count(), 0);

        reader.appendData(stateMessage(0, 1, 1, "", "legacy client"));
        QCOMPARE(states.count(), 1);
        QCOMPARE(states.at(0).at(4).value<IpcIdentityPresence>(), IpcIdentityPresence::LegacyUnavailable);
    }

    void unknownMessageDoesNotEmitOrCrashAndRecoversOnNextRead()
    {
        IpcReader reader(nullptr);
        QSignalSpy logs(&reader, &IpcReader::readLogLine);
        QSignalSpy errors(&reader, &IpcReader::protocolError);
        reader.appendData(QByteArrayLiteral("NOPEgarbage") + logMessage("must-not-pass"));
        QCOMPARE(logs.count(), 0);
        QCOMPARE(errors.count(), 1);
        reader.appendData(logMessage("after"));
        QCOMPARE(logs.count(), 1);
    }

    void stopClearsPartialFrameBeforeNextConnection()
    {
        IpcReader reader(nullptr);
        QSignalSpy logs(&reader, &IpcReader::readLogLine);
        const QByteArray stale = logMessage("stale");

        reader.appendData(stale.left(6));
        reader.stop();
        reader.appendData(logMessage("fresh"));

        QCOMPARE(logs.count(), 1);
        QCOMPARE(logs.at(0).at(0).toString(), QStringLiteral("fresh"));
    }

    void logConsumerCanStopReaderReentrantly()
    {
        IpcReader reader(nullptr);
        bool stopped = false;
        connect(&reader, &IpcReader::readLogLine, &reader, [&] {
            reader.stop();
            stopped = true;
        }, Qt::DirectConnection);

        reader.appendData(logMessage("fingerprint-modal-consumer"));

        QVERIFY(stopped);
    }

    void stringLengthAboveLimitIsRejectedButExactLimitIsAccepted()
    {
        IpcReader reader(nullptr);
        QSignalSpy logs(&reader, &IpcReader::readLogLine);
        QSignalSpy errors(&reader, &IpcReader::protocolError);
        QByteArray oversizedHeader = QByteArrayLiteral("ILOG");
        oversizedHeader.append(char(0x00));
        oversizedHeader.append(char(0x10));
        oversizedHeader.append(char(0x00));
        oversizedHeader.append(char(0x01));

        reader.appendData(oversizedHeader);
        QCOMPARE(errors.count(), 1);
        QCOMPARE(logs.count(), 0);

        reader.appendData(logMessage(QByteArray(1024 * 1024, 'x')));
        QCOMPARE(logs.count(), 1);
    }
};

QTEST_GUILESS_MAIN(IpcReaderTests)
#include "IpcReaderTests.moc"
