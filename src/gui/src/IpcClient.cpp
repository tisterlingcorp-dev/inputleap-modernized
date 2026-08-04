/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2012 Nick Bolton
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "IpcClient.h"
#include <QTcpSocket>
#include <QHostAddress>
#include <QEventLoop>
#include <iostream>
#include <QTimer>
#include <QUuid>
#include "IpcReader.h"
#include "Ipc.h"
#include <QDataStream>

IpcClient::IpcClient(quint16 port) :
m_ReaderStarted(false),
m_Enabled(false),
m_Port(port)
{
    m_Socket = new QTcpSocket(this);
    connect(m_Socket, &QTcpSocket::connected, this, &IpcClient::connected);
    connect(m_Socket, &QTcpSocket::disconnected, this, [this] {
        // A delayed signal from a deliberately closed transport can arrive after an
        // immediate reconnect has already moved this socket to a new attempt.
        if (m_Socket->state() != QAbstractSocket::UnconnectedState) return;
        const bool transportWasEnabled = m_Enabled;
        m_Ready = false;
        m_Reader->stop();
        m_ReaderStarted = false;
        if (m_ReconnectPending && m_Enabled) {
            m_ReconnectPending = false;
            beginConnectionAttempt();
            return;
        }
        if (transportWasEnabled) Q_EMIT transportUnavailable();
    });
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
    connect(m_Socket, &QTcpSocket::errorOccurred, this, &IpcClient::error);
#else
    connect(m_Socket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(error(QAbstractSocket::SocketError)));
#endif

    m_Reader = new IpcReader(m_Socket);
    connect(m_Reader, &IpcReader::readLogLineForGeneration,
            this, &IpcClient::handleReadLogLineForGeneration);
    connect(m_Reader, &IpcReader::commandAppliedForGeneration,
            this, &IpcClient::handleCommandAppliedForGeneration);
    connect(m_Reader, &IpcReader::readConnectionStateForGeneration,
            this, &IpcClient::handleReadConnectionStateForGeneration);
}

IpcClient::~IpcClient()
{
}

void IpcClient::connected()
{
    sendHello();
    m_Ready = true;
    if (m_PendingCommand) {
        const auto pending = *m_PendingCommand;
        writeCommand(pending.command, pending.elevate, pending.nonce);
        if (pending.nonce.isEmpty()) m_PendingCommand.reset();
    }
    if (m_StopDisconnectPending) writeStopRequest();
    Q_EMIT connectionReady();
    Q_EMIT infoMessage("connection established");
}

void IpcClient::connectToHost()
{
    m_Enabled = true;

    Q_EMIT infoMessage("connecting to service...");
    if (m_Socket->state() != QAbstractSocket::UnconnectedState) {
        if (m_Socket->state() == QAbstractSocket::ClosingState) {
            m_ReconnectPending = true;
        }
        return;
    }
    m_ReconnectPending = false;
    beginConnectionAttempt();
}

void IpcClient::beginConnectionAttempt()
{
    ++m_ConnectionGeneration;
    if (m_ReaderStarted) {
        m_Reader->stop();
    }
    m_Reader->start(m_ConnectionGeneration);
    m_ReaderStarted = true;
    m_Socket->connectToHost(QHostAddress(QHostAddress::LocalHost), m_Port);
}

void IpcClient::disconnectFromHost()
{
    ++m_ConnectionGeneration;
    m_Enabled = false;
    m_Ready = false;
    m_ReconnectPending = false;
    Q_EMIT infoMessage("service disconnect");
    m_Reader->stop();
    m_ReaderStarted = false;
    m_Socket->disconnectFromHost();
}

void IpcClient::error(QAbstractSocket::SocketError error)
{
    m_Ready = false;
    QString text;
    switch (error) {
        case 0: text = "connection refused"; break;
        case 1: text = "remote host closed"; break;
        default: text = QString("code=%1").arg(error); break;
    }

    Q_EMIT errorMessage(QString("ipc connection error, %1").arg(text));

    const quint64 connectionGeneration = m_ConnectionGeneration;
    QTimer::singleShot(1000, this, [this, connectionGeneration] {
        if (m_Enabled && connectionGeneration == m_ConnectionGeneration) {
            connectToHost();
        }
    });
}

void IpcClient::retryConnect()
{
    if (m_Enabled) {
        connectToHost();
    }
}

void IpcClient::sendHello()
{
    QByteArray frame;
    QDataStream stream(&frame, QIODevice::WriteOnly);
    stream.writeRawData(kIpcMsgHello, 4);

    char typeBuf[1];
    typeBuf[0] = kIpcClientGui;
    stream.writeRawData(typeBuf, 1);
    m_Socket->write(frame);
}

void IpcClient::sendCommand(const QString& command, ElevateMode const elevate)
{
    m_StartNonce = command.isEmpty() ? QByteArray() : QUuid::createUuid().toRfc4122();
    m_PendingCommand = PendingCommand{command, elevate, m_StartNonce};
    if (!m_Ready || m_Socket->state() != QAbstractSocket::ConnectedState) {
        return;
    }
    writeCommand(command, elevate, m_StartNonce);
    if (m_StartNonce.isEmpty()) m_PendingCommand.reset();
}

void IpcClient::requestServiceStopAndDisconnect(ElevateMode const elevate)
{
    Q_UNUSED(elevate);
    if (m_StopDisconnectPending) return;
    ++m_StopGeneration;
    m_StopDisconnectPending = true;
    m_StopNonce = QUuid::createUuid().toRfc4122();
    cancelPendingCommand();
    if (m_Ready && m_Socket->state() == QAbstractSocket::ConnectedState) {
        writeStopRequest();
    }
    else if (!m_Enabled) {
        connectToHost();
    }
}

bool IpcClient::requestServiceStopAndWait(ElevateMode const elevate, int timeoutMs)
{
    bool applied = false;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    connect(this, &IpcClient::commandApplied, &loop, [&] {
        applied = true;
        loop.quit();
    });
    connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    requestServiceStopAndDisconnect(elevate);
    timeout.start(timeoutMs);
    loop.exec();
    return applied;
}

void IpcClient::cancelPendingCommand() noexcept
{
    m_PendingCommand.reset();
    m_StartNonce.clear();
}

void IpcClient::writeCommand(
    const QString& command, ElevateMode const elevate, const QByteArray& nonce)
{
    const QByteArray encoded = command.toUtf8();
    constexpr qsizetype kMaximumCommandLength = 1024 * 1024;
    if (encoded.size() > kMaximumCommandLength) {
        Q_EMIT errorMessage(QStringLiteral("ipc command exceeds maximum length"));
        return;
    }

    QByteArray frame;
    QDataStream stream(&frame, QIODevice::WriteOnly);

    const bool correlatedStart = nonce.size() == 16;
    stream.writeRawData(correlatedStart ? kIpcMsgStartRequest : kIpcMsgCommand, 4);

    char lenBuf[4];
    if (correlatedStart) {
        intToBytes(nonce.size(), lenBuf, 4);
        stream.writeRawData(lenBuf, 4);
        stream.writeRawData(nonce.constData(), nonce.size());
    }

    const int length = static_cast<int>(encoded.size());
    intToBytes(length, lenBuf, 4);
    stream.writeRawData(lenBuf, 4);
    stream.writeRawData(encoded.constData(), length);

    char elevateBuf[1];
    // Refer to enum ElevateMode documentation for why this flag is mapped this way
    elevateBuf[0] = (elevate == ElevateAlways) ? 1 : 0;
    stream.writeRawData(elevateBuf, 1);
    m_Socket->write(frame);
}

void IpcClient::writeStopRequest()
{
    if (m_StopNonce.size() != 16) {
        Q_EMIT errorMessage(QStringLiteral("IPC stop nonce is invalid"));
        return;
    }
    QByteArray frame;
    QDataStream stream(&frame, QIODevice::WriteOnly);
    stream.writeRawData(kIpcMsgStopRequest, 4);
    char lenBuf[4];
    intToBytes(m_StopNonce.size(), lenBuf, 4);
    stream.writeRawData(lenBuf, 4);
    stream.writeRawData(m_StopNonce.constData(), m_StopNonce.size());
    m_Socket->write(frame);
}

void IpcClient::handleReadLogLine(const QString& text)
{
    if (m_StopDisconnectPending) return;
    Q_EMIT readLogLine(text);
}

void IpcClient::handleCommandApplied(const QByteArray& nonce)
{
    if (!m_StopDisconnectPending && nonce == m_StartNonce) {
        m_StartNonce.clear();
        m_PendingCommand.reset();
        Q_EMIT startCommandApplied();
        return;
    }
    if (!m_StopDisconnectPending || nonce != m_StopNonce) return;
    const quint64 stopGeneration = m_StopGeneration;
    const quint64 connectionGeneration = m_ConnectionGeneration;
    QTimer::singleShot(0, this, [this, stopGeneration, connectionGeneration] {
        if (stopGeneration != m_StopGeneration ||
            connectionGeneration != m_ConnectionGeneration) return;
        m_StopNonce.clear();
        m_StopDisconnectPending = false;
        disconnectFromHost();
        Q_EMIT commandApplied();
    });
}

void IpcClient::handleReadConnectionState(
    IpcConnectionState state, IpcConnectionRole role,
    const QString& technicalName, const QString& detail,
    IpcIdentityPresence identityPresence)
{
    if (m_StopDisconnectPending) return;
    Q_EMIT readConnectionState(state, role, technicalName, detail, identityPresence);
}

void IpcClient::handleReadLogLineForGeneration(
    const QString& text, quint64 generation)
{
    if (generation != m_ConnectionGeneration) return;
    handleReadLogLine(text);
}

void IpcClient::handleCommandAppliedForGeneration(
    const QByteArray& nonce, quint64 generation)
{
    if (generation != m_ConnectionGeneration) return;
    handleCommandApplied(nonce);
}

void IpcClient::handleReadConnectionStateForGeneration(
    IpcConnectionState state, IpcConnectionRole role,
    const QString& technicalName, const QString& detail,
    IpcIdentityPresence identityPresence, quint64 generation)
{
    if (generation != m_ConnectionGeneration) return;
    handleReadConnectionState(state, role, technicalName, detail, identityPresence);
}

// TODO: qt must have a built in way of converting int to bytes.
void IpcClient::intToBytes(int value, char *buffer, int size)
{
    if (size == 1) {
        buffer[0] = value & 0xff;
    }
    else if (size == 2) {
        buffer[0] = (value >> 8) & 0xff;
        buffer[1] = value & 0xff;
    }
    else if (size == 4) {
        buffer[0] = (value >> 24) & 0xff;
        buffer[1] = (value >> 16) & 0xff;
        buffer[2] = (value >> 8) & 0xff;
        buffer[3] = value & 0xff;
    }
    else {
        // TODO: other sizes, if needed.
    }
}
