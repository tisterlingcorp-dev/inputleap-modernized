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

#pragma once

#include <QObject>
#include <QAbstractSocket>
#include <optional>

#include "ElevateMode.h"
#include "Ipc.h"

class QTcpSocket;
class IpcReader;

class IpcClient : public QObject
{
    Q_OBJECT

public:
    explicit IpcClient(quint16 port = IPC_PORT);
    virtual ~IpcClient();

    void sendHello();
    void sendCommand(const QString& command, ElevateMode elevate);
    void requestServiceStopAndDisconnect(ElevateMode elevate);
    bool requestServiceStopAndWait(ElevateMode elevate, int timeoutMs);
    void cancelPendingCommand() noexcept;
    void connectToHost();
    void disconnectFromHost();

public slots:
    void retryConnect();

private:
    void intToBytes(int value, char* buffer, int size);
    void beginConnectionAttempt();
    void writeCommand(const QString& command, ElevateMode elevate, const QByteArray& nonce);
    void writeStopRequest();

private slots:
    void connected();
    void error(QAbstractSocket::SocketError error);
    void handleReadLogLine(const QString& text);
    void handleCommandApplied(const QByteArray& nonce);
    void handleReadConnectionState(IpcConnectionState state, IpcConnectionRole role,
                                   const QString& technicalName, const QString& detail,
                                   IpcIdentityPresence identityPresence);
    void handleReadLogLineForGeneration(const QString& text, quint64 generation);
    void handleCommandAppliedForGeneration(const QByteArray& nonce, quint64 generation);
    void handleReadConnectionStateForGeneration(
        IpcConnectionState state, IpcConnectionRole role,
        const QString& technicalName, const QString& detail,
        IpcIdentityPresence identityPresence, quint64 generation);

Q_SIGNALS:
    void readLogLine(const QString& text);
    void connectionReady();
    void transportUnavailable();
    void commandApplied();
    void startCommandApplied();
    void readConnectionState(IpcConnectionState state, IpcConnectionRole role,
                             const QString& technicalName, const QString& detail,
                             IpcIdentityPresence identityPresence);
    void infoMessage(const QString& text);
    void errorMessage(const QString& text);

private:
    struct PendingCommand {
        QString command;
        ElevateMode elevate;
        QByteArray nonce;
    };

    QTcpSocket* m_Socket;
    IpcReader* m_Reader;
    bool m_ReaderStarted;
    bool m_Enabled;
    bool m_Ready{false};
    quint16 m_Port;
    std::optional<PendingCommand> m_PendingCommand;
    QByteArray m_StartNonce;
    bool m_StopDisconnectPending{false};
    QByteArray m_StopNonce;
    quint64 m_StopGeneration{0};
    quint64 m_ConnectionGeneration{0};
    bool m_ReconnectPending{false};
};
