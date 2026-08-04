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
#include <QRecursiveMutex>
#include <QByteArray>
#include "Ipc.h"

class QTcpSocket;

class IpcReader : public QObject
{
    Q_OBJECT

public:
    IpcReader(QTcpSocket* socket);
    virtual ~IpcReader();
    void start(quint64 generation = 0);
    void stop();
    // Incremental, non-blocking parser entry point; also useful for deterministic tests.
    void appendData(const QByteArray& data);

Q_SIGNALS:
    void readLogLine(const QString& text);
    void commandApplied(const QByteArray& nonce);
    void protocolError(const QString& detail);
    void readConnectionState(IpcConnectionState state, IpcConnectionRole role,
                             const QString& technicalName, const QString& detail,
                             IpcIdentityPresence identityPresence);
    void readLogLineForGeneration(const QString& text, quint64 generation);
    void commandAppliedForGeneration(const QByteArray& nonce, quint64 generation);
    void readConnectionStateForGeneration(
        IpcConnectionState state, IpcConnectionRole role,
        const QString& technicalName, const QString& detail,
        IpcIdentityPresence identityPresence, quint64 generation);

private:
    void parseAvailable();
    void failProtocol(const QString& detail);

private slots:
    void read();

private:
    QTcpSocket* m_Socket;
    quint64 m_Generation{0};
    // Consumers may enter a nested Qt event loop (for example the fingerprint dialog),
    // allowing disconnect/stop to re-enter while a parsed frame is being delivered.
    QRecursiveMutex m_Mutex;
    QByteArray m_Buffer;
};
