/*
 * InputLeap -- mouse and keyboard sharing utility
 * Incremental GUI IPC reader.
 */

#include "IpcReader.h"

#include <QTcpSocket>
#include <QMutexLocker>
#include <QtEndian>
#include <cstring>

namespace {
constexpr quint32 kMaximumStringLength = 1024 * 1024;

enum class FieldResult { Complete, Incomplete, Malformed };

FieldResult readStringField(const QByteArray& buffer, int& offset, QByteArray& value)
{
    if (buffer.size() - offset < 4) {
        return FieldResult::Incomplete;
    }
    const auto* bytes = reinterpret_cast<const uchar*>(buffer.constData() + offset);
    const quint32 length = qFromBigEndian<quint32>(bytes);
    if (length > kMaximumStringLength) {
        return FieldResult::Malformed;
    }
    if (quint64(buffer.size() - offset - 4) < length) {
        return FieldResult::Incomplete;
    }
    offset += 4;
    value = buffer.mid(offset, static_cast<int>(length));
    offset += static_cast<int>(length);
    return FieldResult::Complete;
}
}

IpcReader::IpcReader(QTcpSocket* socket) :
    m_Socket(socket)
{
}

IpcReader::~IpcReader() = default;

void IpcReader::start(quint64 generation)
{
    m_Generation = generation;
    if (m_Socket != nullptr) {
        connect(m_Socket, &QTcpSocket::readyRead, this, &IpcReader::read);
    }
}

void IpcReader::stop()
{
    if (m_Socket != nullptr) {
        disconnect(m_Socket, &QTcpSocket::readyRead, this, &IpcReader::read);
    }
    QMutexLocker locker(&m_Mutex);
    m_Buffer.clear();
}

void IpcReader::read()
{
    if (m_Socket != nullptr) {
        appendData(m_Socket->readAll());
    }
}

void IpcReader::appendData(const QByteArray& data)
{
    QMutexLocker locker(&m_Mutex);
    m_Buffer.append(data);
    parseAvailable();
}

void IpcReader::parseAvailable()
{
    while (m_Buffer.size() >= 4) {
        const QByteArray code = m_Buffer.left(4);
        int offset = 4;

        if (code == QByteArray(kIpcMsgCommandApplied, 4)) {
            QByteArray nonce;
            const auto result = readStringField(m_Buffer, offset, nonce);
            if (result == FieldResult::Incomplete) return;
            if (result == FieldResult::Malformed || nonce.size() != 16) {
                failProtocol(QStringLiteral("IPC command acknowledgement nonce is invalid"));
                return;
            }
            m_Buffer.remove(0, offset);
            const quint64 generation = m_Generation;
            Q_EMIT commandApplied(nonce);
            Q_EMIT commandAppliedForGeneration(nonce, generation);
            continue;
        }

        if (code == QByteArray(kIpcMsgLogLine, 4)) {
            QByteArray line;
            const auto result = readStringField(m_Buffer, offset, line);
            if (result == FieldResult::Incomplete) {
                return;
            }
            if (result == FieldResult::Malformed) {
                failProtocol(QStringLiteral("IPC log string exceeds maximum length"));
                return;
            }
            m_Buffer.remove(0, offset);
            const quint64 generation = m_Generation;
            const QString text = QString::fromUtf8(line);
            Q_EMIT readLogLine(text);
            Q_EMIT readLogLineForGeneration(text, generation);
            continue;
        }

        if (code == QByteArray(kIpcMsgConnectionState, 4)) {
            if (m_Buffer.size() < 7) {
                return;
            }
            const quint8 stateValue = static_cast<quint8>(m_Buffer.at(4));
            const quint8 roleValue = static_cast<quint8>(m_Buffer.at(5));
            const quint8 presenceValue = static_cast<quint8>(m_Buffer.at(6));
            offset = 7;
            QByteArray technicalName;
            QByteArray detail;
            const auto nameResult = readStringField(m_Buffer, offset, technicalName);
            if (nameResult == FieldResult::Incomplete) {
                return;
            }
            if (nameResult == FieldResult::Malformed) {
                failProtocol(QStringLiteral("IPC technical name exceeds maximum length"));
                return;
            }
            const auto detailResult = readStringField(m_Buffer, offset, detail);
            if (detailResult == FieldResult::Incomplete) {
                return;
            }
            if (detailResult == FieldResult::Malformed) {
                failProtocol(QStringLiteral("IPC detail exceeds maximum length"));
                return;
            }

            m_Buffer.remove(0, offset);
            const bool validEnums = stateValue <= static_cast<quint8>(IpcConnectionState::Disconnected)
                && roleValue <= static_cast<quint8>(IpcConnectionRole::ServerPeer)
                && presenceValue <= static_cast<quint8>(IpcIdentityPresence::LegacyUnavailable);
            const bool legacy = presenceValue == static_cast<quint8>(IpcIdentityPresence::LegacyUnavailable);
            const bool validIdentity = legacy ? technicalName.isEmpty() : !technicalName.isEmpty();
            if (!validEnums || !validIdentity) {
                failProtocol(QStringLiteral("IPC connection state contains invalid values"));
                return;
            }

            const auto state = static_cast<IpcConnectionState>(stateValue);
            const auto role = static_cast<IpcConnectionRole>(roleValue);
            const QString name = QString::fromUtf8(technicalName);
            const QString stateDetail = QString::fromUtf8(detail);
            const auto presence = static_cast<IpcIdentityPresence>(presenceValue);
            const quint64 generation = m_Generation;
            Q_EMIT readConnectionState(state, role, name, stateDetail, presence);
            Q_EMIT readConnectionStateForGeneration(
                state, role, name, stateDetail, presence, generation);
            continue;
        }

        // Unknown messages have no negotiated length. Fail closed rather than guessing a
        // delimiter and risking false synchronization with attacker-controlled payload bytes.
        failProtocol(QStringLiteral("Unknown IPC message type"));
        return;
    }
}

void IpcReader::failProtocol(const QString& detail)
{
    m_Buffer.clear();
    if (m_Socket != nullptr) {
        m_Socket->abort();
    }
    Q_EMIT protocolError(detail);
}
