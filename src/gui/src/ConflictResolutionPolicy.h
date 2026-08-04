#pragma once

#include <QByteArray>
#include <QHash>
#include <QSet>
#include <QString>
#include <QUuid>

#include <functional>

enum class ConflictAction { Replace, Rename, Skip };

struct ConflictDecision
{
    ConflictAction action = ConflictAction::Rename;
    bool applyToAll = false;
};

struct ConflictRequest
{
    QUuid peerUuid;
    QByteArray batchId;
    QByteArray transferId;
    QString fileName;
    QString destinationPath;
    quint32 itemIndex = 0;
    quint32 itemCount = 1;
};

class ConflictResolutionPolicy
{
public:
    using Callback = std::function<ConflictDecision(const ConflictRequest&)>;

    ConflictAction resolve(const ConflictRequest& request, const Callback& callback);
    void recordNonConflict(const ConflictRequest& request);
    void completeBatch(const QUuid& peerUuid, const QByteArray& batchId, quint32 itemCount);
    void resetPeer(const QUuid& peerUuid);
    void resetAll();

private:
    struct BatchState {
        ConflictAction action = ConflictAction::Rename;
        quint32 itemCount = 0;
        quint32 lastItemIndex = 0;
        QSet<QByteArray> seenTransferIds;
    };
    static QByteArray scopeKey(const QUuid& peerUuid, const QByteArray& batchId);
    QHash<QByteArray, BatchState> batchDecisions_;
};
