#pragma once

#include <QDateTime>
#include <QList>
#include <QSet>
#include <QString>
#include <QUuid>

#include <functional>
#include <optional>

class TransferQueue
{
public:
    enum class State { Pending, Running, Paused, Completed, FailedRetryable, FailedTerminal, Cancelled, Skipped };
    enum class LoadResult { Missing, Loaded, Corrupt, Unsupported };

    struct Source {
        QString sourcePath;
        QString relativePath;
        bool operator==(const Source&) const = default;
    };

    struct Item {
        QByteArray transferId;
        QByteArray batchId;
        quint32 batchIndex=0;
        quint32 batchCount=1;
        QUuid peerUuid;
        QString displayName;
        QList<Source> sources;
        State state = State::Pending;
        bool userEnqueued = false;
        quint64 confirmedBytes = 0;
        int attempts = 0;
        quint64 generation = 0;
        QDateTime createdAtUtc;
        QDateTime updatedAtUtc;
    };

    explicit TransferQueue(QString storePath);

    static QByteArray newTransferId();
    static QString stateName(State state);
    static std::optional<State> parseState(const QString& value);

    const QString& storePath() const { return storePath_; }
    const QList<Item>& items() const { return items_; }
    void disablePersistence() noexcept { persistenceEnabled_ = false; }
    bool persistenceEnabled() const noexcept { return persistenceEnabled_; }
    std::optional<Item> find(const QByteArray& transferId) const;

    bool enqueue(const Item& item, QString* error = nullptr);
    bool enqueueMany(const QList<Item>& items, QString* error = nullptr);
    bool pause(const QByteArray& transferId, QString* error = nullptr);
    bool continueItem(const QByteArray& transferId, QString* error = nullptr);
    bool cancel(const QByteArray& transferId, QString* error = nullptr);
    std::optional<QByteArray> repeat(const QByteArray& transferId, QString* error = nullptr);
    bool markRunning(const QByteArray& transferId, quint64* generation, QString* error = nullptr);
    bool finish(const QByteArray& transferId, quint64 generation, State result, QString* error = nullptr);
    std::optional<Item> nextEligible(const std::function<bool(const Item&)>& eligible) const;
    std::optional<Item> nextEligibleConcurrent(const std::function<bool(const Item&)>& eligible) const;

    bool save(QString* error = nullptr) const;
    LoadResult load(QString* error = nullptr);

private:
    static bool validItem(const Item& item, QString* error = nullptr);
    Item* mutableItem(const QByteArray& transferId);
    bool persistMutation(QString* error);

    QString storePath_;
    QList<Item> items_;
    bool persistenceEnabled_ = true;
};
