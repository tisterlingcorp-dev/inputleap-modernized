/*
 * InputLeap -- mouse and keyboard sharing utility
 */
#pragma once

#include <QDateTime>
#include <QHash>
#include <QObject>
#include <QString>
#include <QUuid>

#include <optional>

class DeviceConnectionModel : public QObject
{
    Q_OBJECT

public:
    enum class State {
        Offline,
        Available,
        Connecting,
        Connected,
        Controlling,
        Transferring,
        Incompatible,
        Error
    };
    Q_ENUM(State)
    enum class Direction { Unknown, LocalControlsRemote, RemoteControlsLocal };
    Q_ENUM(Direction)

    enum class TransitionResult { Accepted, Rejected, Unchanged };
    Q_ENUM(TransitionResult)

    struct Snapshot {
        QUuid uuid;
        State state = State::Offline;
        QDateTime lastChanged;
        QDateTime lastObserved;
        QString friendlyDetail;
        QString technicalDetail;
        Direction direction = Direction::Unknown;
    };

    explicit DeviceConnectionModel(QObject* parent = nullptr);

    TransitionResult setState(const QUuid& uuid,
                              State state,
                              const QString& friendlyDetail = {},
                              const QString& technicalDetail = {},
                              const QDateTime& observedAt = {},
                              Direction direction = Direction::Unknown);
    // Authoritative core events may skip discovery states after GUI startup.
    TransitionResult synchronizeState(const QUuid& uuid,
                                      State state,
                                      const QString& friendlyDetail = {},
                                      const QString& technicalDetail = {},
                                      const QDateTime& observedAt = {},
                                      Direction direction = Direction::Unknown);
    std::optional<Snapshot> snapshot(const QUuid& uuid) const;
    QList<Snapshot> snapshots() const;
    bool remove(const QUuid& uuid);
    int removeExpired(const QDateTime& cutoff);
    void clear();

Q_SIGNALS:
    void deviceChanged(const QUuid& uuid);
    void deviceRemoved(const QUuid& uuid);

private:
    static bool isValidTransition(State from, State to);
    TransitionResult applyState(const QUuid& uuid, State state,
                                const QString& friendlyDetail,
                                const QString& technicalDetail,
                                const QDateTime& observedAt,
                                bool authoritative, Direction direction);

    QHash<QUuid, Snapshot> states_;
};
