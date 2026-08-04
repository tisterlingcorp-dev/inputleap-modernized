/*
 * InputLeap -- mouse and keyboard sharing utility
 */
#include "DeviceConnectionModel.h"

DeviceConnectionModel::DeviceConnectionModel(QObject* parent) : QObject(parent)
{
}

DeviceConnectionModel::TransitionResult DeviceConnectionModel::setState(
    const QUuid& uuid, State state, const QString& friendlyDetail, const QString& technicalDetail,
    const QDateTime& observedAt, Direction direction)
{
    return applyState(uuid, state, friendlyDetail, technicalDetail, observedAt, false, direction);
}

DeviceConnectionModel::TransitionResult DeviceConnectionModel::synchronizeState(
    const QUuid& uuid, State state, const QString& friendlyDetail, const QString& technicalDetail,
    const QDateTime& observedAt, Direction direction)
{
    return applyState(uuid, state, friendlyDetail, technicalDetail, observedAt, true, direction);
}

DeviceConnectionModel::TransitionResult DeviceConnectionModel::applyState(
    const QUuid& uuid, State state, const QString& friendlyDetail, const QString& technicalDetail,
    const QDateTime& observedAt, bool authoritative, Direction direction)
{
    if (uuid.isNull()) {
        return TransitionResult::Rejected;
    }

    const QDateTime observation = observedAt.isValid() ? observedAt : QDateTime::currentDateTimeUtc();
    auto it = states_.find(uuid);
    if (it == states_.end()) {
        Snapshot initial;
        initial.uuid = uuid;
        initial.lastChanged = observation;
        initial.lastObserved = observation;
        it = states_.insert(uuid, initial);
    }
    else if (observation > it->lastObserved) {
        it->lastObserved = observation;
    }

    if (it->state == state && it->friendlyDetail == friendlyDetail &&
        it->technicalDetail == technicalDetail && it->direction == direction) {
        return TransitionResult::Unchanged;
    }
    if (!authoritative && it->state != state && !isValidTransition(it->state, state)) {
        return TransitionResult::Rejected;
    }

    it->state = state;
    it->friendlyDetail = friendlyDetail;
    it->technicalDetail = technicalDetail;
    it->direction = direction;
    it->lastChanged = observation;
    Q_EMIT deviceChanged(uuid);
    return TransitionResult::Accepted;
}

std::optional<DeviceConnectionModel::Snapshot> DeviceConnectionModel::snapshot(const QUuid& uuid) const
{
    const auto it = states_.constFind(uuid);
    if (uuid.isNull() || it == states_.cend()) {
        return std::nullopt;
    }
    return *it;
}

QList<DeviceConnectionModel::Snapshot> DeviceConnectionModel::snapshots() const
{
    return states_.values();
}

bool DeviceConnectionModel::remove(const QUuid& uuid)
{
    if (uuid.isNull() || states_.remove(uuid) == 0) {
        return false;
    }
    Q_EMIT deviceRemoved(uuid);
    return true;
}

int DeviceConnectionModel::removeExpired(const QDateTime& cutoff)
{
    if (!cutoff.isValid()) {
        return 0;
    }

    QList<QUuid> expired;
    for (auto it = states_.cbegin(); it != states_.cend(); ++it) {
        // Active connections are authoritative core state. They live until a
        // core event changes them; discovery silence alone must not expire them.
        if (it->state != State::Connected && it->state != State::Controlling && it->state != State::Transferring &&
            it->lastObserved < cutoff) {
            expired.append(it.key());
        }
    }
    for (const auto& uuid : expired) {
        remove(uuid);
    }
    return expired.size();
}

void DeviceConnectionModel::clear()
{
    const QList<QUuid> uuids = states_.keys();
    states_.clear();
    for (const auto& uuid : uuids) {
        Q_EMIT deviceRemoved(uuid);
    }
}

bool DeviceConnectionModel::isValidTransition(State from, State to)
{
    if (to == State::Offline) {
        return true;
    }

    switch (from) {
    case State::Offline:
        return to == State::Available || to == State::Connecting ||
               to == State::Incompatible || to == State::Error;
    case State::Available:
        return to == State::Connecting || to == State::Incompatible || to == State::Error;
    case State::Connecting:
        return to == State::Available || to == State::Connected ||
               to == State::Incompatible || to == State::Error;
    case State::Connected:
    case State::Controlling:
        return to == State::Available || to == State::Connected || to == State::Controlling || to == State::Transferring || to == State::Error;
    case State::Transferring:
        return to == State::Connected || to == State::Controlling || to == State::Error;
    case State::Incompatible:
    case State::Error:
        return to == State::Available;
    }
    return false;
}
