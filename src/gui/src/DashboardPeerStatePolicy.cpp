#include "DashboardPeerStatePolicy.h"

namespace {
bool isState(const QList<DeviceConnectionModel::Snapshot>& peers, const QUuid& uuid,
             DeviceConnectionModel::State state)
{
    for (const auto& peer : peers) {
        if (peer.uuid == uuid && peer.state == state) return true;
    }
    return false;
}

QUuid firstInState(const QList<DeviceConnectionModel::Snapshot>& peers,
                   DeviceConnectionModel::State state, const QUuid& preferred)
{
    if (isState(peers, preferred, state)) return preferred;
    for (const auto& peer : peers) {
        if (peer.state == state) return peer.uuid;
    }
    return {};
}
}

DashboardPeerStatePolicy::Snapshot DashboardPeerStatePolicy::evaluate(
    const QList<DeviceConnectionModel::Snapshot>& peers,
    const QUuid& currentSelection, const QUuid& eventPeer,
    DeviceConnectionModel::State legacyState)
{
    Snapshot result;

    result.selected = firstInState(peers, DeviceConnectionModel::State::Transferring,
                                   isState(peers, currentSelection, DeviceConnectionModel::State::Transferring)
                                       ? currentSelection : eventPeer);
    if (!result.selected.isNull()) {
        result.aggregate = DeviceConnectionModel::State::Transferring;
        return result;
    }

    result.selected = firstInState(peers, DeviceConnectionModel::State::Connected,
                                   currentSelection);
    if (!result.selected.isNull()) {
        result.aggregate = DeviceConnectionModel::State::Connected;
        return result;
    }

    // Legacy peers can report a real aggregate connection without a stable
    // identity. They never replace or disconnect a known active peer.
    if (legacyState == DeviceConnectionModel::State::Connected ||
        legacyState == DeviceConnectionModel::State::Transferring) {
        result.aggregate = legacyState;
        return result;
    }

    const auto connecting = firstInState(peers, DeviceConnectionModel::State::Connecting,
                                         eventPeer);
    const auto available = firstInState(peers, DeviceConnectionModel::State::Available,
                                        eventPeer);
    if (!connecting.isNull() || !available.isNull()) {
        result.aggregate = !connecting.isNull() ? DeviceConnectionModel::State::Connecting
                                                : DeviceConnectionModel::State::Available;
        if (isState(peers, currentSelection, DeviceConnectionModel::State::Connecting) ||
            isState(peers, currentSelection, DeviceConnectionModel::State::Available)) {
            result.selected = currentSelection;
        } else if (!eventPeer.isNull() &&
                   (isState(peers, eventPeer, DeviceConnectionModel::State::Connecting) ||
                    isState(peers, eventPeer, DeviceConnectionModel::State::Available))) {
            result.selected = eventPeer;
        } else {
            result.selected = !connecting.isNull() ? connecting : available;
        }
    } else if (legacyState == DeviceConnectionModel::State::Available ||
               legacyState == DeviceConnectionModel::State::Connecting) {
        result.aggregate = legacyState;
    }
    return result;
}
