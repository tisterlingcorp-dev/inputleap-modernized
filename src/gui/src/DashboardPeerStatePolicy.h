#pragma once

#include "DeviceConnectionModel.h"

class DashboardPeerStatePolicy
{
public:
    struct Snapshot {
        // Aggregate precedence: Transferring > Connected > Connecting/Available > Offline.
        // Error and Incompatible are peer-local and aggregate as Offline.
        DeviceConnectionModel::State aggregate = DeviceConnectionModel::State::Offline;
        QUuid selected;
    };

    static Snapshot evaluate(const QList<DeviceConnectionModel::Snapshot>& peers,
                             const QUuid& currentSelection,
                             const QUuid& eventPeer = {},
                             DeviceConnectionModel::State legacyState =
                                 DeviceConnectionModel::State::Offline);
};
