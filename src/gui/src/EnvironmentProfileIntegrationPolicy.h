/* InputLeap -- environment profile integration state and permission policy. */
#pragma once

#include "DevicePermissions.h"

#include <QHash>
#include <QSet>
#include <QThread>
#include <QUuid>

#include <functional>

class EnvironmentProfileIntegrationPolicy
{
public:
    using Gate = std::function<bool()>;

    EnvironmentProfileIntegrationPolicy();

    bool beginProcessTransition();
    bool completeProcessTransition();
    bool processTransitionBusy() const { return process_transition_busy_; }

    bool transferStarted(const QUuid& uuid);
    bool transferFinished(const QUuid& uuid);
    int transferCount(const QUuid& uuid) const;
    bool hasActiveTransfers() const { return total_transfers_ > 0; }
    QSet<QUuid> activeTransferUuids() const;

    bool busy(bool expectedStarted, bool receiving) const;

    static bool deviceAllows(DevicePermissions::Permission permission,
                             const Gate& profileGate,
                             const Gate& globalGate);

private:
    bool onOwnerThread() const;

    QThread* owner_thread_ = nullptr;
    bool process_transition_busy_ = false;
    QHash<QUuid, int> transfer_counts_;
    int total_transfers_ = 0;
};
