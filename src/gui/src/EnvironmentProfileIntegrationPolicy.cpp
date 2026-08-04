/* InputLeap -- environment profile integration state and permission policy. */
#include "EnvironmentProfileIntegrationPolicy.h"

#include "EnvironmentProfile.h"

EnvironmentProfileIntegrationPolicy::EnvironmentProfileIntegrationPolicy() :
    owner_thread_(QThread::currentThread())
{
}

bool EnvironmentProfileIntegrationPolicy::onOwnerThread() const
{
    return QThread::currentThread() == owner_thread_;
}

bool EnvironmentProfileIntegrationPolicy::beginProcessTransition()
{
    if (!onOwnerThread()) return false;
    process_transition_busy_ = true;
    return true;
}

bool EnvironmentProfileIntegrationPolicy::completeProcessTransition()
{
    if (!onOwnerThread()) return false;
    process_transition_busy_ = false;
    return true;
}

bool EnvironmentProfileIntegrationPolicy::transferStarted(const QUuid& uuid)
{
    if (!onOwnerThread()) return false;
    ++transfer_counts_[uuid];
    ++total_transfers_;
    return true;
}

bool EnvironmentProfileIntegrationPolicy::transferFinished(const QUuid& uuid)
{
    if (!onOwnerThread()) return false;
    auto it = transfer_counts_.find(uuid);
    if (it == transfer_counts_.end() || *it <= 0 || total_transfers_ <= 0) return false;
    --(*it);
    --total_transfers_;
    if (*it == 0) transfer_counts_.erase(it);
    return true;
}

int EnvironmentProfileIntegrationPolicy::transferCount(const QUuid& uuid) const
{
    return transfer_counts_.value(uuid, 0);
}

QSet<QUuid> EnvironmentProfileIntegrationPolicy::activeTransferUuids() const
{
    QSet<QUuid> result;
    for (auto it = transfer_counts_.cbegin(); it != transfer_counts_.cend(); ++it) {
        if (it.value() > 0) result.insert(it.key());
    }
    return result;
}

bool EnvironmentProfileIntegrationPolicy::busy(bool expectedStarted, bool receiving) const
{
    return process_transition_busy_ || expectedStarted || receiving || total_transfers_ > 0;
}

bool EnvironmentProfileIntegrationPolicy::deviceAllows(
    DevicePermissions::Permission permission,
    const Gate& profileGate,
    const Gate& globalGate)
{
    const auto raw = static_cast<DevicePermissions::Mask>(permission);
    const bool exactlyOneBit = raw != 0 && (raw & (raw - 1)) == 0;
    const auto known = EnvironmentProfile::ManagedResources |
                       static_cast<DevicePermissions::Mask>(DevicePermissions::OpenSafeFiles);
    if (!exactlyOneBit || (raw & known) == 0 || (raw & ~known) != 0) return false;

    if ((raw & EnvironmentProfile::ManagedResources) != 0) {
        if (!profileGate || !profileGate()) return false;
    }
    return globalGate && globalGate();
}
