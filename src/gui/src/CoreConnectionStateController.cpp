#include "CoreConnectionStateController.h"

CoreConnectionStateController::CoreConnectionStateController(DeviceRegistry& registry, DeviceConnectionModel& model) : registry_(registry), model_(model) {}

CoreConnectionStateController::Result CoreConnectionStateController::apply(IpcConnectionState state, const QString& technicalName, const QString& detail)
{
    const auto resolved = registry_.resolveOrCreateByTechnicalName(technicalName);
    if (resolved.status == DeviceRegistry::ResolveStatus::Rejected || resolved.status == DeviceRegistry::ResolveStatus::PersistenceError)
        return {Status::RegistryError, {}};
    DeviceConnectionModel::State mapped = DeviceConnectionModel::State::Offline;
    if (state == IpcConnectionState::Available) mapped = DeviceConnectionModel::State::Available;
    else if (state == IpcConnectionState::Connected) mapped = DeviceConnectionModel::State::Connected;
    else if (discovered_.contains(technicalName)) mapped = DeviceConnectionModel::State::Available;
    model_.synchronizeState(resolved.uuid, mapped, detail, detail);
    return {Status::Applied, resolved.uuid};
}

CoreConnectionStateController::Result CoreConnectionStateController::apply(
    IpcConnectionState state, IpcConnectionRole role, const QString& technicalName, const QString& detail)
{
    const auto resolved = registry_.resolveOrCreateByTechnicalName(technicalName);
    if (resolved.status == DeviceRegistry::ResolveStatus::Rejected || resolved.status == DeviceRegistry::ResolveStatus::PersistenceError)
        return {Status::RegistryError, {}};
    DeviceConnectionModel::State mapped = DeviceConnectionModel::State::Offline;
    DeviceConnectionModel::Direction direction = DeviceConnectionModel::Direction::Unknown;
    if (state == IpcConnectionState::Available) mapped = DeviceConnectionModel::State::Available;
    else if (state == IpcConnectionState::Connected) {
        if (role == IpcConnectionRole::ServerPeer) { mapped = DeviceConnectionModel::State::Connected; direction = DeviceConnectionModel::Direction::LocalControlsRemote; }
        else { mapped = DeviceConnectionModel::State::Connected; direction = DeviceConnectionModel::Direction::RemoteControlsLocal; }
    } else if (discovered_.contains(technicalName)) mapped = DeviceConnectionModel::State::Available;
    model_.synchronizeState(resolved.uuid, mapped, detail, detail, {}, direction);
    return {Status::Applied, resolved.uuid};
}

CoreConnectionStateController::Result CoreConnectionStateController::applyLegacy(IpcConnectionState, const QString&)
{
    return {Status::LegacyUnavailable, {}};
}

void CoreConnectionStateController::setDiscovered(const QString& technicalName, bool discovered)
{
    if (technicalName.isEmpty()) return;
    if (discovered) discovered_.insert(technicalName); else discovered_.remove(technicalName);
}
