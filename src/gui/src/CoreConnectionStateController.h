#pragma once
#include "DeviceConnectionModel.h"
#include "DeviceRegistry.h"
#include "Ipc.h"
#include <QSet>

class CoreConnectionStateController
{
public:
    enum class Status { Applied, LegacyUnavailable, RegistryError };
    struct Result { Status status; QUuid uuid; };
    CoreConnectionStateController(DeviceRegistry& registry, DeviceConnectionModel& model);
    Result apply(IpcConnectionState state, const QString& technicalName, const QString& detail);
    Result apply(IpcConnectionState state, IpcConnectionRole role,
                 const QString& technicalName, const QString& detail);
    Result applyLegacy(IpcConnectionState state, const QString& detail);
    void setDiscovered(const QString& technicalName, bool discovered);
    static bool logLineCanChangeState(const QString&) { return false; }
private:
    DeviceRegistry& registry_;
    DeviceConnectionModel& model_;
    QSet<QString> discovered_;
};
