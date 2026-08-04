#pragma once

#include <QString>
#include <QUuid>
#include <functional>

class QSettings;

struct LocalDeviceIdentityResult {
    bool ok = false;
    QUuid uuid;
    QString detail;
};

class LocalDeviceIdentity {
public:
    using SyncFunction = std::function<bool(QSettings&)>;
    static LocalDeviceIdentityResult loadExisting(QSettings& settings);
    static LocalDeviceIdentityResult loadOrCreate(QSettings& settings, SyncFunction sync = {});
};
