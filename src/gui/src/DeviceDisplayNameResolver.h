#pragma once
#include <QString>
#include <QUuid>
class DeviceRegistry;

class DeviceDisplayNameResolver {
public:
    explicit DeviceDisplayNameResolver(const DeviceRegistry& registry) : registry_(registry) {}
    QString resolve(const QUuid& uuid, const QString& technicalFallback) const;
private:
    const DeviceRegistry& registry_;
};
