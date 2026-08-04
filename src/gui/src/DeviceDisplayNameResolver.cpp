#include "DeviceDisplayNameResolver.h"
#include "DeviceRegistry.h"

QString DeviceDisplayNameResolver::resolve(const QUuid& uuid, const QString& technicalFallback) const
{
    if (!uuid.isNull()) {
        const auto device = registry_.find(uuid);
        if (device) {
            if (!device->localAlias().isEmpty()) return device->localAlias();
            if (!device->technicalName().isEmpty()) return device->technicalName();
        }
    }
    return technicalFallback;
}
