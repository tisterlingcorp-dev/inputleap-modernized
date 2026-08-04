#include "TrayMenuPolicy.h"
#include "EndpointPolicy.h"

#include <QHostAddress>
#include <QHash>
#include <algorithm>

bool TrayMenuPolicy::active(DeviceConnectionModel::State state)
{
    return state == DeviceConnectionModel::State::Connected ||
           state == DeviceConnectionModel::State::Controlling ||
           state == DeviceConnectionModel::State::Transferring;
}

QString TrayMenuPolicy::usableAddress(const QSet<QString>& addresses)
{
    QStringList sorted(addresses.cbegin(), addresses.cend());
    sorted.sort(Qt::CaseInsensitive);
    for (const QString& candidate : sorted) {
        if (EndpointPolicy::isUsableUnicast(candidate))
            return candidate;
    }
    return {};
}

bool TrayMenuPolicy::transferable(const DiscoveredDeviceView& device, const QString& address)
{
    return (device.state == DeviceConnectionModel::State::Connected ||
            device.state == DeviceConnectionModel::State::Controlling) &&
           device.discoveryAvailable && device.compatible && device.negotiation.capabilityAllowed(CapabilityId::FileTransfer) && !device.uuid.isNull() &&
           device.capabilities.contains(ZeroconfCapability::FileTransfer) &&
           device.transferPort != 0 && !address.isEmpty();
}

TrayMenuPolicy::Menu TrayMenuPolicy::build(const QList<DiscoveredDeviceView>& devices)
{
    QList<DiscoveredDeviceView> eligible;
    for (const auto& device : devices) {
        if (!device.uuid.isNull() && active(device.state))
            eligible.append(device);
    }
    std::sort(eligible.begin(), eligible.end(), [](const auto& left, const auto& right) {
        const int nameOrder = QString::compare(left.displayName, right.displayName, Qt::CaseInsensitive);
        if (nameOrder != 0)
            return nameOrder < 0;
        return left.uuid.toString(QUuid::WithoutBraces) < right.uuid.toString(QUuid::WithoutBraces);
    });

    Menu menu;
    const auto visible=eligible.mid(0,MaximumPeers);
    QHash<QString,int> totals;
    for(const auto& device:visible)++totals[device.displayName.toCaseFolded()];
    QHash<QString,int> ordinals;
    for (const auto& device : visible) {
        const QString address = usableAddress(device.addresses);
        const QString key=device.displayName.toCaseFolded();const int ordinal=++ordinals[key];
        const QString label=totals.value(key)>1?QStringLiteral("%1 (%2)").arg(device.displayName).arg(ordinal):device.displayName;
        menu.peers.append({label, {device.uuid, address, device.transferPort},
                           transferable(device, address)});
    }
    return menu;
}

TrayMenuPolicy::Visibility TrayMenuPolicy::visibility(bool mainWindowVisible)
{
    return {mainWindowVisible, !mainWindowVisible};
}

std::optional<DiscoveredDeviceView> TrayMenuPolicy::resolveTarget(
    const Target& captured, const DiscoveredDeviceView& current)
{
    const QString address = usableAddress(current.addresses);
    if (current.uuid != captured.uuid || address != captured.address ||
        current.transferPort != captured.transferPort || !transferable(current, address))
        return std::nullopt;
    return current;
}
