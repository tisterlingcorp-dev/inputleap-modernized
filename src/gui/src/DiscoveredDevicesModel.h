#pragma once

#include "DeviceConnectionModel.h"
#include "ZeroconfMetadata.h"
#include "DeviceRegistry.h"
#include <QObject>
#include <QHash>
#include <optional>

class DeviceRegistry;

struct DiscoveredDeviceView {
    QUuid uuid;
    QString displayName;
    QString technicalName;
    QString friendlyName;
    QString operatingSystem;
    QString version;
    QSet<QString> addresses;
    QSet<ZeroconfCapability> capabilities;
    QSet<QString> features;
    ZeroconfRole role = ZeroconfRole::Client;
    quint16 controlPort = 0;
    quint16 transferPort = 0;
    quint16 pairingPort = 0;
    bool pairedThisSession = false;
    qint64 lastSeenMs = 0;
    QDateTime lastObserved;
    DeviceConnectionModel::Direction direction = DeviceConnectionModel::Direction::Unknown;
    DeviceConnectionModel::State state = DeviceConnectionModel::State::Available;
    bool compatible = true;
    CapabilityNegotiationSnapshot negotiation;
    bool updateAvailable = false;
    bool discoveryAvailable = true;
    bool operator==(const DiscoveredDeviceView&) const = default;
};
Q_DECLARE_METATYPE(DiscoveredDeviceView)

class DiscoveredDevicesModel : public QObject {
    Q_OBJECT
public:
    explicit DiscoveredDevicesModel(DeviceRegistry& registry, DeviceConnectionModel& connections,
                                    const QUuid& localUuid, QObject* parent=nullptr);
    bool upsert(const DiscoveredDeviceAdvertisement& advertisement);
    void remove(const DiscoveredDeviceAdvertisement& advertisement) { remove(advertisement.uuid); }
    void remove(const QUuid& uuid);
    void clearDiscovery();
    int count() const { return devices_.size(); }
    int hiddenCount() const;
    QList<DiscoveredDeviceView> devices() const;
    QList<DiscoveredDeviceView> visibleDevices() const;
    std::optional<DiscoveredDeviceView> find(const QUuid& uuid) const;
    DeviceRegistry::AliasResult setLocalAlias(const QUuid& uuid, const QString& alias);
    void setPairedThisSession(const QUuid& uuid, bool paired);
    void setUpdateTargetVersion(const QString& version);
Q_SIGNALS:
    void devicesChanged();
private:
    void connectionChanged(const QUuid& uuid);
    static int priority(DeviceConnectionModel::State state);
    DeviceRegistry& registry_;
    DeviceConnectionModel& connections_;
    QUuid localUuid_;
    QHash<QUuid, DiscoveredDeviceView> devices_;
    QString updateTargetVersion_;
};
