#include "DiscoveredDevicesModel.h"
#include "DeviceRegistry.h"
#include <algorithm>
#include <QVersionNumber>

namespace {
QString osName(ZeroconfOsFamily os) {
    switch(os) { case ZeroconfOsFamily::Windows:return "Windows"; case ZeroconfOsFamily::MacOS:return "macOS";
    case ZeroconfOsFamily::Linux:return "Linux"; default:return QObject::tr("Outro sistema"); }
}
QStringList capabilityNames(const QSet<ZeroconfCapability>& values) {
    QStringList result; for(auto value: values) switch(value) {
    case ZeroconfCapability::Keyboard: result<<"keyboard"; break; case ZeroconfCapability::Mouse: result<<"mouse"; break;
    case ZeroconfCapability::Clipboard: result<<"clipboard"; break; case ZeroconfCapability::FileTransfer: result<<"file-transfer"; break; }
    result.sort(); return result;
}
bool sameDiscoveredFields(const DeviceInfo& current, const DeviceInfo& incoming)
{
    QStringList currentAddresses = current.ipAddresses();
    QStringList incomingAddresses = incoming.ipAddresses();
    currentAddresses.sort();
    incomingAddresses.sort();
    return current.technicalName() == incoming.technicalName() &&
           current.operatingSystem() == incoming.operatingSystem() &&
           currentAddresses == incomingAddresses &&
           current.version() == incoming.version() &&
           current.capabilities() == incoming.capabilities() &&
           current.lastSeen() == incoming.lastSeen();
}
bool needsUpdate(const QString& installed, const QString& target)
{
    const QVersionNumber installedVersion = QVersionNumber::fromString(installed);
    const QVersionNumber targetVersion = QVersionNumber::fromString(target);
    return !installedVersion.isNull() && !targetVersion.isNull() &&
        installedVersion < targetVersion;
}
}

DiscoveredDevicesModel::DiscoveredDevicesModel(DeviceRegistry& registry, DeviceConnectionModel& connections,
                                               const QUuid& localUuid, QObject* parent)
    : QObject(parent), registry_(registry), connections_(connections), localUuid_(localUuid)
{
    connect(&connections_, &DeviceConnectionModel::deviceChanged, this, &DiscoveredDevicesModel::connectionChanged);
    connect(&connections_, &DeviceConnectionModel::deviceRemoved, this, &DiscoveredDevicesModel::connectionChanged);
}

bool DiscoveredDevicesModel::upsert(const DiscoveredDeviceAdvertisement& ad)
{
    if (ad.uuid.isNull() || ad.uuid == localUuid_ || ad.metadata.uuid != ad.uuid) return false;
    DeviceInfo info(ad.uuid); info.setTechnicalName(ad.metadata.technicalName);
    QStringList addresses = ad.addresses.values(); addresses.sort();
    info.setOperatingSystem(osName(ad.metadata.osFamily)); info.setIpAddresses(addresses);
    info.setVersion(ad.metadata.inputLeapVersion); info.setCapabilities(capabilityNames(ad.metadata.capabilities));
    info.setLastSeen(QDateTime::fromMSecsSinceEpoch(ad.lastSeenMs, Qt::UTC));
    const auto before = registry_.find(ad.uuid);
    if ((!before || !sameDiscoveredFields(*before, info)) &&
        registry_.upsertDiscovered(info) == DeviceRegistry::AddResult::Error) return false;
    const auto persisted = registry_.find(ad.uuid);
    if (!persisted) return false;

    DiscoveredDeviceView next; next.uuid=ad.uuid; next.technicalName=ad.metadata.technicalName;
    next.friendlyName=ad.metadata.friendlyName; next.displayName=!persisted->localAlias().isEmpty() ? persisted->localAlias() :
        (!next.friendlyName.isEmpty() ? next.friendlyName : next.technicalName);
    next.operatingSystem=persisted->operatingSystem(); next.version=ad.metadata.inputLeapVersion;
    next.updateAvailable=needsUpdate(next.version, updateTargetVersion_);
    next.addresses=ad.addresses; next.capabilities=ad.metadata.capabilities; next.features=ad.metadata.features; next.role=ad.metadata.role;
    next.controlPort=ad.metadata.controlPort; next.transferPort=ad.metadata.transferPort;
    next.pairingPort=ad.metadata.pairingPort; next.lastSeenMs=ad.lastSeenMs;
    next.lastObserved=QDateTime::fromMSecsSinceEpoch(ad.lastSeenMs,Qt::UTC);
    CapabilityAdvertisement advertised; advertised.uuid=ad.uuid; advertised.versions=ad.metadata.protocolVersions;
    // Empty structured versions identify the documented pre-6.2 3.1.0 baseline.
    advertised.legacy=ad.metadata.protocolVersions.isEmpty(); advertised.legacyAppVersion=ad.metadata.inputLeapVersion;
    advertised.claimed.insert(CapabilityId::Control);
    if(ad.metadata.capabilities.contains(ZeroconfCapability::FileTransfer))advertised.claimed.insert(CapabilityId::FileTransfer);
    if(ad.metadata.features.contains("pairing-srp6a-v1"))advertised.claimed.insert(CapabilityId::Pairing);
    if(ad.metadata.features.contains("monitor-metadata-v1"))advertised.claimed.insert(CapabilityId::Monitor);
    next.negotiation=CapabilityNegotiationPolicy().negotiate(advertised);
    next.compatible=next.negotiation.baseConnectionAllowed();
    next.state=next.compatible ? DeviceConnectionModel::State::Available : DeviceConnectionModel::State::Incompatible;
    if (auto state=connections_.snapshot(ad.uuid)) { next.state=state->state; if(state->lastObserved>next.lastObserved)next.lastObserved=state->lastObserved; next.direction=state->direction; }
    next.discoveryAvailable=true;
    if (auto previous=devices_.constFind(ad.uuid); previous!=devices_.cend()) next.pairedThisSession=previous->pairedThisSession;
    auto old=devices_.constFind(ad.uuid); if(old!=devices_.cend() && old.value()==next) return true;
    devices_[ad.uuid]=next; emit devicesChanged(); return true;
}

void DiscoveredDevicesModel::remove(const QUuid& uuid)
{
    auto it=devices_.find(uuid); if(it==devices_.end()) return;
    const auto state=connections_.snapshot(uuid); const bool active=state &&
        (state->state==DeviceConnectionModel::State::Connected || state->state==DeviceConnectionModel::State::Controlling || state->state==DeviceConnectionModel::State::Transferring);
    if(active) { if(!it->discoveryAvailable) return; it->discoveryAvailable=false; it->state=state->state; emit devicesChanged(); }
    else { devices_.erase(it); connections_.remove(uuid); emit devicesChanged(); }
}

void DiscoveredDevicesModel::clearDiscovery()
{
    bool changed = false;
    for (auto it = devices_.begin(); it != devices_.end();) {
        const auto snapshot = connections_.snapshot(it.key());
        const bool active = snapshot &&
            (snapshot->state == DeviceConnectionModel::State::Connected || snapshot->state == DeviceConnectionModel::State::Controlling ||
             snapshot->state == DeviceConnectionModel::State::Transferring);
        if (active) {
            if (it->discoveryAvailable) {
                it->discoveryAvailable = false;
                it->state = snapshot->state;
                changed = true;
            }
            ++it;
        }
        else {
            const QUuid uuid = it.key();
            it = devices_.erase(it);
            connections_.remove(uuid);
            changed = true;
        }
    }
    if (changed) emit devicesChanged();
}

int DiscoveredDevicesModel::priority(DeviceConnectionModel::State s) {
    switch(s){ case DeviceConnectionModel::State::Transferring: return 0; case DeviceConnectionModel::State::Controlling: case DeviceConnectionModel::State::Connected:return 1;
    case DeviceConnectionModel::State::Connecting:return 2; case DeviceConnectionModel::State::Available:return 3; default:return 4; }
}
QList<DiscoveredDeviceView> DiscoveredDevicesModel::devices() const {
    auto values=devices_.values(); std::sort(values.begin(),values.end(),[](const auto&a,const auto&b){
        if(priority(a.state)!=priority(b.state)) return priority(a.state)<priority(b.state);
        if(a.lastSeenMs!=b.lastSeenMs) return a.lastSeenMs>b.lastSeenMs;
        const int names=QString::localeAwareCompare(a.displayName,b.displayName); if(names) return names<0;
        return a.uuid.toString()<b.uuid.toString(); }); return values;
}
QList<DiscoveredDeviceView> DiscoveredDevicesModel::visibleDevices() const { auto result=devices(); while(result.size()>4) result.removeLast(); return result; }
int DiscoveredDevicesModel::hiddenCount() const { return (std::max)(0,count()-4); }
std::optional<DiscoveredDeviceView> DiscoveredDevicesModel::find(const QUuid& uuid) const { auto it=devices_.constFind(uuid); return it==devices_.cend()?std::nullopt:std::optional(it.value()); }
DeviceRegistry::AliasResult DiscoveredDevicesModel::setLocalAlias(const QUuid& uuid, const QString& alias) {
    const auto result=registry_.setLocalAlias(uuid,alias); if(result!=DeviceRegistry::AliasResult::Changed)return result;
    auto it=devices_.find(uuid); if(it!=devices_.end()) { const auto saved=registry_.find(uuid); if(saved) it->displayName=saved->localAlias().isEmpty() ?
        (!it->friendlyName.isEmpty()?it->friendlyName:it->technicalName) : saved->localAlias(); }
    emit devicesChanged(); return result;
}
void DiscoveredDevicesModel::setPairedThisSession(const QUuid& uuid, bool paired) {
    auto it=devices_.find(uuid); if(it==devices_.end()||it->pairedThisSession==paired)return;
    it->pairedThisSession=paired; emit devicesChanged();
}
void DiscoveredDevicesModel::setUpdateTargetVersion(const QString& version)
{
    if (updateTargetVersion_ == version)
        return;
    updateTargetVersion_ = version;
    bool changed = false;
    for (auto it = devices_.begin(); it != devices_.end(); ++it) {
        const bool value = needsUpdate(it->version, updateTargetVersion_);
        if (it->updateAvailable != value) {
            it->updateAvailable = value;
            changed = true;
        }
    }
    if (changed)
        emit devicesChanged();
}
void DiscoveredDevicesModel::connectionChanged(const QUuid& uuid) {
    auto it=devices_.find(uuid); if(it==devices_.end()) return; auto snapshot=connections_.snapshot(uuid);
    if (!it->discoveryAvailable && (!snapshot ||
        (snapshot->state != DeviceConnectionModel::State::Connected && snapshot->state != DeviceConnectionModel::State::Controlling &&
         snapshot->state != DeviceConnectionModel::State::Transferring))) {
        devices_.erase(it);
        emit devicesChanged();
        return;
    }
    auto state=snapshot?snapshot->state:(it->compatible?DeviceConnectionModel::State::Available:DeviceConnectionModel::State::Incompatible);
    const auto direction=snapshot?snapshot->direction:DeviceConnectionModel::Direction::Unknown;
    const auto observed=snapshot&&snapshot->lastObserved>it->lastObserved?snapshot->lastObserved:it->lastObserved;
    if(it->state==state && it->direction==direction && it->lastObserved==observed)return;
    it->state=state; it->direction=direction; it->lastObserved=observed; emit devicesChanged();
}
