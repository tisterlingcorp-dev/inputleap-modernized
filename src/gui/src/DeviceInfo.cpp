/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#include "DeviceInfo.h"

DeviceInfo::DeviceInfo(const QUuid& uuid) : uuid_(uuid) {}

bool DeviceInfo::isValid() const { return !uuid_.isNull(); }

const QUuid& DeviceInfo::uuid() const { return uuid_; }
const QString& DeviceInfo::technicalName() const { return technicalName_; }
const QString& DeviceInfo::localAlias() const { return localAlias_; }
const QString& DeviceInfo::operatingSystem() const { return operatingSystem_; }
const QStringList& DeviceInfo::ipAddresses() const { return ipAddresses_; }
const QString& DeviceInfo::version() const { return version_; }
const QStringList& DeviceInfo::capabilities() const { return capabilities_; }
DeviceInfo::TrustState DeviceInfo::trustState() const { return trustState_; }
const QDateTime& DeviceInfo::lastSeen() const { return lastSeen_; }

void DeviceInfo::setTechnicalName(const QString& value) { technicalName_ = value; }
void DeviceInfo::setLocalAlias(const QString& value) { localAlias_ = value; }
void DeviceInfo::setOperatingSystem(const QString& value) { operatingSystem_ = value; }
void DeviceInfo::setIpAddresses(const QStringList& value) { ipAddresses_ = value; }
void DeviceInfo::setVersion(const QString& value) { version_ = value; }
void DeviceInfo::setCapabilities(const QStringList& value) { capabilities_ = value; }
void DeviceInfo::setTrustState(TrustState value)
{
    const int raw = static_cast<int>(value);
    trustState_ = raw >= static_cast<int>(TrustState::Unknown) &&
                          raw <= static_cast<int>(TrustState::Trusted)
                      ? value
                      : TrustState::Unknown;
}
void DeviceInfo::setLastSeen(const QDateTime& value) { lastSeen_ = value; }
