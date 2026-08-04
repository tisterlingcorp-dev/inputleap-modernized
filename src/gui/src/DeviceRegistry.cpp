/*
 * InputLeap -- mouse and keyboard sharing utility
 */
#include "DeviceRegistry.h"
#include "ConfigurationTransactionLock.h"

#include <QSettings>

#include <algorithm>
#include <limits>

namespace
{
constexpr auto RegistryGroup = "deviceRegistry";
constexpr auto DevicesArray = "devices";
constexpr auto ActiveGeneration = "deviceRegistry/activeGeneration";
constexpr auto GenerationsGroup = "deviceRegistry/generations";

QString generationGroup(const QString& id)
{
    return QString(GenerationsGroup) + '/' + id;
}

bool readStrictInt(const QSettings& settings, const QString& key, int& result)
{
    const QVariant value = settings.value(key);
    if (value.metaType().id() == QMetaType::Int) {
        result = value.toInt();
        return true;
    }
    if (value.metaType().id() != QMetaType::LongLong) return false;
    const qlonglong integer = value.toLongLong();
    if (integer < std::numeric_limits<int>::min() || integer > std::numeric_limits<int>::max()) return false;
    result = static_cast<int>(integer);
    return true;
}
}

DeviceRegistry::DeviceRegistry(QSettings& settings, SyncFunction sync,
                               PersistenceMode persistenceMode) :
    settings_(settings),
    sync_(sync ? std::move(sync) : [](QSettings& value) {
        value.sync();
        return value.status() == QSettings::NoError;
    }),
    persistenceMode_(persistenceMode)
{
    load();
}

bool DeviceRegistry::mutationsAllowed() const
{
    return persistenceMode_ == PersistenceMode::Enabled &&
        loadStatus_ == LoadStatus::Loaded && saveStatus_ != SaveStatus::Error;
}

bool DeviceRegistry::enablePersistence()
{
    const std::lock_guard lock(mutex_);
    if (persistenceMode_ == PersistenceMode::Enabled)
        return mutationsAllowed();
    if (loadStatus_ != LoadStatus::Loaded || saveStatus_ == SaveStatus::Error)
        return false;
    persistenceMode_ = PersistenceMode::Enabled;
    if (!settings_.contains(QString(RegistryGroup) + "/schemaVersion") &&
        save() != SaveResult::Success) {
        persistenceMode_ = PersistenceMode::ReadOnly;
        return false;
    }
    return true;
}

void DeviceRegistry::disablePersistence()
{
    const std::lock_guard lock(mutex_);
    persistenceMode_ = PersistenceMode::ReadOnly;
}

bool DeviceRegistry::sync() { return sync_(settings_); }
void DeviceRegistry::markSaveError() { saveStatus_ = SaveStatus::Error; }

int DeviceRegistry::indexOf(const QUuid& uuid) const
{
    for (int i = 0; i < devices_.size(); ++i) {
        if (devices_.at(i).uuid() == uuid) return i;
    }
    return -1;
}

QUuid DeviceRegistry::create(const QString& technicalName)
{
    const std::lock_guard lock(mutex_);
    if (!mutationsAllowed()) return {};
    const QUuid uuid = QUuid::createUuid();
    DeviceInfo device(uuid);
    device.setTechnicalName(technicalName);
    devices_.append(device);
    return uuid;
}

DeviceRegistry::ResolveResult DeviceRegistry::resolveOrCreateByTechnicalName(const QString& technicalName)
{
    const std::lock_guard lock(mutex_);
    if (technicalName.isEmpty()) return {ResolveStatus::Rejected, {}};
    const auto existing = std::find_if(devices_.cbegin(), devices_.cend(), [&](const DeviceInfo& device) {
        return device.technicalName() == technicalName;
    });
    if (existing != devices_.cend()) return {ResolveStatus::Found, existing->uuid()};
    if (!mutationsAllowed()) return {ResolveStatus::PersistenceError, {}};
    const QList<DeviceInfo> before = devices_;
    DeviceInfo device(QUuid::createUuid());
    device.setTechnicalName(technicalName);
    devices_.append(device);
    if (save() != SaveResult::Success) {
        devices_ = before;
        return {ResolveStatus::PersistenceError, {}};
    }
    return {ResolveStatus::Created, device.uuid()};
}

DeviceRegistry::AddResult DeviceRegistry::add(const DeviceInfo& device)
{
    const std::lock_guard lock(mutex_);
    if (!mutationsAllowed()) return AddResult::Error;
    if (!device.isValid()) return AddResult::Rejected;
    const int existingIndex = indexOf(device.uuid());
    if (existingIndex < 0) {
        devices_.append(device);
        return AddResult::Added;
    }

    DeviceInfo merged = device;
    merged.setLocalAlias(devices_.at(existingIndex).localAlias());
    merged.setTrustState(devices_.at(existingIndex).trustState());
    devices_[existingIndex] = merged;
    return AddResult::Merged;
}

DeviceRegistry::AddResult DeviceRegistry::upsertDiscovered(const DeviceInfo& device)
{
    const std::lock_guard lock(mutex_);
    if (!mutationsAllowed() || !device.isValid())
        return device.isValid() ? AddResult::Error : AddResult::Rejected;
    const QList<DeviceInfo> before = devices_;
    const AddResult result = add(device);
    if (result == AddResult::Error || result == AddResult::Rejected) return result;
    if (save() != SaveResult::Success) {
        devices_ = before;
        return AddResult::Error;
    }
    return result;
}

std::optional<DeviceInfo> DeviceRegistry::find(const QUuid& uuid) const
{
    const std::lock_guard lock(mutex_);
    const int index = indexOf(uuid);
    if (index < 0) return std::nullopt;
    return devices_.at(index);
}

bool DeviceRegistry::update(const DeviceInfo& device)
{
    const std::lock_guard lock(mutex_);
    if (!mutationsAllowed() || !device.isValid()) return false;
    const int index = indexOf(device.uuid());
    if (index < 0) return false;
    devices_[index] = device;
    return true;
}

bool DeviceRegistry::remove(const QUuid& uuid)
{
    const std::lock_guard lock(mutex_);
    if (!mutationsAllowed()) return false;
    const int index = indexOf(uuid);
    if (index < 0) return false;
    devices_.removeAt(index);
    return true;
}

bool DeviceRegistry::isValidLocalAlias(const QString& alias, QString* normalized)
{
    const QString value = alias.trimmed();
    int scalarCount = 0;
    const auto blockedCategory = [](QChar::Category category) {
        return category == QChar::Other_Control || category == QChar::Other_Format ||
               category == QChar::Separator_Line || category == QChar::Separator_Paragraph;
    };
    for (qsizetype i = 0; i < value.size(); ++i) {
        const QChar character = value.at(i);
        if (character.isHighSurrogate()) {
            if (i + 1 >= value.size() || !value.at(i + 1).isLowSurrogate()) return false;
            const char32_t codePoint = QChar::surrogateToUcs4(character, value.at(i + 1));
            if (blockedCategory(QChar::category(codePoint))) return false;
            ++i;
        }
        else if (character.isLowSurrogate() || blockedCategory(character.category())) return false;
        ++scalarCount;
    }
    if (scalarCount > 96 || value.toUtf8().size() > 192) return false;
    if (normalized) *normalized = value;
    return true;
}

DeviceRegistry::AliasResult DeviceRegistry::setLocalAlias(const QUuid& uuid, const QString& alias)
{
    const std::lock_guard lock(mutex_);
    QString normalized;
    if (!isValidLocalAlias(alias, &normalized)) return AliasResult::InvalidAlias;
    const int index = indexOf(uuid);
    if (index < 0) return AliasResult::UnknownDevice;
    if (!mutationsAllowed()) return AliasResult::PersistenceError;
    if (devices_.at(index).localAlias() == normalized) return AliasResult::Unchanged;
    const QList<DeviceInfo> before = devices_;
    devices_[index].setLocalAlias(normalized);
    if (save() != SaveResult::Success) { devices_ = before; return AliasResult::PersistenceError; }
    return AliasResult::Changed;
}

QList<DeviceInfo> DeviceRegistry::devices() const
{
    const std::lock_guard lock(mutex_);
    return devices_;
}
DevicePermissions::Mask DeviceRegistry::permissions(const QUuid& uuid) const
{
    const std::lock_guard lock(mutex_);
    return find(uuid).has_value() ? permissions_.forDevice(uuid) : DevicePermissions::defaults();
}

bool DeviceRegistry::allows(const QUuid& uuid, DevicePermissions::Permission permission) const
{
    const std::lock_guard lock(mutex_);
    return find(uuid).has_value() && permissions_.allows(uuid, permission);
}

bool DeviceRegistry::setPermissions(const QUuid& uuid, DevicePermissions::Mask mask)
{
    const std::lock_guard lock(mutex_);
    if (!mutationsAllowed() || !find(uuid).has_value()) return false;
    const DevicePermissions before = permissions_;
    if (!permissions_.set(uuid, mask)) return false;
    if (save() != SaveResult::Success) { permissions_ = before; return false; }
    return true;
}

bool DeviceRegistry::revokePermission(const QUuid& uuid, DevicePermissions::Permission permission)
{
    const std::lock_guard lock(mutex_);
    if (!mutationsAllowed() || !find(uuid).has_value()) return false;
    const DevicePermissions before = permissions_;
    if (!permissions_.revoke(uuid, permission)) return false;
    if (save() != SaveResult::Success) { permissions_ = before; return false; }
    return true;
}
DeviceRegistry::LoadStatus DeviceRegistry::loadStatus() const
{
    const std::lock_guard lock(mutex_);
    return loadStatus_;
}
DeviceRegistry::SaveStatus DeviceRegistry::saveStatus() const
{
    const std::lock_guard lock(mutex_);
    return saveStatus_;
}

bool DeviceRegistry::readRegistry(const QString& group, QList<DeviceInfo>& devices, bool requireValidSize) const
{
    devices.clear();
    const QString sizeKey = group + '/' + DevicesArray + "/size";
    int storedSize = 0;
    const bool sizeOk = readStrictInt(settings_, sizeKey, storedSize);
    if (requireValidSize && (!settings_.contains(sizeKey) || !sizeOk || storedSize < 0)) return false;

    settings_.beginGroup(group);
    const int count = settings_.beginReadArray(DevicesArray);
    if (requireValidSize && count != storedSize) {
        settings_.endArray(); settings_.endGroup();
        return false;
    }
    for (int index = 0; index < count; ++index) {
        settings_.setArrayIndex(index);
        DeviceInfo device(QUuid(settings_.value("uuid").toString()));
        if (!device.isValid()) continue;
        device.setTechnicalName(settings_.value("technicalName").toString());
        device.setLocalAlias(settings_.value("localAlias").toString());
        device.setOperatingSystem(settings_.value("operatingSystem").toString());
        device.setIpAddresses(settings_.value("ipAddresses").toStringList());
        device.setVersion(settings_.value("version").toString());
        device.setCapabilities(settings_.value("capabilities").toStringList());
        device.setTrustState(static_cast<DeviceInfo::TrustState>(settings_.value("trustState").toInt()));
        device.setLastSeen(settings_.value("lastSeen").toDateTime());
        const QString permissionValue = settings_.value("permissions").toString();
        if (!permissionValue.isEmpty()) permissions_.deserialize(device.uuid(), permissionValue);
        const auto existing = std::find_if(devices.begin(), devices.end(), [&](const DeviceInfo& value) {
            return value.uuid() == device.uuid();
        });
        if (existing == devices.end()) devices.append(device);
        else {
            const QString alias = existing->localAlias();
            const DeviceInfo::TrustState trust = existing->trustState();
            *existing = device;
            existing->setLocalAlias(alias);
            existing->setTrustState(trust);
        }
    }
    settings_.endArray();
    settings_.endGroup();
    return settings_.status() == QSettings::NoError;
}

bool DeviceRegistry::registryMatches(const QString& group, const QList<DeviceInfo>& expected) const
{
    QList<DeviceInfo> actual;
    if (!readRegistry(group, actual, true) || actual.size() != expected.size()) return false;
    for (int i = 0; i < expected.size(); ++i) {
        const DeviceInfo& a = actual.at(i); const DeviceInfo& e = expected.at(i);
        if (a.uuid() != e.uuid() || a.technicalName() != e.technicalName() ||
            a.localAlias() != e.localAlias() || a.operatingSystem() != e.operatingSystem() ||
            a.ipAddresses() != e.ipAddresses() || a.version() != e.version() ||
            a.capabilities() != e.capabilities() || a.trustState() != e.trustState() ||
            a.lastSeen() != e.lastSeen()) return false;
    }
    return true;
}

DeviceRegistry::LoadStatus DeviceRegistry::load()
{
    const std::lock_guard lock(mutex_);
    settings_.sync();
    saveStatus_ = SaveStatus::NotAttempted;
    loadedGeneration_.clear();
    devices_.clear();
    permissions_ = DevicePermissions{};
    if (settings_.status() != QSettings::NoError)
        return loadStatus_ = LoadStatus::SettingsError;

    const QString rootSchemaKey = QString(RegistryGroup) + "/schemaVersion";
    const bool hasRootSchema = settings_.contains(rootSchemaKey);
    int rootSchema = 0;
    if (hasRootSchema) {
        if (!readStrictInt(settings_, rootSchemaKey, rootSchema) || rootSchema <= 0)
            return loadStatus_ = LoadStatus::InvalidSchema;
        if (rootSchema > SchemaVersion) return loadStatus_ = LoadStatus::FutureSchema;
        if (rootSchema != SchemaVersion) return loadStatus_ = LoadStatus::InvalidSchema;
    }

    const QString active = settings_.value(ActiveGeneration).toString();
    const QString source = active.isEmpty() ? QString(RegistryGroup) : generationGroup(active);
    const QString schemaKey = source + "/schemaVersion";
    if (!active.isEmpty()) {
        if (!settings_.contains(schemaKey)) return loadStatus_ = LoadStatus::InvalidSchema;
        int schema = 0;
        if (!readStrictInt(settings_, schemaKey, schema) || schema <= 0 || (hasRootSchema && schema != rootSchema))
            return loadStatus_ = LoadStatus::InvalidSchema;
        if (schema > SchemaVersion) return loadStatus_ = LoadStatus::FutureSchema;
        if (schema != SchemaVersion) return loadStatus_ = LoadStatus::InvalidSchema;
    }

    loadStatus_ = LoadStatus::Loaded;
    QList<DeviceInfo> loaded;
    if (!readRegistry(source, loaded, !active.isEmpty()))
        return loadStatus_ = active.isEmpty() ? LoadStatus::SettingsError : LoadStatus::InvalidSchema;
    devices_ = loaded;
    loadedGeneration_ = active;

    if (!hasRootSchema) {
        migrateLegacyRecentDestinations();
        if (persistenceMode_ == PersistenceMode::Enabled &&
            save() != SaveResult::Success)
            loadStatus_ = LoadStatus::SettingsError;
    }
    return loadStatus_;
}

void DeviceRegistry::writeRegistry(const QString& group)
{
    settings_.remove(group);
    settings_.setValue(group + "/schemaVersion", SchemaVersion);
    settings_.beginWriteArray(group + "/" + DevicesArray);
    for (int index = 0; index < devices_.size(); ++index) {
        settings_.setArrayIndex(index);
        const DeviceInfo& device = devices_.at(index);
        settings_.setValue("uuid", device.uuid().toString(QUuid::WithoutBraces));
        settings_.setValue("technicalName", device.technicalName());
        settings_.setValue("localAlias", device.localAlias());
        settings_.setValue("operatingSystem", device.operatingSystem());
        settings_.setValue("ipAddresses", device.ipAddresses());
        settings_.setValue("version", device.version());
        settings_.setValue("capabilities", device.capabilities());
        settings_.setValue("trustState", static_cast<int>(device.trustState()));
        settings_.setValue("lastSeen", device.lastSeen());
        settings_.setValue("permissions", permissions_.serialize(device.uuid()));
    }
    settings_.endArray();
}

DeviceRegistry::SaveResult DeviceRegistry::save()
{
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return SaveResult::SettingsError;
    const std::lock_guard lock(mutex_);
    if (loadStatus_ == LoadStatus::FutureSchema) return SaveResult::FutureSchema;
    if (loadStatus_ == LoadStatus::InvalidSchema) return SaveResult::InvalidSchema;
    if (loadStatus_ != LoadStatus::Loaded || saveStatus_ == SaveStatus::Error)
        return SaveResult::SettingsError;

    settings_.sync();
    if (settings_.status() != QSettings::NoError)
        return SaveResult::SettingsError;
    const QString previous = settings_.value(ActiveGeneration).toString();
    if (previous != loadedGeneration_)
        return SaveResult::SettingsError;
    const QString generation = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const QString group = generationGroup(generation);
    writeRegistry(group);
    if (!sync()) {
        markSaveError();
        return SaveResult::SettingsError;
    }

    int schema = 0;
    if (!readStrictInt(settings_, group + "/schemaVersion", schema) || schema != SchemaVersion ||
        !registryMatches(group, devices_)) {
        markSaveError();
        return SaveResult::SettingsError;
    }

    settings_.setValue(QString(RegistryGroup) + "/schemaVersion", SchemaVersion);
    settings_.setValue(ActiveGeneration, generation);
    if (!sync()) {
        if (previous.isEmpty()) settings_.remove(ActiveGeneration);
        else settings_.setValue(ActiveGeneration, previous);
        sync();
        markSaveError();
        return SaveResult::SettingsError;
    }
    loadedGeneration_ = generation;

    settings_.beginGroup(GenerationsGroup);
    const QStringList generations = settings_.childGroups();
    settings_.endGroup();
    for (const QString& old : generations) {
        if (old != generation) settings_.remove(generationGroup(old));
    }
    settings_.remove(QString(RegistryGroup) + "/devices");
    if (!sync()) {
        // The active generation was already promoted and synchronized. Garbage
        // collection is best effort and must not turn a committed mutation into
        // a false rollback; stale generations are harmless and cleaned later.
        saveStatus_ = SaveStatus::Success;
        return SaveResult::Success;
    }
    saveStatus_ = SaveStatus::Success;
    return SaveResult::Success;
}

void DeviceRegistry::migrateLegacyRecentDestinations()
{
    const int count = settings_.beginReadArray("recentDestinations");
    for (int index = 0; index < count; ++index) {
        settings_.setArrayIndex(index);
        DeviceInfo device(QUuid(settings_.value("uuid").toString()));
        if (!device.isValid()) continue;
        device.setTechnicalName(settings_.value("name").toString());
        const QString address = settings_.value("address").toString();
        if (!address.isEmpty()) device.setIpAddresses({address});
        const int existingIndex = indexOf(device.uuid());
        if (existingIndex < 0) {
            devices_.append(device);
        } else {
            const QString alias = devices_.at(existingIndex).localAlias();
            const auto trust = devices_.at(existingIndex).trustState();
            devices_[existingIndex] = device;
            devices_[existingIndex].setLocalAlias(alias);
            devices_[existingIndex].setTrustState(trust);
        }
    }
    settings_.endArray();
}
