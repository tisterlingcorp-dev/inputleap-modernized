/*
 * InputLeap -- mouse and keyboard sharing utility
 */
#pragma once

#include "DeviceInfo.h"
#include "DevicePermissions.h"

#include <QList>
#include <functional>
#include <mutex>
#include <optional>

class QSettings;

class DeviceRegistry
{
public:
    static constexpr int SchemaVersion = 1;
    enum class LoadStatus { Loaded, InvalidSchema, FutureSchema, SettingsError };
    enum class SaveResult { Success, InvalidSchema, FutureSchema, SettingsError };
    enum class SaveStatus { NotAttempted, Success, Error };
    enum class PersistenceMode { Enabled, ReadOnly };
    enum class AddResult { Added, Merged, Rejected, Error };
    enum class ResolveStatus { Found, Created, Rejected, PersistenceError };
    enum class AliasResult { Changed, Unchanged, InvalidAlias, UnknownDevice, PersistenceError };
    struct ResolveResult { ResolveStatus status; QUuid uuid; };
    using SyncFunction = std::function<bool(QSettings&)>;

    explicit DeviceRegistry(
        QSettings& settings, SyncFunction sync = {},
        PersistenceMode persistenceMode = PersistenceMode::Enabled);
    bool enablePersistence();
    void disablePersistence();

    QUuid create(const QString& technicalName);
    ResolveResult resolveOrCreateByTechnicalName(const QString& technicalName);
    AddResult add(const DeviceInfo& device);
    // Atomic UUID-keyed network merge; preserves alias/trust and persists before success.
    AddResult upsertDiscovered(const DeviceInfo& device);
    std::optional<DeviceInfo> find(const QUuid& uuid) const;
    bool update(const DeviceInfo& device);
    bool remove(const QUuid& uuid);
    AliasResult setLocalAlias(const QUuid& uuid, const QString& alias);
    static bool isValidLocalAlias(const QString& alias, QString* normalized = nullptr);
    QList<DeviceInfo> devices() const;
    DevicePermissions::Mask permissions(const QUuid& uuid) const;
    bool allows(const QUuid& uuid, DevicePermissions::Permission permission) const;
    bool setPermissions(const QUuid& uuid, DevicePermissions::Mask mask);
    bool revokePermission(const QUuid& uuid, DevicePermissions::Permission permission);

    LoadStatus load();
    LoadStatus loadStatus() const;
    SaveResult save();
    SaveStatus saveStatus() const;

private:
    void migrateLegacyRecentDestinations();
    int indexOf(const QUuid& uuid) const;
    void writeRegistry(const QString& group);
    bool readRegistry(const QString& group, QList<DeviceInfo>& devices, bool requireValidSize) const;
    bool registryMatches(const QString& group, const QList<DeviceInfo>& expected) const;
    bool mutationsAllowed() const;
    bool sync();
    void markSaveError();

    QSettings& settings_;
    SyncFunction sync_;
    mutable std::recursive_mutex mutex_;
    QList<DeviceInfo> devices_;
    mutable DevicePermissions permissions_;
    LoadStatus loadStatus_ = LoadStatus::Loaded;
    SaveStatus saveStatus_ = SaveStatus::NotAttempted;
    PersistenceMode persistenceMode_ = PersistenceMode::Enabled;
    QString loadedGeneration_;
};
