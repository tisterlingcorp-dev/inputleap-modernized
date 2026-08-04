/* InputLeap -- transactional environment profile controller. */
#pragma once

#include "DevicePermissions.h"
#include "EnvironmentProfileStore.h"

#include <QObject>

#include <atomic>
#include <functional>
#include <memory>
#include <optional>

class DeviceRegistry;
class ServerConfig;

class EnvironmentProfileController : public QObject
{
    Q_OBJECT
public:
    enum class ActivationSource { Manual, Network };
    enum class Result {
        Success,
        Unchanged,
        Busy,
        ExternalConfigUnsupported,
        InvalidProfile,
        PersistenceError,
        ConcurrentModification,
        AutomationRequiresConsent,
        IndeterminateState,
        Reentrant,
        WrongThread
    };

    struct Services {
        std::function<EnvironmentProfileStore::LoadStatus()> load;
        std::function<std::optional<EnvironmentProfile>(EnvironmentProfile::Kind)> profile;
        std::function<std::optional<EnvironmentProfile::Kind>()> activeKind;
        std::function<std::optional<QString>()> currentGeneration;
        std::function<EnvironmentProfileStore::SaveResult(const EnvironmentProfile&)> initializeFromLegacy;
        std::function<EnvironmentProfileStore::Mutation(
            const EnvironmentProfile&, const QString&, const std::optional<QString>&)>
            replaceProfileIfGeneration;
        std::function<EnvironmentProfileStore::Mutation(
            EnvironmentProfile::Kind, const QString&, const std::optional<QString>&)>
            setActiveIfGeneration;
        std::function<EnvironmentProfileStore::SaveResult(const QString&)> verifyGeneration;
        std::function<EnvironmentProfileStore::SaveResult(
            const QString&, const EnvironmentProfileStore::VerifiedConsumer&)>
            consumeVerifiedGeneration;
        std::function<EnvironmentProfile::Layout()> snapshotLayout;
        std::function<bool(const EnvironmentProfile::Layout&)> applyLayout;
        std::function<DevicePermissions::Mask(const QUuid&)> permissions;
        std::function<bool(const QUuid&, DevicePermissions::Permission)> allows;
        std::function<bool()> isBusy;
        std::function<bool()> usesExternalConfig;
        std::function<QList<EnvironmentProfile>()> profiles;
        std::function<EnvironmentProfileStore::Mutation(
            const QList<EnvironmentProfile>&, EnvironmentProfile::Kind,
            const QString&, const std::optional<QString>&)> replaceAllIfGeneration;
        std::function<EnvironmentProfileStore::RecoveryResult()> recoverLastValidGeneration;
    };

    struct CollectionSnapshot {
        QList<EnvironmentProfile> profiles;
        EnvironmentProfile::Kind activeKind = EnvironmentProfile::Kind::Home;
        QString generation;
    };

    EnvironmentProfileController(EnvironmentProfileStore& store,
                                 ServerConfig& serverConfig,
                                 DeviceRegistry& registry,
                                 QUuid localUuid,
                                 std::function<bool()> isBusy,
                                 std::function<bool()> usesExternalConfig,
                                 QObject* parent = nullptr);
    EnvironmentProfileController(EnvironmentProfileStore& store,
                                 ServerConfig& serverConfig,
                                 DeviceRegistry& registry,
                                 std::function<QUuid()> localUuid,
                                 std::function<bool()> isBusy,
                                 std::function<bool()> usesExternalConfig,
                                 QObject* parent = nullptr);
    explicit EnvironmentProfileController(Services services, QObject* parent = nullptr);

    bool initialize();
    void invalidate();
    bool recoveredOnInitialize() const;
    EnvironmentProfile::Kind activeKind() const;
    std::optional<CollectionSnapshot> collectionSnapshot() const;
    Result replaceAll(const QList<EnvironmentProfile>& profiles,
                      EnvironmentProfile::Kind activeKind);
    Result capture(EnvironmentProfile::Kind kind);
    Result activate(EnvironmentProfile::Kind kind, ActivationSource source);
    bool effectiveAllows(const QUuid& uuid, DevicePermissions::Permission permission) const;

Q_SIGNALS:
    void activeProfileChanged(EnvironmentProfile::Kind kind);
    void profileCaptured(EnvironmentProfile::Kind kind);
    void authorizationInvalidated();

private:
    std::optional<EnvironmentProfile> captureCurrent(EnvironmentProfile::Kind kind) const;
    Result persistenceResult(EnvironmentProfileStore::SaveResult result);
    bool servicesComplete() const;
    void closeAuthorizationGate() noexcept;
    void publishAuthorizationProfile();
    void failClosed();

    Services services_;
    std::optional<EnvironmentProfile::Kind> activeKind_;
    std::optional<EnvironmentProfile> activeProfile_;
    std::optional<QString> generation_;
    std::atomic<std::shared_ptr<const EnvironmentProfile>> authorizationProfile_;
    std::atomic_bool gateClosed_{true};
    bool initialized_ = false;
    bool recoveredOnInitialize_ = false;
    bool operationInProgress_ = false;
};
