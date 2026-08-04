/* InputLeap -- transactional environment profile controller. */
#include "EnvironmentProfileController.h"

#include "ConfigurationTransactionLock.h"
#include "DeviceRegistry.h"
#include "ServerConfig.h"

#include <QScopeGuard>
#include <QThread>

#include <algorithm>
#include <utility>

namespace {
bool validCollection(const QList<EnvironmentProfile>& profiles,
                     EnvironmentProfile::Kind activeKind)
{
    if (profiles.size() != EnvironmentProfile::canonicalKinds().size() ||
        !EnvironmentProfile::canonicalKinds().contains(activeKind)) {
        return false;
    }
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        int matches = 0;
        for (const auto& profile : profiles) {
            if (profile.kind == kind && profile.isValid())
                ++matches;
        }
        if (matches != 1)
            return false;
    }
    return true;
}
}

EnvironmentProfileController::EnvironmentProfileController(
    EnvironmentProfileStore& store,
    ServerConfig& serverConfig,
    DeviceRegistry& registry,
    QUuid localUuid,
    std::function<bool()> isBusy,
    std::function<bool()> usesExternalConfig,
    QObject* parent) :
    EnvironmentProfileController(
        store, serverConfig, registry, [localUuid] { return localUuid; },
        std::move(isBusy), std::move(usesExternalConfig), parent)
{
}

EnvironmentProfileController::EnvironmentProfileController(
    EnvironmentProfileStore& store,
    ServerConfig& serverConfig,
    DeviceRegistry& registry,
    std::function<QUuid()> localUuid,
    std::function<bool()> isBusy,
    std::function<bool()> usesExternalConfig,
    QObject* parent) :
    EnvironmentProfileController(
        Services{
            [&store] { return store.load(); },
            [&store](EnvironmentProfile::Kind kind) { return store.profile(kind); },
            [&store] { return store.activeKind(); },
            [&store] { return store.currentGeneration(); },
            [&store](const EnvironmentProfile& profile) { return store.initializeFromLegacy(profile); },
            [&store](const EnvironmentProfile& profile, const QString& generation,
                     const std::optional<QString>& recoveryGeneration) {
                return store.replaceProfileIfGeneration(
                    profile, generation, recoveryGeneration);
            },
            [&store](EnvironmentProfile::Kind kind, const QString& generation,
                     const std::optional<QString>& recoveryGeneration) {
                return store.setActiveIfGeneration(kind, generation, recoveryGeneration);
            },
            [&store](const QString& generation) { return store.verifyGeneration(generation); },
            [&store](const QString& generation,
                     const EnvironmentProfileStore::VerifiedConsumer& consumer) {
                return store.consumeVerifiedGeneration(generation, consumer);
            },
            [&serverConfig, &registry, localUuid = std::move(localUuid)] {
                QHash<QString, QUuid> stableIdentities;
                for (const DeviceInfo& device : registry.devices()) {
                    const QString name = device.technicalName();
                    if (name.isEmpty()) continue;
                    if (stableIdentities.contains(name))
                        stableIdentities[name] = {};
                    else
                        stableIdentities.insert(name, device.uuid());
                }
                return serverConfig.environmentLayoutSnapshot(
                    localUuid ? localUuid() : QUuid(), stableIdentities);
            },
            [&serverConfig](const EnvironmentProfile::Layout& layout) {
                return serverConfig.applyEnvironmentLayout(layout);
            },
            [&registry](const QUuid& uuid) { return registry.permissions(uuid); },
            [&registry](const QUuid& uuid, DevicePermissions::Permission permission) {
                return registry.allows(uuid, permission);
            },
            std::move(isBusy),
            std::move(usesExternalConfig),
            [&store] { return store.profiles(); },
            [&store](const QList<EnvironmentProfile>& profiles,
                     EnvironmentProfile::Kind activeKind, const QString& generation,
                     const std::optional<QString>& recoveryGeneration) {
                return store.replaceAllIfGeneration(
                    profiles, activeKind, generation, recoveryGeneration);
            },
            [&store] { return store.recoverLastValidGeneration(); }},
        parent)
{
}

EnvironmentProfileController::EnvironmentProfileController(Services services, QObject* parent) :
    QObject(parent),
    services_(std::move(services))
{
}

void EnvironmentProfileController::failClosed()
{
    Q_ASSERT(QThread::currentThread() == thread());
    closeAuthorizationGate();
    initialized_ = false;
    activeKind_.reset();
    activeProfile_.reset();
    generation_.reset();
    recoveredOnInitialize_ = false;
    Q_EMIT authorizationInvalidated();
}

void EnvironmentProfileController::invalidate()
{
    failClosed();
}

void EnvironmentProfileController::closeAuthorizationGate() noexcept
{
    gateClosed_.store(true, std::memory_order_release);
    std::atomic_store_explicit(&authorizationProfile_,
        std::shared_ptr<const EnvironmentProfile>{}, std::memory_order_release);
}

void EnvironmentProfileController::publishAuthorizationProfile()
{
    Q_ASSERT(QThread::currentThread() == thread());
    Q_ASSERT(activeProfile_.has_value());
    std::atomic_store_explicit(&authorizationProfile_,
        std::make_shared<const EnvironmentProfile>(*activeProfile_),
        std::memory_order_release);
    gateClosed_.store(false, std::memory_order_release);
}

bool EnvironmentProfileController::servicesComplete() const
{
    return services_.load && services_.profile && services_.activeKind && services_.currentGeneration &&
           services_.initializeFromLegacy && services_.replaceProfileIfGeneration &&
           services_.setActiveIfGeneration && services_.verifyGeneration &&
           services_.consumeVerifiedGeneration && services_.snapshotLayout &&
           services_.applyLayout && services_.permissions && services_.allows && services_.isBusy &&
           services_.usesExternalConfig && services_.profiles && services_.replaceAllIfGeneration;
}

std::optional<EnvironmentProfile> EnvironmentProfileController::captureCurrent(
    EnvironmentProfile::Kind kind) const
{
    if (!EnvironmentProfile::canonicalKinds().contains(kind)) return std::nullopt;
    EnvironmentProfile captured;
    captured.kind = kind;
    captured.layout = services_.snapshotLayout();
    for (const auto& layoutDevice : captured.layout.extension.devices()) {
        captured.devices.push_back({layoutDevice.uuid, layoutDevice.technicalName,
            services_.permissions(layoutDevice.uuid) & EnvironmentProfile::ManagedResources});
    }
    if (!captured.isValid()) return std::nullopt;
    return captured;
}

bool EnvironmentProfileController::initialize()
{
    if (QThread::currentThread() != thread()) {
        closeAuthorizationGate();
        return false;
    }
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) {
        failClosed();
        return false;
    }
    if (operationInProgress_) return false;
    operationInProgress_ = true;
    const auto operationGuard = qScopeGuard([this] { operationInProgress_ = false; });
    failClosed();
    if (!servicesComplete()) return false;

    std::optional<EnvironmentProfile::Layout> previousLayout;
    bool reconciledLayout = false;
    try {
        auto status = services_.load();
        bool recovered = false;
        if (status == EnvironmentProfileStore::LoadStatus::InvalidSchema &&
            services_.recoverLastValidGeneration) {
            if (services_.recoverLastValidGeneration() !=
                EnvironmentProfileStore::RecoveryResult::Recovered) {
                return false;
            }
            status = services_.load();
            recovered = status == EnvironmentProfileStore::LoadStatus::Loaded;
            if (!recovered)
                return false;
        }
        if (status == EnvironmentProfileStore::LoadStatus::Missing) {
            const auto legacy = captureCurrent(EnvironmentProfile::Kind::Home);
            if (!legacy) return false;
            if (services_.initializeFromLegacy(*legacy) != EnvironmentProfileStore::SaveResult::Success) return false;
        }
        else if (status != EnvironmentProfileStore::LoadStatus::Loaded) {
            return false;
        }

        const auto expectedGeneration = services_.currentGeneration();
        if (!expectedGeneration || expectedGeneration->isEmpty()) return false;
        previousLayout = services_.snapshotLayout();
        const auto consumed = services_.consumeVerifiedGeneration(
            *expectedGeneration,
            [this, recovered, &reconciledLayout](
                const EnvironmentProfileStore::VerifiedState& state) {
                if (state.generation.isEmpty() || state.profile.kind != state.activeKind ||
                    !state.profile.isValid()) {
                    return false;
                }
                if (!services_.applyLayout(state.profile.layout)) {
                    return false;
                }
                reconciledLayout = true;
                activeKind_ = state.activeKind;
                activeProfile_ = state.profile;
                generation_ = state.generation;
                initialized_ = true;
                recoveredOnInitialize_ = recovered;
                return true;
            });
        if (consumed != EnvironmentProfileStore::SaveResult::Success || !generation_) {
            if (reconciledLayout && previousLayout) {
                try { services_.applyLayout(*previousLayout); }
                catch (...) {}
            }
            failClosed();
            return false;
        }
        if (services_.verifyGeneration(*generation_) !=
            EnvironmentProfileStore::SaveResult::Success) {
            if (reconciledLayout && previousLayout) {
                try { services_.applyLayout(*previousLayout); }
                catch (...) {}
            }
            failClosed();
            return false;
        }
        const auto published = services_.consumeVerifiedGeneration(
            *generation_,
            [this, &transactionLock](const EnvironmentProfileStore::VerifiedState& state) {
                if (!generation_ || !activeKind_ || state.generation != *generation_ ||
                    state.activeKind != *activeKind_ ||
                    state.profile.kind != state.activeKind || !state.profile.isValid()) {
                    return false;
                }
                generation_ = state.generation;
                activeKind_ = state.activeKind;
                activeProfile_ = state.profile;
                return transactionLock.sealReentrantAcquisition();
            });
        if (published != EnvironmentProfileStore::SaveResult::Success) {
            if (reconciledLayout && previousLayout) {
                try { services_.applyLayout(*previousLayout); }
                catch (...) {}
            }
            failClosed();
            return false;
        }
        if (services_.verifyGeneration(*generation_) !=
            EnvironmentProfileStore::SaveResult::Success) {
            if (reconciledLayout && previousLayout) {
                try { services_.applyLayout(*previousLayout); }
                catch (...) {}
            }
            failClosed();
            return false;
        }
        publishAuthorizationProfile();
        return true;
    }
    catch (...) {
        if (reconciledLayout && previousLayout) {
            try { services_.applyLayout(*previousLayout); }
            catch (...) {}
        }
        failClosed();
        return false;
    }
}

bool EnvironmentProfileController::recoveredOnInitialize() const
{
    return QThread::currentThread() == thread() && initialized_ && recoveredOnInitialize_;
}

EnvironmentProfile::Kind EnvironmentProfileController::activeKind() const
{
    if (QThread::currentThread() != thread()) return EnvironmentProfile::Kind::Home;
    return activeKind_.value_or(EnvironmentProfile::Kind::Home);
}

std::optional<EnvironmentProfileController::CollectionSnapshot>
EnvironmentProfileController::collectionSnapshot() const
{
    if (QThread::currentThread() != thread() || !initialized_ || !activeKind_ ||
        !generation_ || !services_.profiles) {
        return std::nullopt;
    }
    try {
        CollectionSnapshot snapshot{services_.profiles(), *activeKind_, *generation_};
        if (!validCollection(snapshot.profiles, snapshot.activeKind) || snapshot.generation.isEmpty())
            return std::nullopt;
        return snapshot;
    }
    catch (...) {
        return std::nullopt;
    }
}

EnvironmentProfileController::Result EnvironmentProfileController::replaceAll(
    const QList<EnvironmentProfile>& profiles, EnvironmentProfile::Kind activeKind)
{
    if (QThread::currentThread() != thread()) {
        closeAuthorizationGate();
        return Result::WrongThread;
    }
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return Result::ConcurrentModification;
    if (operationInProgress_)
        return Result::Reentrant;
    operationInProgress_ = true;
    const auto operationGuard = qScopeGuard([this] { operationInProgress_ = false; });

    try {
        if (!initialized_ || !activeKind_ || !generation_)
            return Result::InvalidProfile;
        if (!validCollection(profiles, activeKind))
            return Result::InvalidProfile;
        if (services_.isBusy())
            return Result::Busy;
        if (services_.usesExternalConfig())
            return Result::ExternalConfigUnsupported;

        const auto selected = std::find_if(profiles.cbegin(), profiles.cend(),
                                           [activeKind](const EnvironmentProfile& profile) {
            return profile.kind == activeKind;
        });
        if (selected == profiles.cend())
            return Result::InvalidProfile;

        const QList<EnvironmentProfile> previousProfiles = services_.profiles();
        const EnvironmentProfile::Kind previousActive = *activeKind_;
        const EnvironmentProfile::Layout previousLayout = services_.snapshotLayout();
        const QString knownGoodGeneration = *generation_;
        if (!validCollection(previousProfiles, previousActive)) {
            failClosed();
            return Result::IndeterminateState;
        }
        const bool authorizationWasOpen =
            !gateClosed_.load(std::memory_order_acquire);
        closeAuthorizationGate();
        const auto compensatePersistence = [&](const QString& expectedGeneration) {
            try {
                const auto rollback = services_.replaceAllIfGeneration(
                    previousProfiles, previousActive, expectedGeneration,
                    knownGoodGeneration);
                if (rollback.result != EnvironmentProfileStore::SaveResult::Success ||
                    rollback.resultingGeneration.isEmpty()) {
                    return false;
                }
                generation_ = rollback.resultingGeneration;
                activeKind_ = previousActive;
                for (const auto& profile : previousProfiles) {
                    if (profile.kind == previousActive) {
                        activeProfile_ = profile;
                        return true;
                    }
                }
                return false;
            }
            catch (...) {
                return false;
            }
        };

        EnvironmentProfileStore::Mutation mutation;
        try {
            mutation = services_.replaceAllIfGeneration(
                profiles, activeKind, *generation_, std::nullopt);
        }
        catch (...) {
            const auto observed = services_.currentGeneration();
            if (observed && !observed->isEmpty() && *observed != *generation_)
                compensatePersistence(*observed);
            failClosed();
            return Result::IndeterminateState;
        }
        const Result persisted = persistenceResult(mutation.result);
        if (persisted != Result::Success)
            return persisted;
        if (mutation.resultingGeneration.isEmpty()) {
            const auto observed = services_.currentGeneration();
            if (observed && !observed->isEmpty() && *observed != *generation_)
                compensatePersistence(*observed);
            failClosed();
            return Result::IndeterminateState;
        }

        const auto compensate = [&]() {
            return compensatePersistence(mutation.resultingGeneration);
        };

        const auto restoreLayout = [&]() {
            try { return services_.applyLayout(previousLayout); }
            catch (...) { return false; }
        };

        bool layoutApplied = false;
        try { layoutApplied = services_.applyLayout(selected->layout); }
        catch (...) { layoutApplied = false; }
        if (!layoutApplied) {
            const bool layoutRestored = restoreLayout();
            const bool persistenceRestored = compensate();
            if (!layoutRestored || !persistenceRestored) {
                failClosed();
                return Result::IndeterminateState;
            }
            return Result::PersistenceError;
        }

        EnvironmentProfileStore::SaveResult verification;
        try {
            verification = services_.consumeVerifiedGeneration(
                mutation.resultingGeneration,
                [this, activeKind, &transactionLock](
                    const EnvironmentProfileStore::VerifiedState& state) {
                    if (state.activeKind != activeKind || state.generation.isEmpty() ||
                        state.profile.kind != activeKind || !state.profile.isValid()) {
                        return false;
                    }
                    generation_ = state.generation;
                    activeKind_ = state.activeKind;
                    activeProfile_ = state.profile;
                    return transactionLock.sealReentrantAcquisition();
                });
            if (verification == EnvironmentProfileStore::SaveResult::Success)
                verification = services_.verifyGeneration(mutation.resultingGeneration);
        }
        catch (...) {
            failClosed();
            const bool layoutRestored = restoreLayout();
            const bool persistenceRestored = compensate();
            if (!layoutRestored || !persistenceRestored)
                failClosed();
            return Result::IndeterminateState;
        }
        if (verification != EnvironmentProfileStore::SaveResult::Success) {
            failClosed();
            const bool layoutRestored = restoreLayout();
            const bool persistenceRestored = compensate();
            if (!layoutRestored ||
                (verification != EnvironmentProfileStore::SaveResult::ConcurrentModification &&
                 !persistenceRestored)) {
                failClosed();
                return Result::IndeterminateState;
            }
            return verification == EnvironmentProfileStore::SaveResult::ConcurrentModification
                ? Result::ConcurrentModification : Result::PersistenceError;
        }

        if (authorizationWasOpen)
            publishAuthorizationProfile();
        return Result::Success;
    }
    catch (...) {
        failClosed();
        return Result::IndeterminateState;
    }
}

EnvironmentProfileController::Result EnvironmentProfileController::persistenceResult(
    EnvironmentProfileStore::SaveResult result)
{
    if (result == EnvironmentProfileStore::SaveResult::Success) return Result::Success;
    failClosed();
    if (result == EnvironmentProfileStore::SaveResult::ConcurrentModification) return Result::ConcurrentModification;
    if (result == EnvironmentProfileStore::SaveResult::InvalidProfile) return Result::InvalidProfile;
    if (result == EnvironmentProfileStore::SaveResult::IndeterminateState) return Result::IndeterminateState;
    return Result::PersistenceError;
}

EnvironmentProfileController::Result EnvironmentProfileController::capture(EnvironmentProfile::Kind kind)
{
    if (QThread::currentThread() != thread()) {
        closeAuthorizationGate();
        return Result::WrongThread;
    }
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return Result::ConcurrentModification;
    if (operationInProgress_) return Result::Reentrant;
    operationInProgress_ = true;
    const auto operationGuard = qScopeGuard([this] { operationInProgress_ = false; });

    try {
        if (!initialized_ || !generation_) return Result::InvalidProfile;
        if (services_.isBusy()) return Result::Busy;
        if (services_.usesExternalConfig()) return Result::ExternalConfigUnsupported;
        const bool authorizationWasOpen =
            !gateClosed_.load(std::memory_order_acquire);
        const auto captured = captureCurrent(kind);
        if (!captured) return Result::InvalidProfile;
        const auto previous = services_.profile(kind);
        if (activeKind_ && *activeKind_ == kind)
            closeAuthorizationGate();
        const auto mutation = services_.replaceProfileIfGeneration(
            *captured, *generation_, std::nullopt);
        const Result persisted = persistenceResult(mutation.result);
        if (persisted != Result::Success) return persisted;
        if (!mutation.promotedProfile || mutation.promotedProfile->kind != kind ||
            !mutation.promotedProfile->isValid() || mutation.resultingGeneration.isEmpty()) {
            failClosed();
            return Result::IndeterminateState;
        }
        auto verification = services_.consumeVerifiedGeneration(
            mutation.resultingGeneration,
            [this](const EnvironmentProfileStore::VerifiedState& state) {
                if (state.generation.isEmpty() || state.profile.kind != state.activeKind ||
                    !state.profile.isValid()) {
                    return false;
                }
                generation_ = state.generation;
                activeKind_ = state.activeKind;
                activeProfile_ = state.profile;
                return true;
            });
        if (verification == EnvironmentProfileStore::SaveResult::Success) {
            closeAuthorizationGate();
            verification = services_.verifyGeneration(mutation.resultingGeneration);
        }
        Result verified = persistenceResult(verification);
        if (verified != Result::Success) return verified;
        try {
            verification = services_.consumeVerifiedGeneration(
                mutation.resultingGeneration,
                [this, kind, authorizationWasOpen, &transactionLock](
                    const EnvironmentProfileStore::VerifiedState& state) {
                    if (state.generation.isEmpty() || state.profile.kind != state.activeKind ||
                        !state.profile.isValid()) {
                        return false;
                    }
                    generation_ = state.generation;
                    activeKind_ = state.activeKind;
                    activeProfile_ = state.profile;
                    if (!transactionLock.sealReentrantAcquisition())
                        return false;
                    Q_EMIT profileCaptured(kind);
                    if (authorizationWasOpen)
                        publishAuthorizationProfile();
                    return true;
                });
        }
        catch (...) {
            bool compensated = false;
            if (previous) {
                try {
                    const auto rollback = services_.replaceProfileIfGeneration(
                        *previous, mutation.resultingGeneration, mutation.previousGeneration);
                    compensated = rollback.result == EnvironmentProfileStore::SaveResult::Success;
                }
                catch (...) {}
            }
            failClosed();
            return compensated ? Result::PersistenceError : Result::IndeterminateState;
        }
        verified = persistenceResult(verification);
        if (verified != Result::Success) return verified;
        return Result::Success;
    }
    catch (...) {
        failClosed();
        return Result::IndeterminateState;
    }
}

EnvironmentProfileController::Result EnvironmentProfileController::activate(
    EnvironmentProfile::Kind kind, ActivationSource source)
{
    if (QThread::currentThread() != thread()) {
        closeAuthorizationGate();
        return Result::WrongThread;
    }
    ConfigurationTransactionLock transactionLock;
    if (!transactionLock.isLocked()) return Result::ConcurrentModification;
    if (operationInProgress_) return Result::Reentrant;
    operationInProgress_ = true;
    const auto operationGuard = qScopeGuard([this] { operationInProgress_ = false; });

    if (source != ActivationSource::Manual) return Result::AutomationRequiresConsent;
    try {
        if (!initialized_ || !activeKind_ || !activeProfile_ || !generation_) return Result::InvalidProfile;
        const auto targetHint = services_.profile(kind);
        if (!targetHint || targetHint->kind != kind || !targetHint->isValid()) return Result::InvalidProfile;
        if (services_.isBusy()) return Result::Busy;
        if (services_.usesExternalConfig()) return Result::ExternalConfigUnsupported;
        if (*activeKind_ == kind) return Result::Unchanged;

        closeAuthorizationGate();
        const auto previousKind = *activeKind_;
        const auto previousProfile = *activeProfile_;
        const auto previousLayout = services_.snapshotLayout();
        const QString knownGoodGeneration = *generation_;
        const auto mutation = services_.setActiveIfGeneration(
            kind, *generation_, std::nullopt);
        const Result persisted = persistenceResult(mutation.result);
        if (persisted != Result::Success) return persisted;
        if (!mutation.promotedProfile || mutation.promotedProfile->kind != kind ||
            !mutation.promotedProfile->isValid() || mutation.resultingGeneration.isEmpty()) {
            failClosed();
            return Result::IndeterminateState;
        }

        const auto compensate = [&]() -> bool {
            try {
                const auto rollback = services_.setActiveIfGeneration(
                    previousKind, mutation.resultingGeneration, knownGoodGeneration);
                if (rollback.result != EnvironmentProfileStore::SaveResult::Success ||
                    rollback.resultingGeneration.isEmpty() || !rollback.promotedProfile) return false;
                generation_ = rollback.resultingGeneration;
                activeKind_ = previousKind;
                activeProfile_ = previousProfile;
                return true;
            }
            catch (...) { return false; }
        };
        const auto restoreLayout = [&]() -> bool {
            try { return services_.applyLayout(previousLayout); }
            catch (...) { return false; }
        };

        bool applied = false;
        try { applied = services_.applyLayout(mutation.promotedProfile->layout); }
        catch (...) { applied = false; }
        if (!applied) {
            const bool layoutRestored = restoreLayout();
            const bool persistenceRestored = compensate();
            if (!layoutRestored || !persistenceRestored) {
                failClosed();
                return Result::IndeterminateState;
            }
            return Result::PersistenceError;
        }

        EnvironmentProfileStore::SaveResult verification = EnvironmentProfileStore::SaveResult::SettingsError;
        try {
            verification = services_.consumeVerifiedGeneration(
                mutation.resultingGeneration,
                [this, kind](const EnvironmentProfileStore::VerifiedState& state) {
                    if (state.activeKind != kind || state.generation.isEmpty() ||
                        state.profile.kind != kind || !state.profile.isValid()) {
                        return false;
                    }
                    generation_ = state.generation;
                    activeKind_ = state.activeKind;
                    activeProfile_ = state.profile;
                    return true;
                });
            if (verification == EnvironmentProfileStore::SaveResult::Success)
                verification = services_.verifyGeneration(mutation.resultingGeneration);
        }
        catch (...) {
            failClosed();
            const bool layoutRestored = restoreLayout();
            const bool persistenceRestored = compensate();
            if (!layoutRestored || !persistenceRestored) return Result::IndeterminateState;
            return Result::PersistenceError;
        }
        if (verification != EnvironmentProfileStore::SaveResult::Success) {
            failClosed();
            const bool layoutRestored = restoreLayout();
            const bool persistenceRestored = compensate();
            if (!layoutRestored ||
                (verification != EnvironmentProfileStore::SaveResult::ConcurrentModification &&
                 !persistenceRestored))
                return Result::IndeterminateState;
            return verification == EnvironmentProfileStore::SaveResult::ConcurrentModification
                ? Result::ConcurrentModification : Result::IndeterminateState;
        }

        try {
            Q_EMIT activeProfileChanged(kind);
        }
        catch (...) {
            closeAuthorizationGate();
            const bool layoutRestored = restoreLayout();
            const bool persistenceRestored = compensate();
            if (!layoutRestored || !persistenceRestored) {
                failClosed();
                return Result::IndeterminateState;
            }
            publishAuthorizationProfile();
            return Result::PersistenceError;
        }
        EnvironmentProfileStore::SaveResult publication =
            EnvironmentProfileStore::SaveResult::SettingsError;
        try {
            publication = services_.consumeVerifiedGeneration(
                mutation.resultingGeneration,
                [this, kind, &transactionLock](
                    const EnvironmentProfileStore::VerifiedState& state) {
                    if (state.activeKind != kind || state.generation.isEmpty() ||
                        state.profile.kind != kind || !state.profile.isValid()) {
                        return false;
                    }
                    generation_ = state.generation;
                    activeKind_ = state.activeKind;
                    activeProfile_ = state.profile;
                    if (!transactionLock.sealReentrantAcquisition())
                        return false;
                    publishAuthorizationProfile();
                    return true;
                });
        }
        catch (...) {
            failClosed();
            const bool layoutRestored = restoreLayout();
            const bool persistenceRestored = compensate();
            if (!layoutRestored || !persistenceRestored)
                return Result::IndeterminateState;
            return Result::PersistenceError;
        }
        if (publication != EnvironmentProfileStore::SaveResult::Success) {
            failClosed();
            const bool layoutRestored = restoreLayout();
            const bool persistenceRestored = compensate();
            if (!layoutRestored ||
                (publication != EnvironmentProfileStore::SaveResult::ConcurrentModification &&
                 !persistenceRestored)) {
                return Result::IndeterminateState;
            }
            return publication == EnvironmentProfileStore::SaveResult::ConcurrentModification
                ? Result::ConcurrentModification : Result::PersistenceError;
        }
        return Result::Success;
    }
    catch (...) {
        failClosed();
        return Result::IndeterminateState;
    }
}

bool EnvironmentProfileController::effectiveAllows(
    const QUuid& uuid, DevicePermissions::Permission permission) const
{
    if (gateClosed_.load(std::memory_order_acquire)) return false;
    const auto profile = std::atomic_load_explicit(&authorizationProfile_, std::memory_order_acquire);
    const auto bit = static_cast<DevicePermissions::Mask>(permission);
    if (!profile || uuid.isNull() ||
        bit == DevicePermissions::None || (bit & (bit - 1u)) != 0 ||
        (bit & EnvironmentProfile::ManagedResources) == 0 ||
        (bit & ~EnvironmentProfile::ManagedResources) != 0)
        return false;
    try {
        return profile->requests(uuid, permission) && services_.allows(uuid, permission);
    }
    catch (...) {
        return false;
    }
}
