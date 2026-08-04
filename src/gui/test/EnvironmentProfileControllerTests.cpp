/* InputLeap -- transactional environment profile controller tests. */
#include "EnvironmentProfileController.h"
#include "AppConfig.h"
#include "DeviceInfo.h"
#include "DeviceRegistry.h"
#include "ServerConfig.h"

#include <gtest/gtest.h>

#include <QFile>
#include <QMap>
#include <QSettings>
#include <QSignalSpy>
#include <QTemporaryDir>

#include <stdexcept>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace {
const QUuid firstUuid(QStringLiteral("{11111111-1111-1111-1111-111111111111}"));
const QUuid secondUuid(QStringLiteral("{22222222-2222-2222-2222-222222222222}"));
const QString capabilitySentinel(QStringLiteral("CAPABILITY_SENTINEL_DO_NOT_COPY"));

EnvironmentProfile validProfile(EnvironmentProfile::Kind kind = EnvironmentProfile::Kind::Home,
                                const QUuid& uuid = firstUuid,
                                const QString& name = QStringLiteral("alpha"))
{
    ScreenLayout::Device device;
    device.uuid = uuid;
    device.technicalName = name;
    device.geometry = QRect(0, 0, 100, 100);

    EnvironmentProfile profile;
    profile.kind = kind;
    profile.layout.columns = 1;
    profile.layout.rows = 1;
    profile.layout.gridTechnicalNames = {name};
    profile.layout.extension = ScreenLayout({device});
    profile.devices = {{uuid, name, DevicePermissions::ControlMouseKeyboard | DevicePermissions::SendFiles}};
    EXPECT_TRUE(profile.isValid());
    return profile;
}

struct SettingsValues {
    QStringList keys;
    QMap<QString, QVariant> values;
};

SettingsValues settingsSubtree(QSettings& settings, const QString& prefix)
{
    SettingsValues result;
    for (const QString& key : settings.allKeys()) {
        if (key == prefix || key.startsWith(prefix + QLatin1Char('/'))) {
            result.keys.push_back(key);
            result.values.insert(key, settings.value(key));
        }
    }
    return result;
}

void expectSettingsValuesEqual(const SettingsValues& actual, const SettingsValues& expected)
{
    EXPECT_EQ(actual.keys, expected.keys);
    for (const QString& key : expected.keys) {
        ASSERT_TRUE(actual.values.contains(key)) << key.toStdString();
        EXPECT_EQ(actual.values.value(key).metaType().id(), expected.values.value(key).metaType().id())
            << key.toStdString();
        EXPECT_TRUE(actual.values.value(key) == expected.values.value(key)) << key.toStdString();
    }
}

QByteArray fileBytes(const QString& path)
{
    QFile file(path);
    EXPECT_TRUE(file.open(QIODevice::ReadOnly));
    return file.readAll();
}

void seedLegacyLayout(QSettings& settings)
{
    settings.beginGroup(QStringLiteral("internalConfig"));
    settings.setValue(QStringLiteral("numColumns"), 1);
    settings.setValue(QStringLiteral("numRows"), 1);
    settings.setValue(QStringLiteral("hasHeartbeat"), true);
    settings.setValue(QStringLiteral("heartbeat"), 4321);
    settings.beginWriteArray(QStringLiteral("screens"));
    settings.setArrayIndex(0);
    settings.setValue(QStringLiteral("name"), QStringLiteral("alpha"));
    settings.endArray();
    ScreenLayout::Device device;
    device.uuid = firstUuid;
    device.technicalName = QStringLiteral("alpha");
    device.geometry = QRect(0, 0, 100, 100);
    device.monitors.push_back({QStringLiteral("primary"), QRect(0, 0, 100, 100), 1.25,
                               Qt::LandscapeOrientation, true});
    ASSERT_TRUE(ScreenLayout({device}).saveMetadata(settings));
    settings.endGroup();
    settings.sync();
}

void seedRegistry(DeviceRegistry& registry)
{
    DeviceInfo device(firstUuid);
    device.setTechnicalName(QStringLiteral("alpha"));
    device.setLocalAlias(QStringLiteral("Desk"));
    device.setOperatingSystem(QStringLiteral("Windows"));
    device.setIpAddresses({QStringLiteral("192.0.2.10")});
    device.setVersion(QStringLiteral("3.0.0"));
    device.setCapabilities({capabilitySentinel});
    device.setTrustState(DeviceInfo::TrustState::Trusted);
    ASSERT_EQ(registry.add(device), DeviceRegistry::AddResult::Added);
    ASSERT_EQ(registry.save(), DeviceRegistry::SaveResult::Success);
    ASSERT_TRUE(registry.setPermissions(firstUuid,
        DevicePermissions::ControlMouseKeyboard | DevicePermissions::SendFiles |
        DevicePermissions::OpenSafeFiles));
}

void expectLayoutEqual(const EnvironmentProfile::Layout& actual, const EnvironmentProfile::Layout& expected)
{
    EXPECT_EQ(actual.columns, expected.columns);
    EXPECT_EQ(actual.rows, expected.rows);
    EXPECT_EQ(actual.gridTechnicalNames, expected.gridTechnicalNames);
    const auto& actualDevices = actual.extension.devices();
    const auto& expectedDevices = expected.extension.devices();
    ASSERT_EQ(actualDevices.size(), expectedDevices.size());
    for (size_t i = 0; i < expectedDevices.size(); ++i) {
        EXPECT_EQ(actualDevices[i].uuid, expectedDevices[i].uuid);
        EXPECT_EQ(actualDevices[i].technicalName, expectedDevices[i].technicalName);
        EXPECT_EQ(actualDevices[i].geometry, expectedDevices[i].geometry);
        ASSERT_EQ(actualDevices[i].monitors.size(), expectedDevices[i].monitors.size());
        for (size_t j = 0; j < expectedDevices[i].monitors.size(); ++j) {
            EXPECT_EQ(actualDevices[i].monitors[j].id, expectedDevices[i].monitors[j].id);
            EXPECT_EQ(actualDevices[i].monitors[j].geometry, expectedDevices[i].monitors[j].geometry);
            EXPECT_DOUBLE_EQ(actualDevices[i].monitors[j].devicePixelRatio,
                             expectedDevices[i].monitors[j].devicePixelRatio);
            EXPECT_EQ(actualDevices[i].monitors[j].orientation, expectedDevices[i].monitors[j].orientation);
            EXPECT_EQ(actualDevices[i].monitors[j].stableIdentity, expectedDevices[i].monitors[j].stableIdentity);
        }
    }
}

struct Harness {
    EnvironmentProfileStore::LoadStatus status = EnvironmentProfileStore::LoadStatus::Loaded;
    EnvironmentProfile::Kind storedActive = EnvironmentProfile::Kind::Home;
    QList<EnvironmentProfile> storedProfiles;
    EnvironmentProfile::Layout currentLayout;
    QHash<QUuid, DevicePermissions::Mask> permissions;
    bool busy = false;
    bool external = false;
    bool applySucceeds = true;
    bool rollbackApplySucceeds = true;
    bool startupApplySucceeds = true;
    bool startupReconciliationPending = false;
    bool recoveryLeavesInvalid = false;
    bool advanceGenerationAfterVerify = false;
    bool advanceGenerationAfterStandaloneVerify = false;
    EnvironmentProfileStore::SaveResult initializeResult = EnvironmentProfileStore::SaveResult::Success;
    EnvironmentProfileStore::SaveResult replaceResult = EnvironmentProfileStore::SaveResult::Success;
    EnvironmentProfileStore::SaveResult replaceAllResult = EnvironmentProfileStore::SaveResult::Success;
    EnvironmentProfileStore::SaveResult activateResult = EnvironmentProfileStore::SaveResult::Success;
    EnvironmentProfileStore::SaveResult compensateResult = EnvironmentProfileStore::SaveResult::Success;
    EnvironmentProfileStore::SaveResult verifyResult = EnvironmentProfileStore::SaveResult::Success;
    EnvironmentProfileStore::RecoveryResult recoveryResult =
        EnvironmentProfileStore::RecoveryResult::Recovered;
    QString generation = QStringLiteral("generation-1");
    int generationCounter = 1;
    int initializeCalls = 0;
    int replaceCalls = 0;
    int replaceAllCalls = 0;
    int setActiveCalls = 0;
    int applyCalls = 0;
    int startupApplyCalls = 0;
    int recoveryCalls = 0;
    int verifyCalls = 0;
    QStringList order;
    QList<std::optional<QString>> recoveryOverrides;

    Harness()
    {
        for (auto kind : EnvironmentProfile::canonicalKinds()) storedProfiles.push_back(validProfile(kind));
        currentLayout = storedProfiles.front().layout;
    }

    std::optional<EnvironmentProfile> profile(EnvironmentProfile::Kind kind) const
    {
        for (const auto& profile : storedProfiles) if (profile.kind == kind) return profile;
        return std::nullopt;
    }

    EnvironmentProfileController::Services services()
    {
        return {
            [this] {
                startupReconciliationPending = true;
                return status;
            },
            [this](EnvironmentProfile::Kind kind) { return profile(kind); },
            [this] { return std::optional<EnvironmentProfile::Kind>(storedActive); },
            [this] { return std::optional<QString>(generation); },
            [this](const EnvironmentProfile& profile) {
                ++initializeCalls;
                if (initializeResult == EnvironmentProfileStore::SaveResult::Success) {
                    storedProfiles.clear();
                    for (auto kind : EnvironmentProfile::canonicalKinds()) {
                        auto clone = profile; clone.kind = kind; storedProfiles.push_back(clone);
                    }
                    storedActive = EnvironmentProfile::Kind::Home;
                    status = EnvironmentProfileStore::LoadStatus::Loaded;
                    generation = QStringLiteral("generation-%1").arg(++generationCounter);
                }
                return initializeResult;
            },
            [this](const EnvironmentProfile& replacement, const QString& expected,
                   const std::optional<QString>& recoveryGeneration) {
                ++replaceCalls;
                recoveryOverrides.push_back(recoveryGeneration);
                EnvironmentProfileStore::Mutation mutation;
                mutation.previousGeneration = expected;
                mutation.resultingGeneration = generation;
                if (expected != generation) {
                    mutation.result = EnvironmentProfileStore::SaveResult::ConcurrentModification;
                    return mutation;
                }
                mutation.result = replaceResult;
                if (replaceResult == EnvironmentProfileStore::SaveResult::Success) {
                    for (auto& profile : storedProfiles) if (profile.kind == replacement.kind) profile = replacement;
                    generation = QStringLiteral("generation-%1").arg(++generationCounter);
                    mutation.resultingGeneration = generation;
                    mutation.promotedProfile = replacement;
                }
                return mutation;
            },
            [this](EnvironmentProfile::Kind kind, const QString& expected,
                   const std::optional<QString>& recoveryGeneration) {
                ++setActiveCalls;
                recoveryOverrides.push_back(recoveryGeneration);
                order.push_back(QStringLiteral("persist"));
                EnvironmentProfileStore::Mutation mutation;
                mutation.previousGeneration = expected;
                mutation.resultingGeneration = generation;
                if (expected != generation) {
                    mutation.result = EnvironmentProfileStore::SaveResult::ConcurrentModification;
                    return mutation;
                }
                const auto result = setActiveCalls == 1 ? activateResult : compensateResult;
                mutation.result = result;
                if (result == EnvironmentProfileStore::SaveResult::Success) {
                    storedActive = kind;
                    generation = QStringLiteral("generation-%1").arg(++generationCounter);
                    mutation.resultingGeneration = generation;
                    mutation.promotedProfile = profile(kind);
                }
                return mutation;
            },
            [this](const QString& expected) {
                ++verifyCalls;
                startupReconciliationPending = false;
                if (verifyResult != EnvironmentProfileStore::SaveResult::Success) return verifyResult;
                if (expected != generation)
                    return EnvironmentProfileStore::SaveResult::ConcurrentModification;
                if (advanceGenerationAfterVerify || advanceGenerationAfterStandaloneVerify)
                    generation = QStringLiteral("generation-advanced");
                return EnvironmentProfileStore::SaveResult::Success;
            },
            [this](const QString& expected,
                   const EnvironmentProfileStore::VerifiedConsumer& consumer) {
                ++verifyCalls;
                if (verifyResult != EnvironmentProfileStore::SaveResult::Success) return verifyResult;
                if (expected != generation)
                    return EnvironmentProfileStore::SaveResult::ConcurrentModification;
                const auto active = profile(storedActive);
                if (!active)
                    return EnvironmentProfileStore::SaveResult::InvalidProfile;
                const bool accepted = consumer({storedActive, generation, *active});
                if (advanceGenerationAfterVerify)
                    generation = QStringLiteral("generation-advanced");
                return accepted ? EnvironmentProfileStore::SaveResult::Success
                                : EnvironmentProfileStore::SaveResult::InvalidProfile;
            },
            [this] { return currentLayout; },
            [this](const EnvironmentProfile::Layout& layout) {
                if (startupReconciliationPending) {
                    ++startupApplyCalls;
                    if (startupApplySucceeds) currentLayout = layout;
                    return startupApplySucceeds;
                }
                ++applyCalls;
                order.push_back(QStringLiteral("apply"));
                const bool succeeds = applyCalls == 1 ? applySucceeds : rollbackApplySucceeds;
                if (succeeds) currentLayout = layout;
                return succeeds;
            },
            [this](const QUuid& uuid) { return permissions.value(uuid, DevicePermissions::None); },
            [this](const QUuid& uuid, DevicePermissions::Permission permission) {
                return (permissions.value(uuid, DevicePermissions::None) & static_cast<DevicePermissions::Mask>(permission)) != 0;
            },
            [this] { return busy; },
            [this] { return external; },
            [this] { return storedProfiles; },
            [this](const QList<EnvironmentProfile>& replacements,
                   EnvironmentProfile::Kind active, const QString& expected,
                   const std::optional<QString>& recoveryGeneration) {
                ++replaceAllCalls;
                recoveryOverrides.push_back(recoveryGeneration);
                EnvironmentProfileStore::Mutation mutation;
                mutation.previousGeneration = expected;
                mutation.resultingGeneration = generation;
                if (expected != generation) {
                    mutation.result = EnvironmentProfileStore::SaveResult::ConcurrentModification;
                    return mutation;
                }
                mutation.result = replaceAllResult;
                if (replaceAllResult == EnvironmentProfileStore::SaveResult::Success) {
                    storedProfiles = replacements;
                    storedActive = active;
                    generation = QStringLiteral("generation-%1").arg(++generationCounter);
                    mutation.resultingGeneration = generation;
                }
                return mutation;
            },
            [this] {
                ++recoveryCalls;
                if (recoveryResult == EnvironmentProfileStore::RecoveryResult::Recovered &&
                    !recoveryLeavesInvalid)
                    status = EnvironmentProfileStore::LoadStatus::Loaded;
                return recoveryResult;
            }
        };
    }
};
}

TEST(EnvironmentProfileControllerTests, MissingStoreCapturesClonesAndAppliesVerifiedLayoutBeforeOpeningGate)
{
    Harness h;
    h.status = EnvironmentProfileStore::LoadStatus::Missing;
    h.permissions[firstUuid] = DevicePermissions::ControlMouseKeyboard | DevicePermissions::OpenSafeFiles;
    EnvironmentProfileController controller(h.services());

    ASSERT_TRUE(controller.initialize());
    EXPECT_EQ(h.initializeCalls, 1);
    EXPECT_EQ(h.startupApplyCalls, 1);
    EXPECT_EQ(h.applyCalls, 0);
    EXPECT_EQ(h.storedProfiles.size(), 4);
    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Home);
    for (const auto& profile : h.storedProfiles) {
        ASSERT_TRUE(profile.isValid());
        EXPECT_EQ(profile.devices.front().requestedResources, DevicePermissions::ControlMouseKeyboard);
    }
}

TEST(EnvironmentProfileControllerTests, MissingStoreRejectsInvalidLegacySnapshotWithoutWriting)
{
    Harness h;
    h.status = EnvironmentProfileStore::LoadStatus::Missing;
    h.currentLayout.gridTechnicalNames = {QStringLiteral("mismatch")};
    EnvironmentProfileController controller(h.services());
    EXPECT_FALSE(controller.initialize());
    EXPECT_EQ(h.initializeCalls, 0);
    EXPECT_EQ(h.applyCalls, 0);
}

TEST(EnvironmentProfileControllerTests, StartupKeepsGateClosedInsideVerifiedConsumerUntilFinalVerification)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    h.storedProfiles.front().devices.front().requestedResources = DevicePermissions::SendFiles;
    auto services = h.services();
    EnvironmentProfileController* controllerProbe = nullptr;
    int consumeCalls = 0;
    bool firstConsumeGateOpen = true;
    bool finalConsumeGateOpen = false;
    services.consumeVerifiedGeneration =
        [&](const QString& expected,
            const EnvironmentProfileStore::VerifiedConsumer& consumer) {
            if (expected != h.generation)
                return EnvironmentProfileStore::SaveResult::ConcurrentModification;
            const auto profile = h.profile(h.storedActive);
            if (!profile)
                return EnvironmentProfileStore::SaveResult::InvalidProfile;
            ++consumeCalls;
            const bool consumed = consumer({h.storedActive, h.generation, *profile});
            const bool gateOpen = controllerProbe && controllerProbe->effectiveAllows(
                firstUuid, DevicePermissions::SendFiles);
            if (consumeCalls == 1)
                firstConsumeGateOpen = gateOpen;
            else if (consumeCalls == 2)
                finalConsumeGateOpen = gateOpen;
            return consumed ? EnvironmentProfileStore::SaveResult::Success
                            : EnvironmentProfileStore::SaveResult::InvalidProfile;
        };
    EnvironmentProfileController controller(std::move(services));
    controllerProbe = &controller;

    EXPECT_TRUE(controller.initialize());
    EXPECT_EQ(consumeCalls, 2);
    EXPECT_FALSE(firstConsumeGateOpen);
    EXPECT_FALSE(finalConsumeGateOpen);
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, LoadedStartupReconcilesRuntimeLayoutToPersistedActiveBeforeOpeningGate)
{
    Harness h;
    h.storedActive = EnvironmentProfile::Kind::Travel;
    const auto travel = validProfile(
        EnvironmentProfile::Kind::Travel, secondUuid, QStringLiteral("travel"));
    for (auto& profile : h.storedProfiles) {
        if (profile.kind == EnvironmentProfile::Kind::Travel) profile = travel;
    }
    for (auto& profile : h.storedProfiles) {
        if (profile.kind == EnvironmentProfile::Kind::Travel)
            profile.devices.front().requestedResources = DevicePermissions::SendFiles;
    }
    h.permissions[secondUuid] = DevicePermissions::SendFiles;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Travel);
    EXPECT_TRUE(controller.effectiveAllows(secondUuid, DevicePermissions::SendFiles));
    EXPECT_EQ(h.initializeCalls, 0);
    EXPECT_EQ(h.replaceCalls, 0);
    EXPECT_EQ(h.startupApplyCalls, 1);
    EXPECT_EQ(h.applyCalls, 0);
    expectLayoutEqual(h.currentLayout, travel.layout);

    controller.invalidate();
    EXPECT_FALSE(controller.effectiveAllows(secondUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, LoadedStartupApplyFailurePreservesLegacyLayoutAndKeepsGateClosed)
{
    Harness h;
    const auto legacyLayout = h.currentLayout;
    h.storedActive = EnvironmentProfile::Kind::Travel;
    const auto travel = validProfile(
        EnvironmentProfile::Kind::Travel, secondUuid, QStringLiteral("travel"));
    for (auto& profile : h.storedProfiles) {
        if (profile.kind == EnvironmentProfile::Kind::Travel) profile = travel;
    }
    h.permissions[secondUuid] = DevicePermissions::SendFiles;
    h.startupApplySucceeds = false;
    EnvironmentProfileController controller(h.services());

    EXPECT_FALSE(controller.initialize());
    EXPECT_EQ(h.startupApplyCalls, 1);
    EXPECT_EQ(h.applyCalls, 0);
    expectLayoutEqual(h.currentLayout, legacyLayout);
    EXPECT_FALSE(controller.collectionSnapshot().has_value());
    EXPECT_FALSE(controller.effectiveAllows(secondUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, CaptureUsesExactLayoutUuidsAndManagedGlobalPermissionsOnly)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::ReceiveFiles | DevicePermissions::OpenSafeFiles;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    EXPECT_EQ(controller.capture(EnvironmentProfile::Kind::Office), EnvironmentProfileController::Result::Success);
    const auto captured = h.profile(EnvironmentProfile::Kind::Office);
    ASSERT_TRUE(captured.has_value());
    ASSERT_EQ(captured->devices.size(), 1);
    EXPECT_EQ(captured->devices.front().uuid, firstUuid);
    EXPECT_EQ(captured->devices.front().requestedResources, DevicePermissions::ReceiveFiles);

    h.currentLayout = validProfile(EnvironmentProfile::Kind::Home, secondUuid, QStringLiteral("unknown")).layout;
    EXPECT_EQ(controller.capture(EnvironmentProfile::Kind::Travel), EnvironmentProfileController::Result::Success);
    EXPECT_EQ(h.profile(EnvironmentProfile::Kind::Travel)->devices.front().requestedResources, DevicePermissions::None);
}

TEST(EnvironmentProfileControllerTests, CapturingActiveProfileRepublishesAuthorizationSnapshot)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    h.permissions[secondUuid] = DevicePermissions::SendFiles;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    ASSERT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));

    h.currentLayout = validProfile(EnvironmentProfile::Kind::Home, secondUuid,
                                   QStringLiteral("beta")).layout;

    ASSERT_EQ(controller.capture(EnvironmentProfile::Kind::Home),
              EnvironmentProfileController::Result::Success);
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    EXPECT_TRUE(controller.effectiveAllows(secondUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, CapturingInactiveProfileKeepsCoherentAuthorizationOpen)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    const auto originalReplace = services.replaceProfileIfGeneration;
    EnvironmentProfileController* controllerProbe = nullptr;
    bool authorizationOpenDuringInactiveCapture = false;
    services.replaceProfileIfGeneration =
        [&](const EnvironmentProfile& replacement, const QString& expected,
            const std::optional<QString>& recoveryGeneration) {
            EXPECT_NE(controllerProbe, nullptr);
            authorizationOpenDuringInactiveCapture = controllerProbe->effectiveAllows(
                firstUuid, DevicePermissions::SendFiles);
            return originalReplace(replacement, expected, recoveryGeneration);
        };
    EnvironmentProfileController controller(std::move(services));
    controllerProbe = &controller;
    ASSERT_TRUE(controller.initialize());
    ASSERT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));

    EXPECT_EQ(controller.capture(EnvironmentProfile::Kind::Office),
              EnvironmentProfileController::Result::Success);
    EXPECT_TRUE(authorizationOpenDuringInactiveCapture);
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, CaptureClosesPreviousAuthorizationBeforePersistence)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    const auto originalReplace = services.replaceProfileIfGeneration;
    EnvironmentProfileController* controllerProbe = nullptr;
    bool gateClosedInsidePersistence = false;
    services.replaceProfileIfGeneration =
        [&](const EnvironmentProfile& profile, const QString& generation,
            const std::optional<QString>& recovery) {
            gateClosedInsidePersistence = controllerProbe &&
                !controllerProbe->effectiveAllows(
                    firstUuid, DevicePermissions::SendFiles);
            return originalReplace(profile, generation, recovery);
        };
    EnvironmentProfileController controller(std::move(services));
    controllerProbe = &controller;
    ASSERT_TRUE(controller.initialize());
    ASSERT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));

    EXPECT_EQ(controller.capture(EnvironmentProfile::Kind::Home),
              EnvironmentProfileController::Result::Success);
    EXPECT_TRUE(gateClosedInsidePersistence);
}

TEST(EnvironmentProfileControllerTests, CapturingActiveProfilePublishesInsideFinalVerifiedConsumerAfterPostCheck)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    h.permissions[secondUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    const auto originalConsume = services.consumeVerifiedGeneration;
    EnvironmentProfileController* controllerProbe = nullptr;
    bool startupComplete = false;
    QList<bool> capturedAuthorizationOpenInsideConsumers;
    services.consumeVerifiedGeneration =
        [&](const QString& expected,
            const EnvironmentProfileStore::VerifiedConsumer& consumer) {
            return originalConsume(expected,
                [&](const EnvironmentProfileStore::VerifiedState& state) {
                    const bool accepted = consumer(state);
                    if (startupComplete && controllerProbe) {
                        capturedAuthorizationOpenInsideConsumers.push_back(
                            controllerProbe->effectiveAllows(
                                secondUuid, DevicePermissions::SendFiles));
                    }
                    return accepted;
                });
        };
    EnvironmentProfileController controller(std::move(services));
    controllerProbe = &controller;
    ASSERT_TRUE(controller.initialize());
    startupComplete = true;

    h.currentLayout = validProfile(EnvironmentProfile::Kind::Home, secondUuid,
                                   QStringLiteral("beta")).layout;
    ASSERT_EQ(controller.capture(EnvironmentProfile::Kind::Home),
              EnvironmentProfileController::Result::Success);

    EXPECT_EQ(capturedAuthorizationOpenInsideConsumers, QList<bool>({false, true}));
    EXPECT_TRUE(controller.effectiveAllows(secondUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, EffectiveAllowsIsExactFailClosedIntersection)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::ControlMouseKeyboard | DevicePermissions::SendFiles |
                               DevicePermissions::OpenSafeFiles;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::ControlMouseKeyboard));
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::ReceiveFiles));
    EXPECT_FALSE(controller.effectiveAllows(secondUuid, DevicePermissions::SendFiles));
    EXPECT_FALSE(controller.effectiveAllows({}, DevicePermissions::SendFiles));
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::OpenSafeFiles));
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, static_cast<DevicePermissions::Permission>(1u << 30)));
}

TEST(EnvironmentProfileControllerTests, GlobalRevocationImmediatelyOverridesActiveProfileWithoutReactivation)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    ASSERT_EQ(controller.activate(EnvironmentProfile::Kind::Office,
                                  EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::Success);
    ASSERT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Office);
    ASSERT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));

    h.permissions[firstUuid] = DevicePermissions::None;

    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Office);
    EXPECT_EQ(h.setActiveCalls, 1);
}

TEST(EnvironmentProfileControllerTests, NetworkBusyAndExternalActivationAreSideEffectFree)
{
    Harness h;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    int emittedCount = 0;
    QObject::connect(&controller, &EnvironmentProfileController::activeProfileChanged, [&] { ++emittedCount; });

    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office, EnvironmentProfileController::ActivationSource::Network),
              EnvironmentProfileController::Result::AutomationRequiresConsent);
    h.busy = true;
    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office, EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::Busy);
    h.busy = false; h.external = true;
    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office, EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::ExternalConfigUnsupported);
    EXPECT_EQ(h.setActiveCalls, 0);
    EXPECT_EQ(h.applyCalls, 0);
    EXPECT_EQ(emittedCount, 0);
}

TEST(EnvironmentProfileControllerTests, CaptureRejectsTwoUuidsSharingOneTechnicalNameWithoutAuthorizingByName)
{
    Harness h;
    ScreenLayout::Device first;
    first.uuid = firstUuid;
    first.technicalName = QStringLiteral("duplicate");
    first.geometry = QRect(0, 0, 100, 100);
    ScreenLayout::Device second;
    second.uuid = secondUuid;
    second.technicalName = QStringLiteral("duplicate");
    second.geometry = QRect(100, 0, 100, 100);
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    h.permissions[secondUuid] = DevicePermissions::ReceiveFiles;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    h.currentLayout.columns = 2;
    h.currentLayout.rows = 1;
    h.currentLayout.gridTechnicalNames = {
        QStringLiteral("duplicate"), QStringLiteral("duplicate")};
    h.currentLayout.extension = ScreenLayout({first, second});

    EXPECT_EQ(controller.capture(EnvironmentProfile::Kind::Travel),
              EnvironmentProfileController::Result::InvalidProfile);
    EXPECT_EQ(h.replaceCalls, 0);
    EXPECT_EQ(h.profile(EnvironmentProfile::Kind::Travel)->devices.size(), 1);
}

TEST(EnvironmentProfileControllerTests, InvalidProfileAndPersistenceFailurePrecedeApplyAndSignal)
{
    Harness h;
    h.storedProfiles[1].layout.columns = 0;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office, EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::InvalidProfile);
    EXPECT_EQ(h.setActiveCalls, 0);

    h.storedProfiles[1] = validProfile(EnvironmentProfile::Kind::Office);
    h.activateResult = EnvironmentProfileStore::SaveResult::SettingsError;
    int emittedCount = 0;
    QObject::connect(&controller, &EnvironmentProfileController::activeProfileChanged, [&] { ++emittedCount; });
    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office, EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::PersistenceError);
    EXPECT_EQ(h.applyCalls, 0);
    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Home);
    EXPECT_EQ(emittedCount, 0);
}

TEST(EnvironmentProfileControllerTests, SuccessOrdersPersistApplyEmit)
{
    Harness h;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    QObject::connect(&controller, &EnvironmentProfileController::activeProfileChanged,
                     [&] { h.order.push_back(QStringLiteral("emit")); });
    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office, EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::Success);
    EXPECT_EQ(h.order, QStringList({QStringLiteral("persist"), QStringLiteral("apply"), QStringLiteral("emit")}));
    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Office);
}

TEST(EnvironmentProfileControllerTests, ActivationClosesAuthorizationGateBeforeApplyingNewLayout)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    EnvironmentProfileController* controllerUnderTest = nullptr;
    const auto originalApply = services.applyLayout;
    bool gateWasClosedDuringActivationApply = false;
    services.applyLayout = [&](const EnvironmentProfile::Layout& layout) {
        if (!h.startupReconciliationPending) {
            EXPECT_NE(controllerUnderTest, nullptr);
            gateWasClosedDuringActivationApply = !controllerUnderTest->effectiveAllows(
                firstUuid, DevicePermissions::SendFiles);
        }
        return originalApply(layout);
    };
    EnvironmentProfileController controller(std::move(services));
    controllerUnderTest = &controller;
    ASSERT_TRUE(controller.initialize());
    ASSERT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));

    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office,
                                  EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::Success);
    EXPECT_TRUE(gateWasClosedDuringActivationApply);
}

TEST(EnvironmentProfileControllerTests, ActivationDetectsSecondStorePromotionAfterConsume)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("activation-post-consume.ini"));
    QSettings firstSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore first(firstSettings);
    auto persistedProfile = validProfile();
    ASSERT_TRUE(persistedProfile.layout.extension.updateMonitorsForDevice(
        firstUuid,
        {{QStringLiteral("primary"), QRect(0, 0, 100, 100), 1.0,
          Qt::PrimaryOrientation, true}}));
    ASSERT_EQ(first.initializeFromLegacy(persistedProfile),
              EnvironmentProfileStore::SaveResult::Success);
    QSettings secondSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore second(secondSettings);
    ASSERT_EQ(second.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);

    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    services.load = [&] { return first.load(); };
    services.profile = [&](EnvironmentProfile::Kind kind) { return first.profile(kind); };
    services.activeKind = [&] { return first.activeKind(); };
    services.currentGeneration = [&] { return first.currentGeneration(); };
    services.setActiveIfGeneration =
        [&](EnvironmentProfile::Kind kind, const QString& expected,
            const std::optional<QString>& recoveryGeneration) {
            return first.setActiveIfGeneration(kind, expected, recoveryGeneration);
        };
    bool startupComplete = false;
    bool promotedAfterActivationConsume = false;
    EnvironmentProfileController* controllerUnderTest = nullptr;
    bool gateOpenDuringPostConsumeVerification = false;
    services.verifyGeneration = [&](const QString& expected) {
        if (promotedAfterActivationConsume) {
            EXPECT_NE(controllerUnderTest, nullptr);
            gateOpenDuringPostConsumeVerification = controllerUnderTest->effectiveAllows(
                firstUuid, DevicePermissions::SendFiles);
        }
        return first.verifyGeneration(expected);
    };
    services.consumeVerifiedGeneration =
        [&](const QString& expected,
            const EnvironmentProfileStore::VerifiedConsumer& consumer) {
            const auto consumed = first.consumeVerifiedGeneration(expected, consumer);
            if (startupComplete && !promotedAfterActivationConsume &&
                consumed == EnvironmentProfileStore::SaveResult::Success) {
                EXPECT_EQ(second.load(), EnvironmentProfileStore::LoadStatus::Loaded);
                const auto secondGeneration = second.currentGeneration();
                EXPECT_TRUE(secondGeneration.has_value());
                if (secondGeneration) {
                    const auto concurrent = second.setActiveIfGeneration(
                        EnvironmentProfile::Kind::Travel, *secondGeneration);
                    EXPECT_EQ(concurrent.result, EnvironmentProfileStore::SaveResult::Success);
                    promotedAfterActivationConsume =
                        concurrent.result == EnvironmentProfileStore::SaveResult::Success;
                }
            }
            return consumed;
        };

    EnvironmentProfileController controller(std::move(services));
    controllerUnderTest = &controller;
    ASSERT_TRUE(controller.initialize());
    startupComplete = true;
    ASSERT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));

    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office,
                                  EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::ConcurrentModification);
    EXPECT_TRUE(promotedAfterActivationConsume);
    EXPECT_FALSE(gateOpenDuringPostConsumeVerification);
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, ActivationSignalPromotionCannotLeaveStaleAuthorizationOpen)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("activation-signal-promotion.ini"));
    QSettings firstSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore first(firstSettings);
    auto persistedProfile = validProfile();
    ASSERT_TRUE(persistedProfile.layout.extension.updateMonitorsForDevice(
        firstUuid,
        {{QStringLiteral("primary"), QRect(0, 0, 100, 100), 1.0,
          Qt::PrimaryOrientation, true}}));
    ASSERT_EQ(first.initializeFromLegacy(persistedProfile),
              EnvironmentProfileStore::SaveResult::Success);
    QSettings secondSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore second(secondSettings);
    ASSERT_EQ(second.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);

    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    services.load = [&] { return first.load(); };
    services.profile = [&](EnvironmentProfile::Kind kind) { return first.profile(kind); };
    services.activeKind = [&] { return first.activeKind(); };
    services.currentGeneration = [&] { return first.currentGeneration(); };
    services.setActiveIfGeneration =
        [&](EnvironmentProfile::Kind kind, const QString& expected,
            const std::optional<QString>& recoveryGeneration) {
            return first.setActiveIfGeneration(kind, expected, recoveryGeneration);
        };
    services.verifyGeneration =
        [&](const QString& expected) { return first.verifyGeneration(expected); };
    services.consumeVerifiedGeneration =
        [&](const QString& expected,
            const EnvironmentProfileStore::VerifiedConsumer& consumer) {
            return first.consumeVerifiedGeneration(expected, consumer);
        };

    EnvironmentProfileController controller(std::move(services));
    ASSERT_TRUE(controller.initialize());
    ASSERT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    bool promotedInSignal = false;
    QObject::connect(&controller, &EnvironmentProfileController::activeProfileChanged,
        [&](EnvironmentProfile::Kind) {
            EXPECT_EQ(second.load(), EnvironmentProfileStore::LoadStatus::Loaded);
            const auto generation = second.currentGeneration();
            ASSERT_TRUE(generation.has_value());
            const auto concurrent = second.setActiveIfGeneration(
                EnvironmentProfile::Kind::Travel, *generation);
            EXPECT_EQ(concurrent.result, EnvironmentProfileStore::SaveResult::Success);
            promotedInSignal = concurrent.result == EnvironmentProfileStore::SaveResult::Success;
        });

    const auto result = controller.activate(
        EnvironmentProfile::Kind::Office,
        EnvironmentProfileController::ActivationSource::Manual);

    EXPECT_TRUE(promotedInSignal);
    EXPECT_NE(result, EnvironmentProfileController::Result::Success);
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    ASSERT_EQ(second.load(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(second.activeKind(), EnvironmentProfile::Kind::Travel);
}

TEST(EnvironmentProfileControllerTests, ActivationFinalConsumerCannotPromotePastSealedPublicationBoundary)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("activation-final-consumer.ini"));
    QSettings firstSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore first(firstSettings);
    auto persistedProfile = validProfile();
    ASSERT_TRUE(persistedProfile.layout.extension.updateMonitorsForDevice(
        firstUuid,
        {{QStringLiteral("primary"), QRect(0, 0, 100, 100), 1.0,
          Qt::PrimaryOrientation, true}}));
    ASSERT_EQ(first.initializeFromLegacy(persistedProfile),
              EnvironmentProfileStore::SaveResult::Success);
    QSettings secondSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore second(secondSettings);
    ASSERT_EQ(second.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);

    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    services.load = [&] { return first.load(); };
    services.profile = [&](EnvironmentProfile::Kind kind) { return first.profile(kind); };
    services.activeKind = [&] { return first.activeKind(); };
    services.currentGeneration = [&] { return first.currentGeneration(); };
    services.setActiveIfGeneration =
        [&](EnvironmentProfile::Kind kind, const QString& expected,
            const std::optional<QString>& recoveryGeneration) {
            return first.setActiveIfGeneration(kind, expected, recoveryGeneration);
        };
    services.verifyGeneration =
        [&](const QString& expected) { return first.verifyGeneration(expected); };
    bool activationStarted = false;
    int activationConsumes = 0;
    bool promotionAttempted = false;
    auto promotionResult = EnvironmentProfileStore::SaveResult::SettingsError;
    services.consumeVerifiedGeneration =
        [&](const QString& expected,
            const EnvironmentProfileStore::VerifiedConsumer& consumer) {
            const auto consumed = first.consumeVerifiedGeneration(expected, consumer);
            if (activationStarted && ++activationConsumes == 2 &&
                consumed == EnvironmentProfileStore::SaveResult::Success) {
                promotionAttempted = true;
                EXPECT_EQ(second.load(), EnvironmentProfileStore::LoadStatus::Loaded);
                const auto generation = second.currentGeneration();
                EXPECT_TRUE(generation.has_value());
                if (generation) {
                    promotionResult = second.setActiveIfGeneration(
                        EnvironmentProfile::Kind::Travel, *generation).result;
                }
            }
            return consumed;
        };

    EnvironmentProfileController controller(std::move(services));
    ASSERT_TRUE(controller.initialize());
    activationStarted = true;

    EXPECT_EQ(controller.activate(
                  EnvironmentProfile::Kind::Office,
                  EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::Success);
    EXPECT_TRUE(promotionAttempted);
    EXPECT_NE(promotionResult, EnvironmentProfileStore::SaveResult::Success);
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    ASSERT_EQ(second.load(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(second.activeKind(), EnvironmentProfile::Kind::Office);
}

TEST(EnvironmentProfileControllerTests, ThrowingActivationSlotRestoresPreviousAuthorizationSnapshot)
{
    Harness h;
    h.storedProfiles[0].devices.front().requestedResources = DevicePermissions::None;
    h.storedProfiles[1].devices.front().requestedResources = DevicePermissions::SendFiles;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    ASSERT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    QObject::connect(&controller, &EnvironmentProfileController::activeProfileChanged,
                     [] { throw std::runtime_error("slot failed"); });

    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office,
                                  EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::PersistenceError);
    EXPECT_EQ(h.storedActive, EnvironmentProfile::Kind::Home);
    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Home);
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, ApplyFailureCompensatesPersistenceAndLeavesActiveAndLayoutUnchanged)
{
    Harness h;
    const auto original = h.currentLayout.gridTechnicalNames;
    h.applySucceeds = false;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    int emittedCount = 0;
    QObject::connect(&controller, &EnvironmentProfileController::activeProfileChanged, [&] { ++emittedCount; });
    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office, EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::PersistenceError);
    EXPECT_EQ(h.setActiveCalls, 2);
    ASSERT_EQ(h.recoveryOverrides.size(), 2);
    EXPECT_FALSE(h.recoveryOverrides[0].has_value());
    EXPECT_EQ(h.recoveryOverrides[1], QStringLiteral("generation-1"));
    EXPECT_EQ(h.storedActive, EnvironmentProfile::Kind::Home);
    EXPECT_EQ(h.currentLayout.gridTechnicalNames, original);
    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Home);
    EXPECT_EQ(emittedCount, 0);
}

TEST(EnvironmentProfileControllerTests, FailedCompensationSurfacesIndeterminateAndClosesGate)
{
    Harness h;
    h.applySucceeds = false;
    h.compensateResult = EnvironmentProfileStore::SaveResult::IndeterminateState;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office, EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::IndeterminateState);
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, InvalidAndFutureStartupFailClosedWithoutApplyingLegacyLayout)
{
    for (const auto status : {EnvironmentProfileStore::LoadStatus::InvalidSchema,
                              EnvironmentProfileStore::LoadStatus::FutureSchema,
                              EnvironmentProfileStore::LoadStatus::SettingsError}) {
        Harness h;
        h.status = status;
        if (status == EnvironmentProfileStore::LoadStatus::InvalidSchema)
            h.recoveryResult = EnvironmentProfileStore::RecoveryResult::Unavailable;
        EnvironmentProfileController controller(h.services());
        EXPECT_FALSE(controller.initialize());
        EXPECT_EQ(h.applyCalls, 0);
        EXPECT_EQ(h.recoveryCalls,
                  status == EnvironmentProfileStore::LoadStatus::InvalidSchema ? 1 : 0);
        EXPECT_FALSE(controller.recoveredOnInitialize());
        EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    }
}

TEST(EnvironmentProfileControllerTests, RecoveredStartupRevalidatesAndOpensGate)
{
    Harness h;
    h.status = EnvironmentProfileStore::LoadStatus::InvalidSchema;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    EnvironmentProfileController controller(h.services());

    ASSERT_TRUE(controller.initialize());
    EXPECT_EQ(h.recoveryCalls, 1);
    EXPECT_EQ(h.verifyCalls, 4);
    EXPECT_TRUE(controller.recoveredOnInitialize());
    EXPECT_TRUE(controller.collectionSnapshot().has_value());
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, ConcurrentPromotionDuringRecoveredStartupKeepsGateClosed)
{
    Harness h;
    h.status = EnvironmentProfileStore::LoadStatus::InvalidSchema;
    h.verifyResult = EnvironmentProfileStore::SaveResult::ConcurrentModification;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    EnvironmentProfileController controller(h.services());

    EXPECT_FALSE(controller.initialize());
    EXPECT_EQ(h.recoveryCalls, 1);
    EXPECT_EQ(h.verifyCalls, 1);
    EXPECT_FALSE(controller.recoveredOnInitialize());
    EXPECT_FALSE(controller.collectionSnapshot().has_value());
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, PromotionImmediatelyAfterVerificationKeepsGateClosed)
{
    Harness h;
    h.status = EnvironmentProfileStore::LoadStatus::InvalidSchema;
    h.advanceGenerationAfterStandaloneVerify = true;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    EnvironmentProfileController controller(h.services());

    EXPECT_FALSE(controller.initialize());
    EXPECT_EQ(h.recoveryCalls, 1);
    EXPECT_EQ(h.verifyCalls, 3);
    EXPECT_FALSE(controller.collectionSnapshot().has_value());
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, DurableReadbackDetectsSecondStorePromotionAfterConsume)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("profiles.ini"));
    QSettings firstSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore first(firstSettings);
    auto persistedProfile = validProfile();
    ASSERT_TRUE(persistedProfile.layout.extension.updateMonitorsForDevice(
        firstUuid,
        {{QStringLiteral("primary"), QRect(0, 0, 100, 100), 1.0,
          Qt::PrimaryOrientation, true}}));
    ASSERT_EQ(first.initializeFromLegacy(persistedProfile),
              EnvironmentProfileStore::SaveResult::Success);
    QSettings secondSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore second(secondSettings);
    ASSERT_EQ(second.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);

    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    services.load = [&] { return first.load(); };
    services.profile = [&](EnvironmentProfile::Kind kind) { return first.profile(kind); };
    services.activeKind = [&] { return first.activeKind(); };
    services.currentGeneration = [&] { return first.currentGeneration(); };
    services.consumeVerifiedGeneration =
        [&](const QString& expected,
            const EnvironmentProfileStore::VerifiedConsumer& consumer) {
            const auto consumed = first.consumeVerifiedGeneration(expected, consumer);
            if (consumed == EnvironmentProfileStore::SaveResult::Success) {
                EXPECT_EQ(second.load(), EnvironmentProfileStore::LoadStatus::Loaded);
                const auto secondGeneration = second.currentGeneration();
                EXPECT_TRUE(secondGeneration.has_value());
                if (secondGeneration) {
                    const auto mutation = second.setActiveIfGeneration(
                        EnvironmentProfile::Kind::Office, *secondGeneration);
                    EXPECT_EQ(mutation.result, EnvironmentProfileStore::SaveResult::Success);
                }
            }
            return consumed;
        };
    services.verifyGeneration =
        [&](const QString& expected) { return first.verifyGeneration(expected); };

    EnvironmentProfileController controller(std::move(services));

    EXPECT_FALSE(controller.initialize());
    EXPECT_FALSE(controller.collectionSnapshot().has_value());
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, StartupFinalVerificationCannotPromotePastSealedPublicationBoundary)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("startup-final-verification.ini"));
    QSettings firstSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore first(firstSettings);
    auto persistedProfile = validProfile();
    ASSERT_TRUE(persistedProfile.layout.extension.updateMonitorsForDevice(
        firstUuid,
        {{QStringLiteral("primary"), QRect(0, 0, 100, 100), 1.0,
          Qt::PrimaryOrientation, true}}));
    ASSERT_EQ(first.initializeFromLegacy(persistedProfile),
              EnvironmentProfileStore::SaveResult::Success);
    QSettings secondSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore second(secondSettings);
    ASSERT_EQ(second.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);

    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    services.load = [&] { return first.load(); };
    services.profile = [&](EnvironmentProfile::Kind kind) { return first.profile(kind); };
    services.activeKind = [&] { return first.activeKind(); };
    services.currentGeneration = [&] { return first.currentGeneration(); };
    services.consumeVerifiedGeneration =
        [&](const QString& expected,
            const EnvironmentProfileStore::VerifiedConsumer& consumer) {
            return first.consumeVerifiedGeneration(expected, consumer);
        };
    int standaloneVerifications = 0;
    bool promotionAttempted = false;
    auto promotionResult = EnvironmentProfileStore::SaveResult::SettingsError;
    services.verifyGeneration = [&](const QString& expected) {
        const auto verified = first.verifyGeneration(expected);
        ++standaloneVerifications;
        if (standaloneVerifications == 2 &&
            verified == EnvironmentProfileStore::SaveResult::Success) {
            promotionAttempted = true;
            EXPECT_EQ(second.load(), EnvironmentProfileStore::LoadStatus::Loaded);
            const auto generation = second.currentGeneration();
            EXPECT_TRUE(generation.has_value());
            if (generation) {
                promotionResult = second.setActiveIfGeneration(
                    EnvironmentProfile::Kind::Travel, *generation).result;
            }
        }
        return verified;
    };

    EnvironmentProfileController controller(std::move(services));

    EXPECT_TRUE(controller.initialize());
    EXPECT_TRUE(promotionAttempted);
    EXPECT_NE(promotionResult, EnvironmentProfileStore::SaveResult::Success);
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    ASSERT_EQ(second.load(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(second.activeKind(), EnvironmentProfile::Kind::Home);
}

TEST(EnvironmentProfileControllerTests, ClaimedRecoveryWithoutLoadedReadbackStaysClosed)
{
    Harness h;
    h.status = EnvironmentProfileStore::LoadStatus::InvalidSchema;
    h.recoveryLeavesInvalid = true;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    EnvironmentProfileController controller(h.services());

    EXPECT_FALSE(controller.initialize());
    EXPECT_EQ(h.recoveryCalls, 1);
    EXPECT_FALSE(controller.recoveredOnInitialize());
    EXPECT_FALSE(controller.collectionSnapshot().has_value());
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, AuthorizationGateRemainsClosedThroughFinalGenerationVerification)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    EnvironmentProfileController* controllerUnderTest = nullptr;
    const auto originalVerify = services.verifyGeneration;
    QList<bool> authorizationOpenDuringVerify;
    services.verifyGeneration = [&](const QString& generation) {
        EXPECT_NE(controllerUnderTest, nullptr);
        authorizationOpenDuringVerify.push_back(controllerUnderTest->effectiveAllows(
            firstUuid, DevicePermissions::SendFiles));
        return originalVerify(generation);
    };
    EnvironmentProfileController controller(std::move(services));
    controllerUnderTest = &controller;

    ASSERT_TRUE(controller.initialize());
    EXPECT_EQ(authorizationOpenDuringVerify, QList<bool>({false, false}));
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, CapturePersistenceFailurePreservesStoreAndSignalButClosesGate)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    const auto storedHomeBefore = h.profile(EnvironmentProfile::Kind::Home);
    ASSERT_TRUE(storedHomeBefore);
    ASSERT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    h.currentLayout = validProfile(EnvironmentProfile::Kind::Home, secondUuid,
                                   QStringLiteral("replacement")).layout;
    h.replaceResult = EnvironmentProfileStore::SaveResult::SettingsError;
    QSignalSpy captured(&controller, &EnvironmentProfileController::profileCaptured);

    EXPECT_EQ(controller.capture(EnvironmentProfile::Kind::Home),
              EnvironmentProfileController::Result::PersistenceError);

    ASSERT_TRUE(h.profile(EnvironmentProfile::Kind::Home));
    expectLayoutEqual(h.profile(EnvironmentProfile::Kind::Home)->layout, storedHomeBefore->layout);
    EXPECT_EQ(h.profile(EnvironmentProfile::Kind::Home)->devices, storedHomeBefore->devices);
    EXPECT_EQ(h.replaceCalls, 1);
    EXPECT_EQ(h.storedActive, EnvironmentProfile::Kind::Home);
    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Home);
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    EXPECT_FALSE(controller.effectiveAllows(secondUuid, DevicePermissions::SendFiles));
    EXPECT_EQ(captured.count(), 0);
}

TEST(EnvironmentProfileControllerTests, TargetAndRollbackApplyFailureIsIndeterminateClosesGateAndDoesNotSignal)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    h.applySucceeds = false;
    h.rollbackApplySucceeds = false;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    ASSERT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    QSignalSpy changed(&controller, &EnvironmentProfileController::activeProfileChanged);

    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office,
                                  EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::IndeterminateState);
    EXPECT_EQ(h.applyCalls, 2);
    EXPECT_EQ(h.setActiveCalls, 2);
    EXPECT_EQ(h.storedActive, EnvironmentProfile::Kind::Home);
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    EXPECT_EQ(changed.count(), 0);
}

TEST(EnvironmentProfileControllerTests, EffectiveAllowsRequiresIndependentGlobalGrantForRequestedPresentUuid)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::None;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));

    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, RealMissingStoreCapturesFourProfilesWithoutTouchingLegacyRegistryOrSecrets)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("integrated.ini"));
    QSettings settings(path, QSettings::IniFormat);
    seedLegacyLayout(settings);
    DeviceRegistry registry(settings);
    seedRegistry(registry);
    ServerConfig serverConfig(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
    serverConfig.saveSettings();
    const QList<QPair<QString, QByteArray>> sentinels = {
        {QStringLiteral("internalConfig/credentialToken"), QByteArray("INTERNAL_SECRET\0BYTES", 21)},
        {QStringLiteral("deviceRegistry/privateKey"), QByteArray("REGISTRY_SECRET\0BYTES", 21)},
        {QStringLiteral("credentials/pairingPsk"), QByteArray("GLOBAL_SECRET\0BYTES", 19)},
    };
    for (const auto& sentinel : sentinels) settings.setValue(sentinel.first, sentinel.second);
    settings.sync();
    const SettingsValues internalBefore = settingsSubtree(settings, QStringLiteral("internalConfig"));
    const SettingsValues registryBefore = settingsSubtree(settings, QStringLiteral("deviceRegistry"));
    const auto layoutBefore = serverConfig.environmentLayoutSnapshot();
    EnvironmentProfileStore store(settings);
    ASSERT_EQ(store.loadStatus(), EnvironmentProfileStore::LoadStatus::Missing);
    EnvironmentProfileController controller(store, serverConfig, registry, firstUuid,
        [] { return false; }, [] { return false; });

    ASSERT_TRUE(controller.initialize());

    EXPECT_EQ(store.profiles().size(), 4);
    ASSERT_TRUE(store.activeKind());
    EXPECT_EQ(*store.activeKind(), EnvironmentProfile::Kind::Home);
    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Home);
    const auto registeredDevice = registry.find(firstUuid);
    ASSERT_TRUE(registeredDevice.has_value());
    EXPECT_EQ(registeredDevice->capabilities(), QStringList{capabilitySentinel});
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        const auto profile = store.profile(kind);
        ASSERT_TRUE(profile) << static_cast<int>(kind);
        EXPECT_EQ(profile->kind, kind);
        ASSERT_EQ(profile->devices.size(), 1);
        EXPECT_EQ(profile->devices.front().uuid, firstUuid);
        EXPECT_EQ(profile->devices.front().requestedResources,
                  DevicePermissions::ControlMouseKeyboard | DevicePermissions::SendFiles);
    }
    expectLayoutEqual(serverConfig.environmentLayoutSnapshot(), layoutBefore);
    expectSettingsValuesEqual(settingsSubtree(settings, QStringLiteral("internalConfig")), internalBefore);
    expectSettingsValuesEqual(settingsSubtree(settings, QStringLiteral("deviceRegistry")), registryBefore);
    for (const auto& sentinel : sentinels) {
        const QVariant value = settings.value(sentinel.first);
        EXPECT_EQ(value.metaType().id(), QMetaType::QByteArray) << sentinel.first.toStdString();
        EXPECT_EQ(value.toByteArray(), sentinel.second) << sentinel.first.toStdString();
    }
    for (const QString& key : settings.allKeys()) {
        if (!key.startsWith(QStringLiteral("environmentProfiles/"))) continue;
        const QString lower = key.toLower();
        EXPECT_FALSE(lower.contains(QStringLiteral("credential"))) << key.toStdString();
        EXPECT_FALSE(lower.contains(QStringLiteral("privatekey"))) << key.toStdString();
        EXPECT_FALSE(lower.contains(QStringLiteral("pairing"))) << key.toStdString();
        EXPECT_FALSE(lower.contains(QStringLiteral("psk"))) << key.toStdString();
        EXPECT_FALSE(settings.value(key).toString().contains(capabilitySentinel)) << key.toStdString();
        const QByteArray value = settings.value(key).toByteArray();
        for (const auto& sentinel : sentinels)
            EXPECT_FALSE(value.contains(sentinel.second)) << key.toStdString();
    }
}

TEST(EnvironmentProfileControllerTests, CaptureActivateAndReopenNeverTouchCredentialStoreOrPersistItsBytes)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("credential-sentinel.ini"));
    QSettings settings(path, QSettings::IniFormat);
    seedLegacyLayout(settings);
    DeviceRegistry registry(settings);
    seedRegistry(registry);
    ServerConfig serverConfig(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
    serverConfig.saveSettings();

    const QByteArray sentinel("CREDENTIAL_SENTINEL\0BINARY", 26);
    QMap<QString, QByteArray> credentials{{QStringLiteral("pairing-code"), sentinel}};
    int reads = 0;
    int writes = 0;
    int removes = 0;
    AppConfig appConfig(&settings, SecureCredentialStore(
        [&](const QString& account) -> std::optional<QByteArray> {
            ++reads;
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&](const QString& account, const QByteArray& value) {
            ++writes;
            credentials.insert(account, value);
            return true;
        },
        [&](const QString& account) {
            ++removes;
            credentials.remove(account);
            return true;
        }));
    Q_UNUSED(appConfig);
    const int baselineReads = reads;
    const int baselineWrites = writes;
    const int baselineRemoves = removes;

    {
        EnvironmentProfileStore store(settings);
        EnvironmentProfileController controller(store, serverConfig, registry, firstUuid,
            [] { return false; }, [] { return false; });
        ASSERT_TRUE(controller.initialize());
        ASSERT_EQ(controller.capture(EnvironmentProfile::Kind::Office),
                  EnvironmentProfileController::Result::Success);
        ASSERT_EQ(controller.activate(EnvironmentProfile::Kind::Office,
                                      EnvironmentProfileController::ActivationSource::Manual),
                  EnvironmentProfileController::Result::Success);
    }
    {
        EnvironmentProfileStore reopenedStore(settings);
        EnvironmentProfileController reopened(reopenedStore, serverConfig, registry, firstUuid,
            [] { return false; }, [] { return false; });
        ASSERT_TRUE(reopened.initialize());
        EXPECT_EQ(reopened.activeKind(), EnvironmentProfile::Kind::Office);
    }

    EXPECT_EQ(reads, baselineReads);
    EXPECT_EQ(writes, baselineWrites);
    EXPECT_EQ(removes, baselineRemoves);
    ASSERT_EQ(credentials.size(), 1);
    EXPECT_EQ(credentials.cbegin().value(), sentinel);
    settings.sync();
    EXPECT_FALSE(fileBytes(path).contains(sentinel));
}

TEST(EnvironmentProfileControllerTests, RealInvalidAndFutureStoreStartupIsBytePreservingAndNeverApplies)
{
    const QList<QVariant> schemas = {
        QStringLiteral("1"),
        EnvironmentProfileStore::SchemaVersion + 1,
    };
    for (const QVariant& schema : schemas) {
        QTemporaryDir directory;
        ASSERT_TRUE(directory.isValid());
        const QString path = directory.filePath(QStringLiteral("startup.ini"));
        QSettings settings(path, QSettings::IniFormat);
        seedLegacyLayout(settings);
        DeviceRegistry registry(settings);
        seedRegistry(registry);
        ServerConfig serverConfig(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
        serverConfig.saveSettings();
        settings.setValue(QStringLiteral("environmentProfiles/schemaVersion"), schema);
        settings.setValue(QStringLiteral("environmentProfiles/payload"), QByteArray("PRESERVE\0BYTES", 14));
        settings.sync();
        const auto layoutBefore = serverConfig.environmentLayoutSnapshot();
        const SettingsValues internalBefore = settingsSubtree(settings, QStringLiteral("internalConfig"));
        const SettingsValues registryBefore = settingsSubtree(settings, QStringLiteral("deviceRegistry"));
        const QByteArray bytesBefore = fileBytes(path);
        EnvironmentProfileStore store(settings);
        EnvironmentProfileController controller(store, serverConfig, registry, firstUuid,
            [] { return false; }, [] { return false; });

        EXPECT_FALSE(controller.initialize()) << schema.toString().toStdString();

        EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
        expectLayoutEqual(serverConfig.environmentLayoutSnapshot(), layoutBefore);
        expectSettingsValuesEqual(settingsSubtree(settings, QStringLiteral("internalConfig")), internalBefore);
        expectSettingsValuesEqual(settingsSubtree(settings, QStringLiteral("deviceRegistry")), registryBefore);
        settings.sync();
        EXPECT_EQ(fileBytes(path), bytesBefore) << schema.toString().toStdString();
    }
}

TEST(EnvironmentProfileControllerTests, TruncatedActiveGenerationPreservesLegacyLayoutAndClosesResourceGate)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("truncated-generation.ini"));
    QSettings settings(path, QSettings::IniFormat);
    seedLegacyLayout(settings);
    DeviceRegistry registry(settings);
    seedRegistry(registry);
    ServerConfig serverConfig(&settings, 1, 1, QStringLiteral("alpha"), nullptr);
    serverConfig.saveSettings();
    const auto legacyBefore = serverConfig.environmentLayoutSnapshot();
    EnvironmentProfile legacyProfile;
    legacyProfile.kind = EnvironmentProfile::Kind::Home;
    legacyProfile.layout = legacyBefore;
    legacyProfile.devices = {{firstUuid, QStringLiteral("alpha"), DevicePermissions::SendFiles}};
    ASSERT_TRUE(legacyProfile.isValid());
    {
        EnvironmentProfileStore initial(settings);
        ASSERT_EQ(initial.initializeFromLegacy(legacyProfile), EnvironmentProfileStore::SaveResult::Success);
    }
    const QString active = settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString();
    ASSERT_FALSE(active.isEmpty());
    settings.remove(QStringLiteral("environmentProfiles/generations/") + active +
                    QStringLiteral("/profiles/1/columns"));
    settings.sync();

    EnvironmentProfileStore truncated(settings);
    ASSERT_EQ(truncated.loadStatus(), EnvironmentProfileStore::LoadStatus::InvalidSchema);
    EnvironmentProfileController controller(truncated, serverConfig, registry, firstUuid,
        [] { return false; }, [] { return false; });

    EXPECT_FALSE(controller.initialize());
    expectLayoutEqual(serverConfig.environmentLayoutSnapshot(), legacyBefore);
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    EXPECT_EQ(settings.value(QStringLiteral("environmentProfiles/activeGeneration")).toString(), active);
}

TEST(EnvironmentProfileControllerTests, EveryRequiredServiceIsFailClosedAtInitialization)
{
    Harness h;
    for (int missing = 0; missing < 13; ++missing) {
        auto s = h.services();
        switch (missing) {
        case 0: s.load = {}; break; case 1: s.profile = {}; break; case 2: s.activeKind = {}; break;
        case 3: s.currentGeneration = {}; break; case 4: s.initializeFromLegacy = {}; break;
        case 5: s.replaceProfileIfGeneration = {}; break; case 6: s.setActiveIfGeneration = {}; break;
        case 7: s.verifyGeneration = {}; break; case 8: s.snapshotLayout = {}; break;
        case 9: s.applyLayout = {}; break; case 10: s.permissions = {}; break;
        case 11: s.isBusy = {}; break; case 12: s.usesExternalConfig = {}; break;
        }
        EnvironmentProfileController controller(std::move(s));
        EXPECT_FALSE(controller.initialize()) << missing;
        EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    }
}

TEST(EnvironmentProfileControllerTests, StaleGenerationBeforeActivationFailsClosedWithoutApplyOrSignal)
{
    Harness h; EnvironmentProfileController controller(h.services()); ASSERT_TRUE(controller.initialize());
    h.generation = QStringLiteral("writer-b"); QSignalSpy changed(&controller, &EnvironmentProfileController::activeProfileChanged);
    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office, EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::ConcurrentModification);
    EXPECT_EQ(h.applyCalls, 0); EXPECT_EQ(h.storedActive, EnvironmentProfile::Kind::Home);
    EXPECT_EQ(changed.count(), 0); EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, ConcurrentWriterBetweenPersistAndVerifyRestoresLayoutWithoutOverwritingWriter)
{
    Harness h; const auto previousLayout = h.currentLayout; auto s = h.services();
    s.applyLayout = [&h](const EnvironmentProfile::Layout& layout) {
        if (h.startupReconciliationPending) {
            ++h.startupApplyCalls; h.currentLayout = layout; return true;
        }
        ++h.applyCalls; h.currentLayout = layout;
        if (h.applyCalls == 1) { h.generation = QStringLiteral("writer-b"); h.storedActive = EnvironmentProfile::Kind::Travel; }
        return true;
    };
    EnvironmentProfileController controller(std::move(s)); ASSERT_TRUE(controller.initialize());
    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office, EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::ConcurrentModification);
    EXPECT_EQ(h.applyCalls, 2); expectLayoutEqual(h.currentLayout, previousLayout);
    EXPECT_EQ(h.storedActive, EnvironmentProfile::Kind::Travel); EXPECT_EQ(h.generation, QStringLiteral("writer-b"));
}

TEST(EnvironmentProfileControllerTests, ConcurrentWriterDuringRollbackIsNeverOverwrittenAndClosesGate)
{
    Harness h; auto s = h.services();
    s.applyLayout = [&h](const EnvironmentProfile::Layout& layout) {
        if (h.startupReconciliationPending) {
            ++h.startupApplyCalls; h.currentLayout = layout; return true;
        }
        ++h.applyCalls; if (h.applyCalls == 1) return false;
        h.currentLayout = layout; h.generation = QStringLiteral("writer-b"); h.storedActive = EnvironmentProfile::Kind::Travel; return true;
    };
    EnvironmentProfileController controller(std::move(s)); ASSERT_TRUE(controller.initialize());
    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office, EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::IndeterminateState);
    EXPECT_EQ(h.storedActive, EnvironmentProfile::Kind::Travel); EXPECT_EQ(h.generation, QStringLiteral("writer-b"));
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, ReentrantApplyAndSignalAreRejectedWithoutNestedMutation)
{
    Harness h; auto s = h.services(); EnvironmentProfileController* address = nullptr;
    auto applyReentrant = EnvironmentProfileController::Result::Success;
    s.applyLayout = [&h, &address, &applyReentrant](const EnvironmentProfile::Layout& layout) {
        if (h.startupReconciliationPending) {
            ++h.startupApplyCalls; h.currentLayout = layout; return true;
        }
        ++h.applyCalls; h.currentLayout = layout; applyReentrant = address->capture(EnvironmentProfile::Kind::Travel); return true;
    };
    EnvironmentProfileController controller(std::move(s)); address = &controller; ASSERT_TRUE(controller.initialize());
    auto signalReentrant = EnvironmentProfileController::Result::Success;
    QObject::connect(&controller, &EnvironmentProfileController::activeProfileChanged,
                     [&] { signalReentrant = controller.capture(EnvironmentProfile::Kind::Travel); });
    EXPECT_EQ(controller.activate(EnvironmentProfile::Kind::Office, EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::Success);
    EXPECT_EQ(applyReentrant, EnvironmentProfileController::Result::Reentrant);
    EXPECT_EQ(signalReentrant, EnvironmentProfileController::Result::Reentrant);
    EXPECT_EQ(h.replaceCalls, 0); EXPECT_EQ(h.setActiveCalls, 1);
}

TEST(EnvironmentProfileControllerTests, WrongThreadOperationsCloseGateWithoutCallingServicesOrCleaningOwnerState)
{
    const auto exercise = [](auto invoke, EnvironmentProfileController::Result expected) {
        Harness h;
        h.storedActive = EnvironmentProfile::Kind::Travel;
        h.permissions[firstUuid] = DevicePermissions::SendFiles;
        auto services = h.services();
        std::atomic_int loadCalls = 0;
        const auto originalLoad = services.load;
        services.load = [originalLoad, &loadCalls] {
            ++loadCalls;
            return originalLoad();
        };
        EnvironmentProfileController controller(std::move(services));
        ASSERT_TRUE(controller.initialize());
        ASSERT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Travel);
        ASSERT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));

        auto result = EnvironmentProfileController::Result::Success;
        std::thread worker([&] { result = invoke(controller); });
        worker.join();

        EXPECT_EQ(result, expected);
        EXPECT_EQ(loadCalls.load(), 1);
        EXPECT_EQ(h.replaceCalls, 0);
        EXPECT_EQ(h.setActiveCalls, 0);
        EXPECT_EQ(h.applyCalls, 0);
        EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Travel);
        EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    };

    exercise([](EnvironmentProfileController& controller) {
        return controller.initialize() ? EnvironmentProfileController::Result::Success
                                       : EnvironmentProfileController::Result::WrongThread;
    }, EnvironmentProfileController::Result::WrongThread);
    exercise([](EnvironmentProfileController& controller) {
        return controller.capture(EnvironmentProfile::Kind::Office);
    }, EnvironmentProfileController::Result::WrongThread);
    exercise([](EnvironmentProfileController& controller) {
        return controller.activate(EnvironmentProfile::Kind::Office,
                                   EnvironmentProfileController::ActivationSource::Manual);
    }, EnvironmentProfileController::Result::WrongThread);
}

TEST(EnvironmentProfileControllerTests, WrongThreadActivationAtomicallyClosesGateWhilePermissionCheckIsInFlight)
{
    Harness h;
    h.storedActive = EnvironmentProfile::Kind::Travel;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    std::mutex mutex;
    std::condition_variable entered;
    std::condition_variable release;
    bool permissionEntered = false;
    bool permissionReleased = false;
    std::atomic_int allowsCalls = 0;
    services.allows = [&](const QUuid&, DevicePermissions::Permission) {
        ++allowsCalls;
        std::unique_lock lock(mutex);
        permissionEntered = true;
        entered.notify_one();
        release.wait(lock, [&] { return permissionReleased; });
        return true;
    };
    EnvironmentProfileController controller(std::move(services));
    ASSERT_TRUE(controller.initialize());

    bool inFlightAllowed = false;
    std::thread reader([&] {
        inFlightAllowed = controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles);
    });
    {
        std::unique_lock lock(mutex);
        ASSERT_TRUE(entered.wait_for(lock, std::chrono::seconds(5), [&] { return permissionEntered; }));
    }

    auto activation = EnvironmentProfileController::Result::Success;
    std::thread worker([&] {
        activation = controller.activate(EnvironmentProfile::Kind::Office,
                                         EnvironmentProfileController::ActivationSource::Manual);
    });
    worker.join();

    EXPECT_EQ(activation, EnvironmentProfileController::Result::WrongThread);
    EXPECT_EQ(h.setActiveCalls, 0);
    EXPECT_EQ(h.applyCalls, 0);
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    EXPECT_EQ(allowsCalls.load(), 1);
    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Travel);

    {
        std::lock_guard lock(mutex);
        permissionReleased = true;
    }
    release.notify_one();
    reader.join();
    EXPECT_TRUE(inFlightAllowed);
}

TEST(EnvironmentProfileControllerTests, ActiveKindDoesNotReadOwnerStateFromWrongThread)
{
    Harness h;
    h.storedActive = EnvironmentProfile::Kind::Travel;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());

    auto observed = EnvironmentProfile::Kind::Travel;
    std::thread worker([&] { observed = controller.activeKind(); });
    worker.join();

    EXPECT_EQ(observed, EnvironmentProfile::Kind::Home);
    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Travel);
}

TEST(EnvironmentProfileControllerTests, OwnerRecoveryReopensOnlyAfterInitializeOrActivationNotCapture)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());

    auto captureResult = EnvironmentProfileController::Result::Success;
    std::thread wrongCapture([&] {
        captureResult = controller.capture(EnvironmentProfile::Kind::Office);
    });
    wrongCapture.join();
    ASSERT_EQ(captureResult, EnvironmentProfileController::Result::WrongThread);
    ASSERT_EQ(controller.capture(EnvironmentProfile::Kind::Office),
              EnvironmentProfileController::Result::Success);
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));

    ASSERT_EQ(controller.activate(EnvironmentProfile::Kind::Office,
                                  EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::Success);
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));

    bool initializedOnWrongThread = true;
    std::thread wrongInitialize([&] { initializedOnWrongThread = controller.initialize(); });
    wrongInitialize.join();
    ASSERT_FALSE(initializedOnWrongThread);
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    ASSERT_TRUE(controller.initialize());
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, CallbackExceptionsNeverEscapeAndCloseGate)
{
    Harness before; auto beforeServices = before.services();
    beforeServices.isBusy = []() -> bool { throw std::runtime_error("busy callback"); };
    EnvironmentProfileController beforeController(std::move(beforeServices)); ASSERT_TRUE(beforeController.initialize());
    EXPECT_NO_THROW(EXPECT_EQ(beforeController.capture(EnvironmentProfile::Kind::Office),
                              EnvironmentProfileController::Result::IndeterminateState));
    EXPECT_EQ(before.replaceCalls, 0); EXPECT_FALSE(beforeController.effectiveAllows(firstUuid, DevicePermissions::SendFiles));

    Harness after; auto afterServices = after.services(); int applyCalls = 0;
    afterServices.applyLayout = [&after, &applyCalls](const EnvironmentProfile::Layout& layout) {
        if (after.startupReconciliationPending) {
            ++after.startupApplyCalls; after.currentLayout = layout; return true;
        }
        ++applyCalls; if (applyCalls == 1) throw std::runtime_error("after persist"); after.currentLayout = layout; return true;
    };
    EnvironmentProfileController afterController(std::move(afterServices)); ASSERT_TRUE(afterController.initialize());
    EXPECT_NO_THROW(EXPECT_EQ(afterController.activate(EnvironmentProfile::Kind::Office,
                                                       EnvironmentProfileController::ActivationSource::Manual),
                              EnvironmentProfileController::Result::PersistenceError));
    EXPECT_EQ(after.setActiveCalls, 2); EXPECT_EQ(after.storedActive, EnvironmentProfile::Kind::Home);
}

TEST(EnvironmentProfileControllerTests, PersistenceStateChangesAfterInitializationCloseGate)
{
    for (const auto failure : {EnvironmentProfileStore::SaveResult::ReadOnlyFutureSchema,
                               EnvironmentProfileStore::SaveResult::InvalidProfile,
                               EnvironmentProfileStore::SaveResult::ConcurrentModification,
                               EnvironmentProfileStore::SaveResult::SettingsError}) {
        Harness h; h.replaceResult = failure; EnvironmentProfileController controller(h.services()); ASSERT_TRUE(controller.initialize());
        EXPECT_NE(controller.capture(EnvironmentProfile::Kind::Office), EnvironmentProfileController::Result::Success);
        EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    }
}

TEST(EnvironmentProfileControllerTests, CollectionSnapshotReturnsFourProfilesActiveKindAndGeneration)
{
    Harness h; EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());

    const auto snapshot = controller.collectionSnapshot();

    ASSERT_TRUE(snapshot);
    EXPECT_EQ(snapshot->profiles.size(), 4);
    EXPECT_EQ(snapshot->activeKind, EnvironmentProfile::Kind::Home);
    EXPECT_EQ(snapshot->generation, QStringLiteral("generation-1"));
}

TEST(EnvironmentProfileControllerTests, ReplaceAllClosesPreviousAuthorizationBeforePersistAndApply)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    const auto originalReplaceAll = services.replaceAllIfGeneration;
    const auto originalApply = services.applyLayout;
    EnvironmentProfileController* controllerProbe = nullptr;
    bool operationStarted = false;
    bool gateClosedInsidePersistence = false;
    bool gateClosedInsideApply = false;
    services.replaceAllIfGeneration =
        [&](const QList<EnvironmentProfile>& profiles,
            EnvironmentProfile::Kind activeKind, const QString& generation,
            const std::optional<QString>& recovery) {
            if (operationStarted) {
                gateClosedInsidePersistence = controllerProbe &&
                    !controllerProbe->effectiveAllows(
                        firstUuid, DevicePermissions::SendFiles);
            }
            return originalReplaceAll(profiles, activeKind, generation, recovery);
        };
    services.applyLayout = [&](const EnvironmentProfile::Layout& layout) {
        if (operationStarted) {
            gateClosedInsideApply = controllerProbe &&
                !controllerProbe->effectiveAllows(
                    firstUuid, DevicePermissions::SendFiles);
        }
        return originalApply(layout);
    };
    EnvironmentProfileController controller(std::move(services));
    controllerProbe = &controller;
    ASSERT_TRUE(controller.initialize());
    ASSERT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    operationStarted = true;

    EXPECT_EQ(controller.replaceAll(h.storedProfiles, EnvironmentProfile::Kind::Home),
              EnvironmentProfileController::Result::Success);
    EXPECT_TRUE(gateClosedInsidePersistence);
    EXPECT_TRUE(gateClosedInsideApply);
}

TEST(EnvironmentProfileControllerTests, ReplaceAllUsesGenerationCasAndRefreshesControllerState)
{
    Harness h; EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    QList<EnvironmentProfile> replacements;
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        auto profile = validProfile(kind);
        if (kind == EnvironmentProfile::Kind::Travel)
            profile.devices[0].requestedResources = DevicePermissions::SendFiles;
        replacements.push_back(profile);
    }

    const auto result = controller.replaceAll(replacements, EnvironmentProfile::Kind::Travel);

    EXPECT_EQ(result, EnvironmentProfileController::Result::Success);
    EXPECT_EQ(h.replaceAllCalls, 1);
    EXPECT_EQ(h.applyCalls, 1);
    expectLayoutEqual(h.currentLayout, replacements[3].layout);
    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Travel);
    const auto snapshot = controller.collectionSnapshot();
    ASSERT_TRUE(snapshot);
    EXPECT_EQ(snapshot->generation, QStringLiteral("generation-2"));
    EXPECT_EQ(snapshot->activeKind, EnvironmentProfile::Kind::Travel);
}

TEST(EnvironmentProfileControllerTests, ReplaceAllRestoresStoreAndLayoutWhenRuntimeApplyFails)
{
    Harness h;
    const auto previousLayout = h.currentLayout;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    QList<EnvironmentProfile> replacements;
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        replacements.push_back(kind == EnvironmentProfile::Kind::Travel
            ? validProfile(kind, secondUuid, QStringLiteral("travel"))
            : validProfile(kind));
    }
    h.applySucceeds = false;

    const auto result = controller.replaceAll(replacements, EnvironmentProfile::Kind::Travel);

    EXPECT_EQ(result, EnvironmentProfileController::Result::PersistenceError);
    EXPECT_EQ(h.replaceAllCalls, 2);
    ASSERT_EQ(h.recoveryOverrides.size(), 2);
    EXPECT_FALSE(h.recoveryOverrides[0].has_value());
    EXPECT_EQ(h.recoveryOverrides[1], QStringLiteral("generation-1"));
    EXPECT_EQ(h.applyCalls, 2);
    EXPECT_EQ(h.storedActive, EnvironmentProfile::Kind::Home);
    expectLayoutEqual(h.currentLayout, previousLayout);
    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Home);
}

TEST(EnvironmentProfileControllerTests, ReplaceAllRejectsBusyBeforePersistence)
{
    Harness h; h.busy = true; EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());

    EXPECT_EQ(controller.replaceAll(h.storedProfiles, EnvironmentProfile::Kind::Home),
              EnvironmentProfileController::Result::Busy);
    EXPECT_EQ(h.replaceAllCalls, 0);
}

TEST(EnvironmentProfileControllerTests, CaptureDetectsPromotionAfterVerifiedConsume)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    h.advanceGenerationAfterVerify = true;

    EXPECT_EQ(controller.capture(EnvironmentProfile::Kind::Home),
              EnvironmentProfileController::Result::ConcurrentModification);
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, CaptureKeepsGateClosedThroughPostConsumeVerification)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    const auto originalVerify = services.verifyGeneration;
    EnvironmentProfileController* controllerProbe = nullptr;
    bool captureStarted = false;
    bool gateOpenDuringCaptureVerify = false;
    services.verifyGeneration = [&](const QString& generation) {
        if (captureStarted) {
            EXPECT_NE(controllerProbe, nullptr);
            gateOpenDuringCaptureVerify = controllerProbe->effectiveAllows(
                firstUuid, DevicePermissions::SendFiles);
        }
        return originalVerify(generation);
    };
    EnvironmentProfileController controller(std::move(services));
    controllerProbe = &controller;
    ASSERT_TRUE(controller.initialize());
    captureStarted = true;

    EXPECT_EQ(controller.capture(EnvironmentProfile::Kind::Home),
              EnvironmentProfileController::Result::Success);
    EXPECT_FALSE(gateOpenDuringCaptureVerify);
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, InactiveCapturePromotionDuringFinalVerificationFailsClosed)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("inactive-capture-promotion.ini"));
    QSettings firstSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore first(firstSettings);
    auto persistedProfile = validProfile();
    ASSERT_TRUE(persistedProfile.layout.extension.updateMonitorsForDevice(
        firstUuid,
        {{QStringLiteral("primary"), QRect(0, 0, 100, 100), 1.0,
          Qt::PrimaryOrientation, true}}));
    ASSERT_EQ(first.initializeFromLegacy(persistedProfile),
              EnvironmentProfileStore::SaveResult::Success);
    QSettings secondSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore second(secondSettings);
    ASSERT_EQ(second.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);

    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    services.load = [&] { return first.load(); };
    services.profile = [&](EnvironmentProfile::Kind kind) { return first.profile(kind); };
    services.activeKind = [&] { return first.activeKind(); };
    services.currentGeneration = [&] { return first.currentGeneration(); };
    services.replaceProfileIfGeneration =
        [&](const EnvironmentProfile& profile, const QString& expected,
            const std::optional<QString>& recoveryGeneration) {
            return first.replaceProfileIfGeneration(profile, expected, recoveryGeneration);
        };
    services.consumeVerifiedGeneration =
        [&](const QString& expected,
            const EnvironmentProfileStore::VerifiedConsumer& consumer) {
            return first.consumeVerifiedGeneration(expected, consumer);
        };
    bool captureStarted = false;
    bool promotedDuringFinalVerification = false;
    bool gateOpenDuringFinalVerification = false;
    EnvironmentProfileController* controllerProbe = nullptr;
    services.verifyGeneration = [&](const QString& expected) {
        const auto verified = first.verifyGeneration(expected);
        if (captureStarted && !promotedDuringFinalVerification &&
            verified == EnvironmentProfileStore::SaveResult::Success) {
            EXPECT_NE(controllerProbe, nullptr);
            gateOpenDuringFinalVerification = controllerProbe->effectiveAllows(
                firstUuid, DevicePermissions::SendFiles);
            EXPECT_EQ(second.load(), EnvironmentProfileStore::LoadStatus::Loaded);
            const auto generation = second.currentGeneration();
            EXPECT_TRUE(generation.has_value());
            if (generation) {
                const auto concurrent = second.setActiveIfGeneration(
                    EnvironmentProfile::Kind::Travel, *generation);
                EXPECT_EQ(concurrent.result, EnvironmentProfileStore::SaveResult::Success);
                promotedDuringFinalVerification =
                    concurrent.result == EnvironmentProfileStore::SaveResult::Success;
            }
        }
        return verified;
    };

    EnvironmentProfileController controller(std::move(services));
    controllerProbe = &controller;
    ASSERT_TRUE(controller.initialize());
    ASSERT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    captureStarted = true;

    const auto result = controller.capture(EnvironmentProfile::Kind::Office);

    EXPECT_TRUE(promotedDuringFinalVerification);
    EXPECT_FALSE(gateOpenDuringFinalVerification);
    EXPECT_NE(result, EnvironmentProfileController::Result::Success);
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    ASSERT_EQ(second.load(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(second.activeKind(), EnvironmentProfile::Kind::Travel);
}

TEST(EnvironmentProfileControllerTests, CaptureFinalConsumerCannotPromotePastSealedPublicationBoundary)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("capture-final-consumer.ini"));
    QSettings firstSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore first(firstSettings);
    auto persistedProfile = validProfile();
    ASSERT_TRUE(persistedProfile.layout.extension.updateMonitorsForDevice(
        firstUuid,
        {{QStringLiteral("primary"), QRect(0, 0, 100, 100), 1.0,
          Qt::PrimaryOrientation, true}}));
    ASSERT_EQ(first.initializeFromLegacy(persistedProfile),
              EnvironmentProfileStore::SaveResult::Success);
    QSettings secondSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore second(secondSettings);
    ASSERT_EQ(second.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);

    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    services.load = [&] { return first.load(); };
    services.profile = [&](EnvironmentProfile::Kind kind) { return first.profile(kind); };
    services.activeKind = [&] { return first.activeKind(); };
    services.currentGeneration = [&] { return first.currentGeneration(); };
    services.replaceProfileIfGeneration =
        [&](const EnvironmentProfile& profile, const QString& expected,
            const std::optional<QString>& recoveryGeneration) {
            return first.replaceProfileIfGeneration(profile, expected, recoveryGeneration);
        };
    services.verifyGeneration =
        [&](const QString& expected) { return first.verifyGeneration(expected); };
    bool captureStarted = false;
    int captureConsumes = 0;
    bool promotionAttempted = false;
    auto promotionResult = EnvironmentProfileStore::SaveResult::SettingsError;
    services.consumeVerifiedGeneration =
        [&](const QString& expected,
            const EnvironmentProfileStore::VerifiedConsumer& consumer) {
            const auto consumed = first.consumeVerifiedGeneration(expected, consumer);
            if (captureStarted && ++captureConsumes == 2 &&
                consumed == EnvironmentProfileStore::SaveResult::Success) {
                promotionAttempted = true;
                EXPECT_EQ(second.load(), EnvironmentProfileStore::LoadStatus::Loaded);
                const auto generation = second.currentGeneration();
                EXPECT_TRUE(generation.has_value());
                if (generation) {
                    promotionResult = second.setActiveIfGeneration(
                        EnvironmentProfile::Kind::Travel, *generation).result;
                }
            }
            return consumed;
        };

    EnvironmentProfileController controller(std::move(services));
    ASSERT_TRUE(controller.initialize());
    captureStarted = true;

    EXPECT_EQ(controller.capture(EnvironmentProfile::Kind::Office),
              EnvironmentProfileController::Result::Success);
    EXPECT_TRUE(promotionAttempted);
    EXPECT_NE(promotionResult, EnvironmentProfileStore::SaveResult::Success);
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    ASSERT_EQ(second.load(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(second.activeKind(), EnvironmentProfile::Kind::Home);
}

TEST(EnvironmentProfileControllerTests, ReplaceAllFinalVerificationCannotPromotePastSealedPublicationBoundary)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("replace-all-final-verification.ini"));
    QSettings firstSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore first(firstSettings);
    auto persistedProfile = validProfile();
    ASSERT_TRUE(persistedProfile.layout.extension.updateMonitorsForDevice(
        firstUuid,
        {{QStringLiteral("primary"), QRect(0, 0, 100, 100), 1.0,
          Qt::PrimaryOrientation, true}}));
    ASSERT_EQ(first.initializeFromLegacy(persistedProfile),
              EnvironmentProfileStore::SaveResult::Success);
    QSettings secondSettings(path, QSettings::IniFormat);
    EnvironmentProfileStore second(secondSettings);
    ASSERT_EQ(second.loadStatus(), EnvironmentProfileStore::LoadStatus::Loaded);

    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    services.load = [&] { return first.load(); };
    services.profile = [&](EnvironmentProfile::Kind kind) { return first.profile(kind); };
    services.activeKind = [&] { return first.activeKind(); };
    services.currentGeneration = [&] { return first.currentGeneration(); };
    services.profiles = [&] { return first.profiles(); };
    services.replaceAllIfGeneration =
        [&](const QList<EnvironmentProfile>& profiles,
            EnvironmentProfile::Kind activeKind, const QString& expected,
            const std::optional<QString>& recoveryGeneration) {
            return first.replaceAllIfGeneration(
                profiles, activeKind, expected, recoveryGeneration);
        };
    services.consumeVerifiedGeneration =
        [&](const QString& expected,
            const EnvironmentProfileStore::VerifiedConsumer& consumer) {
            return first.consumeVerifiedGeneration(expected, consumer);
        };
    bool replaceStarted = false;
    bool promotionAttempted = false;
    auto promotionResult = EnvironmentProfileStore::SaveResult::SettingsError;
    services.verifyGeneration = [&](const QString& expected) {
        const auto verified = first.verifyGeneration(expected);
        if (replaceStarted && !promotionAttempted &&
            verified == EnvironmentProfileStore::SaveResult::Success) {
            promotionAttempted = true;
            EXPECT_EQ(second.load(), EnvironmentProfileStore::LoadStatus::Loaded);
            const auto generation = second.currentGeneration();
            EXPECT_TRUE(generation.has_value());
            if (generation) {
                promotionResult = second.setActiveIfGeneration(
                    EnvironmentProfile::Kind::Travel, *generation).result;
            }
        }
        return verified;
    };

    EnvironmentProfileController controller(std::move(services));
    ASSERT_TRUE(controller.initialize());
    replaceStarted = true;
    const auto replacements = first.profiles();

    EXPECT_EQ(controller.replaceAll(replacements, EnvironmentProfile::Kind::Office),
              EnvironmentProfileController::Result::Success);
    EXPECT_TRUE(promotionAttempted);
    EXPECT_NE(promotionResult, EnvironmentProfileStore::SaveResult::Success);
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
    ASSERT_EQ(second.load(), EnvironmentProfileStore::LoadStatus::Loaded);
    EXPECT_EQ(second.activeKind(), EnvironmentProfile::Kind::Office);
}

TEST(EnvironmentProfileControllerTests, ReplaceAllDetectsPromotionAfterVerifiedConsume)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    EnvironmentProfileController controller(h.services());
    ASSERT_TRUE(controller.initialize());
    h.advanceGenerationAfterVerify = true;

    EXPECT_EQ(controller.replaceAll(h.storedProfiles, EnvironmentProfile::Kind::Office),
              EnvironmentProfileController::Result::ConcurrentModification);
    EXPECT_FALSE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}

TEST(EnvironmentProfileControllerTests, ReplaceAllKeepsGateClosedThroughPostConsumeVerification)
{
    Harness h;
    h.permissions[firstUuid] = DevicePermissions::SendFiles;
    auto services = h.services();
    const auto originalVerify = services.verifyGeneration;
    EnvironmentProfileController* controllerProbe = nullptr;
    bool replaceStarted = false;
    bool gateOpenDuringReplaceVerify = false;
    services.verifyGeneration = [&](const QString& generation) {
        if (replaceStarted) {
            EXPECT_NE(controllerProbe, nullptr);
            gateOpenDuringReplaceVerify = controllerProbe->effectiveAllows(
                firstUuid, DevicePermissions::SendFiles);
        }
        return originalVerify(generation);
    };
    EnvironmentProfileController controller(std::move(services));
    controllerProbe = &controller;
    ASSERT_TRUE(controller.initialize());
    replaceStarted = true;

    EXPECT_EQ(controller.replaceAll(h.storedProfiles, EnvironmentProfile::Kind::Home),
              EnvironmentProfileController::Result::Success);
    EXPECT_FALSE(gateOpenDuringReplaceVerify);
    EXPECT_TRUE(controller.effectiveAllows(firstUuid, DevicePermissions::SendFiles));
}
