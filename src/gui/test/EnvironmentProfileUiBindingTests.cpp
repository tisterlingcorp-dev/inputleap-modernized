#include "EnvironmentProfileUiBinding.h"
#include "EnvironmentProfileSelector.h"

#include <gtest/gtest.h>

#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QSet>
#include <QSignalSpy>

namespace {

const QUuid deviceUuid(QStringLiteral("{11111111-1111-1111-1111-111111111111}"));

EnvironmentProfile profile(EnvironmentProfile::Kind kind)
{
    ScreenLayout::Device device;
    device.uuid = deviceUuid;
    device.technicalName = QStringLiteral("alpha");
    device.geometry = QRect(0, 0, 100, 100);
    EnvironmentProfile value;
    value.kind = kind;
    value.layout.columns = 1;
    value.layout.rows = 1;
    value.layout.gridTechnicalNames = {QStringLiteral("alpha")};
    value.layout.extension = ScreenLayout({device});
    value.devices = {{deviceUuid, QStringLiteral("alpha"), DevicePermissions::SendFiles}};
    return value;
}

struct Harness {
    EnvironmentProfile::Kind active = EnvironmentProfile::Kind::Home;
    QString generation = QStringLiteral("g1");
    int activateWrites = 0;
    int captureWrites = 0;
    int applyCalls = 0;
    bool busy = false;
    bool firstApplySucceeds = true;
    EnvironmentProfile::Layout currentLayout = profile(EnvironmentProfile::Kind::Home).layout;

    EnvironmentProfileController::Services services()
    {
        return {
            [] { return EnvironmentProfileStore::LoadStatus::Loaded; },
            [](EnvironmentProfile::Kind kind) { return std::optional<EnvironmentProfile>(profile(kind)); },
            [this] { return std::optional<EnvironmentProfile::Kind>(active); },
            [this] { return std::optional<QString>(generation); },
            [](const EnvironmentProfile&) { return EnvironmentProfileStore::SaveResult::Success; },
            [this](const EnvironmentProfile& value, const QString&,
                   const std::optional<QString>&) {
                ++captureWrites;
                EnvironmentProfileStore::Mutation mutation;
                mutation.result = EnvironmentProfileStore::SaveResult::Success;
                mutation.resultingGeneration = generation = QStringLiteral("capture");
                mutation.promotedProfile = value;
                return mutation;
            },
            [this](EnvironmentProfile::Kind kind, const QString&,
                   const std::optional<QString>&) {
                ++activateWrites;
                active = kind;
                EnvironmentProfileStore::Mutation mutation;
                mutation.result = EnvironmentProfileStore::SaveResult::Success;
                mutation.resultingGeneration = generation = QStringLiteral("activate");
                mutation.promotedProfile = profile(kind);
                return mutation;
            },
            [](const QString&) { return EnvironmentProfileStore::SaveResult::Success; },
            [this](const QString& expected,
                   const EnvironmentProfileStore::VerifiedConsumer& consumer) {
                if (expected != generation)
                    return EnvironmentProfileStore::SaveResult::ConcurrentModification;
                return consumer({active, generation, profile(active)})
                    ? EnvironmentProfileStore::SaveResult::Success
                    : EnvironmentProfileStore::SaveResult::InvalidProfile;
            },
            [this] { return currentLayout; },
            [this](const EnvironmentProfile::Layout& layout) {
                ++applyCalls;
                const bool succeeds = applyCalls != 1 || firstApplySucceeds;
                if (succeeds) currentLayout = layout;
                return succeeds;
            },
            [](const QUuid&) { return DevicePermissions::Mask(DevicePermissions::SendFiles); },
            [](const QUuid&, DevicePermissions::Permission) { return true; },
            [this] { return busy; },
            [] { return false; },
            [] {
                QList<EnvironmentProfile> profiles;
                for (const auto kind : EnvironmentProfile::canonicalKinds())
                    profiles.push_back(profile(kind));
                return profiles;
            },
            [](const QList<EnvironmentProfile>&, EnvironmentProfile::Kind,
               const QString&, const std::optional<QString>&) {
                return EnvironmentProfileStore::Mutation{};
            }
        };
    }
};

QComboBox* combo(EnvironmentProfileSelector& selector)
{
    return selector.findChild<QComboBox*>(QStringLiteral("environmentProfileCombo"));
}

QPushButton* apply(EnvironmentProfileSelector& selector)
{
    return selector.findChild<QPushButton*>(QStringLiteral("applyEnvironmentProfileButton"));
}

QPushButton* capture(EnvironmentProfileSelector& selector)
{
    return selector.findChild<QPushButton*>(QStringLiteral("captureEnvironmentProfileButton"));
}

TEST(EnvironmentProfileUiBindingTests, ComboSelectionAloneDoesNotCallControllerAndSuccessRefreshesActiveState)
{
    Harness harness;
    EnvironmentProfileController controller(harness.services());
    ASSERT_TRUE(controller.initialize());
    EnvironmentProfileSelector selector;
    QString shown;
    EnvironmentProfileUiBinding binding(selector, controller, {},
        [&shown](const QString&, const QString& message, bool) { shown = message; });
    binding.refresh(true, false, false);

    combo(selector)->setCurrentIndex(1);
    EXPECT_EQ(harness.activateWrites, 0);
    apply(selector)->click();

    EXPECT_EQ(harness.activateWrites, 1);
    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Office);
    EXPECT_TRUE(shown.contains(QStringLiteral("Escritório")));
}

TEST(EnvironmentProfileUiBindingTests, CaptureRequiresConfirmationAndCancelPerformsZeroWrites)
{
    Harness harness;
    EnvironmentProfileController controller(harness.services());
    ASSERT_TRUE(controller.initialize());
    EnvironmentProfileSelector selector;
    QString confirmation;
    EnvironmentProfileUiBinding binding(selector, controller,
        [&confirmation](const QString& text) { confirmation = text; return false; }, {});
    binding.refresh(true, false, false);

    combo(selector)->setCurrentIndex(2);
    capture(selector)->click();

    EXPECT_EQ(harness.captureWrites, 0);
    EXPECT_EQ(confirmation,
        QStringLiteral("Salvar layout, dispositivos e recursos permitidos atualmente em Viagem? Segredos e dados de rede não serão incluídos."));
}

TEST(EnvironmentProfileUiBindingTests, ConfirmedCaptureCallsControllerOnce)
{
    Harness harness;
    EnvironmentProfileController controller(harness.services());
    ASSERT_TRUE(controller.initialize());
    EnvironmentProfileSelector selector;
    EnvironmentProfileUiBinding binding(selector, controller, [](const QString&) { return true; }, {});
    binding.refresh(true, false, false);

    capture(selector)->click();
    EXPECT_EQ(harness.captureWrites, 1);
}

TEST(EnvironmentProfileUiBindingTests, FailedActivationRollbackPreservesActiveLayoutSelectorStatusAndSignals)
{
    Harness harness;
    EnvironmentProfileController controller(harness.services());
    ASSERT_TRUE(controller.initialize());
    harness.applyCalls = 0;
    harness.firstApplySucceeds = false;
    EnvironmentProfileSelector selector;
    QString warning;
    EnvironmentProfileUiBinding binding(selector, controller, {},
        [&warning](const QString&, const QString& message, bool) { warning = message; });
    binding.refresh(true, false, false);
    const auto layoutBefore = harness.currentLayout;
    const QString statusBefore = selector.findChild<QLabel*>(QStringLiteral("environmentProfileStatus"))->text();
    QSignalSpy activeSpy(&controller, &EnvironmentProfileController::activeProfileChanged);

    combo(selector)->setCurrentIndex(1);
    apply(selector)->click();

    EXPECT_EQ(controller.activeKind(), EnvironmentProfile::Kind::Home);
    EXPECT_EQ(harness.currentLayout.gridTechnicalNames, layoutBefore.gridTechnicalNames);
    ASSERT_EQ(harness.currentLayout.extension.devices().size(), layoutBefore.extension.devices().size());
    EXPECT_EQ(harness.currentLayout.extension.devices().front().uuid,
              layoutBefore.extension.devices().front().uuid);
    EXPECT_EQ(harness.currentLayout.extension.devices().front().geometry,
              layoutBefore.extension.devices().front().geometry);
    EXPECT_EQ(selector.findChild<QLabel*>(QStringLiteral("environmentProfileStatus"))->text(), statusBefore);
    EXPECT_EQ(activeSpy.count(), 0);
    EXPECT_EQ(harness.applyCalls, 2);
    EXPECT_FALSE(warning.isEmpty());
}

TEST(EnvironmentProfileUiBindingTests, BusyOrUnavailableDisablesActionsAndPerformsZeroWrites)
{
    Harness harness;
    EnvironmentProfileController controller(harness.services());
    ASSERT_TRUE(controller.initialize());
    EnvironmentProfileSelector selector;
    EnvironmentProfileUiBinding binding(selector, controller, [](const QString&) { return true; }, {});

    binding.refresh(false, true);
    apply(selector)->click();
    capture(selector)->click();
    EXPECT_EQ(harness.activateWrites, 0);
    EXPECT_EQ(harness.captureWrites, 0);

    binding.refresh(true, true);
    EXPECT_FALSE(apply(selector)->isEnabled());
    EXPECT_FALSE(capture(selector)->isEnabled());
    apply(selector)->click();
    capture(selector)->click();
    EXPECT_EQ(harness.activateWrites, 0);
    EXPECT_EQ(harness.captureWrites, 0);
}

TEST(EnvironmentProfileUiBindingTests, ExternalConfigurationDisablesActionsImmediatelyAndPerformsZeroWrites)
{
    Harness harness;
    EnvironmentProfileController controller(harness.services());
    ASSERT_TRUE(controller.initialize());
    EnvironmentProfileSelector selector;
    EnvironmentProfileUiBinding binding(selector, controller, [](const QString&) { return true; }, {});

    binding.refresh(true, false, true);
    apply(selector)->click();
    capture(selector)->click();

    EXPECT_FALSE(apply(selector)->isEnabled());
    EXPECT_FALSE(capture(selector)->isEnabled());
    EXPECT_EQ(harness.activateWrites, 0);
    EXPECT_EQ(harness.captureWrites, 0);
    EXPECT_TRUE(selector.findChild<QLabel*>(QStringLiteral("environmentProfileStatus"))
                    ->text().contains(QStringLiteral("configuração externa")));
}

TEST(EnvironmentProfileUiBindingTests, HonestFailurePresentationsAreDistinctWarnings)
{
    using Result = EnvironmentProfileController::Result;
    const QList<QPair<Result, QString>> expected = {
        {Result::ConcurrentModification, QStringLiteral("outro processo")},
        {Result::IndeterminateState, QStringLiteral("incerto")},
        {Result::Reentrant, QStringLiteral("andamento")},
        {Result::WrongThread, QStringLiteral("segurança interna")},
    };

    QSet<QString> messages;
    for (const auto& item : expected) {
        const auto presentation = EnvironmentProfileUiBinding::presentationFor(
            item.first, EnvironmentProfile::Kind::Office, false);
        EXPECT_TRUE(presentation.warning);
        EXPECT_TRUE(presentation.message.contains(item.second));
        messages.insert(presentation.message);
    }
    EXPECT_EQ(messages.size(), expected.size());
}

} // namespace
