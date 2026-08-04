#include "EnvironmentProfileSelector.h"

#include <gtest/gtest.h>

#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QSignalSpy>
#include <QTest>
#include <QVariant>

namespace {

QComboBox* combo(EnvironmentProfileSelector& selector)
{
    return selector.findChild<QComboBox*>("environmentProfileCombo");
}

QPushButton* applyButton(EnvironmentProfileSelector& selector)
{
    return selector.findChild<QPushButton*>("applyEnvironmentProfileButton");
}

QPushButton* captureButton(EnvironmentProfileSelector& selector)
{
    return selector.findChild<QPushButton*>("captureEnvironmentProfileButton");
}

QLabel* statusLabel(EnvironmentProfileSelector& selector)
{
    return selector.findChild<QLabel*>("environmentProfileStatus");
}

EnvironmentProfile::Kind emittedKind(const QSignalSpy& spy, int index = 0)
{
    return static_cast<EnvironmentProfile::Kind>(spy.at(index).at(0).toInt());
}

} // namespace

TEST(EnvironmentProfileSelectorTests, ShowsCanonicalOptionsAndPortugueseAccessibility)
{
    EnvironmentProfileSelector selector;
    auto* profileCombo = combo(selector);
    auto* apply = applyButton(selector);
    auto* capture = captureButton(selector);
    auto* status = statusLabel(selector);

    ASSERT_NE(profileCombo, nullptr);
    ASSERT_NE(apply, nullptr);
    ASSERT_NE(capture, nullptr);
    ASSERT_NE(status, nullptr);
    EXPECT_EQ(profileCombo->count(), 4);
    EXPECT_EQ(profileCombo->itemText(0), QString("Casa"));
    EXPECT_EQ(profileCombo->itemText(1), QString("Escritório"));
    EXPECT_EQ(profileCombo->itemText(2), QString("Viagem"));
    EXPECT_EQ(profileCombo->itemText(3), QString("Apresentação"));
    EXPECT_EQ(profileCombo->itemData(0).toInt(), static_cast<int>(EnvironmentProfile::Kind::Home));
    EXPECT_EQ(profileCombo->itemData(1).toInt(), static_cast<int>(EnvironmentProfile::Kind::Office));
    EXPECT_EQ(profileCombo->itemData(2).toInt(), static_cast<int>(EnvironmentProfile::Kind::Travel));
    EXPECT_EQ(profileCombo->itemData(3).toInt(), static_cast<int>(EnvironmentProfile::Kind::Presentation));
    EXPECT_EQ(apply->text(), QString("Aplicar"));
    EXPECT_EQ(capture->text(), QString("Salvar estado atual neste perfil"));
    EXPECT_EQ(status->textFormat(), Qt::PlainText);
    EXPECT_TRUE(status->text().contains("ainda não disponível"));
    EXPECT_FALSE(status->text().contains("Casa"));
    EXPECT_TRUE(status->accessibleDescription().contains("ainda não disponível"));

    EXPECT_FALSE(selector.accessibleName().isEmpty());
    EXPECT_FALSE(selector.accessibleDescription().isEmpty());
    for (const QWidget* widget : {static_cast<QWidget*>(profileCombo), static_cast<QWidget*>(apply),
                                  static_cast<QWidget*>(capture), static_cast<QWidget*>(status)}) {
        EXPECT_FALSE(widget->accessibleName().isEmpty());
        EXPECT_FALSE(widget->accessibleDescription().isEmpty());
    }
}

TEST(EnvironmentProfileSelectorTests, ComboChangeOnlySelectsIntendedTarget)
{
    EnvironmentProfileSelector selector;
    QSignalSpy applySpy(&selector, &EnvironmentProfileSelector::applyRequested);
    QSignalSpy captureSpy(&selector, &EnvironmentProfileSelector::captureRequested);
    const QString originalStatus = statusLabel(selector)->text();

    combo(selector)->setCurrentIndex(2);

    EXPECT_EQ(applySpy.count(), 0);
    EXPECT_EQ(captureSpy.count(), 0);
    EXPECT_EQ(statusLabel(selector)->text(), originalStatus);
}

TEST(EnvironmentProfileSelectorTests, ApplyClickEmitsSelectedKindExactlyOnce)
{
    EnvironmentProfileSelector selector;
    combo(selector)->setCurrentIndex(1);
    QSignalSpy spy(&selector, &EnvironmentProfileSelector::applyRequested);

    applyButton(selector)->click();

    ASSERT_EQ(spy.count(), 1);
    EXPECT_EQ(emittedKind(spy), EnvironmentProfile::Kind::Office);
}

TEST(EnvironmentProfileSelectorTests, CaptureClickEmitsSelectedKindExactlyOnce)
{
    EnvironmentProfileSelector selector;
    combo(selector)->setCurrentIndex(3);
    QSignalSpy spy(&selector, &EnvironmentProfileSelector::captureRequested);

    captureButton(selector)->click();

    ASSERT_EQ(spy.count(), 1);
    EXPECT_EQ(emittedKind(spy), EnvironmentProfile::Kind::Presentation);
}

TEST(EnvironmentProfileSelectorTests, DisabledStateBlocksBothActionsAndExplainsReason)
{
    EnvironmentProfileSelector selector;
    QSignalSpy applySpy(&selector, &EnvironmentProfileSelector::applyRequested);
    QSignalSpy captureSpy(&selector, &EnvironmentProfileSelector::captureRequested);
    const QString reason = "Pare o InputLeap antes de trocar de perfil.";

    selector.setSwitchEnabled(false, reason);

    EXPECT_FALSE(applyButton(selector)->isEnabled());
    EXPECT_FALSE(captureButton(selector)->isEnabled());
    EXPECT_TRUE(combo(selector)->isEnabled());
    EXPECT_TRUE(combo(selector)->accessibleDescription().contains("pendente"));
    EXPECT_FALSE(statusLabel(selector)->text().isEmpty());
    EXPECT_TRUE(statusLabel(selector)->text().contains(reason));
    EXPECT_TRUE(statusLabel(selector)->accessibleDescription().contains(reason));
    applyButton(selector)->click();
    captureButton(selector)->click();
    EXPECT_EQ(applySpy.count(), 0);
    EXPECT_EQ(captureSpy.count(), 0);
}

TEST(EnvironmentProfileSelectorTests, ReenableClearsBlockAndRestoresActiveStatus)
{
    EnvironmentProfileSelector selector;
    selector.setActiveKind(EnvironmentProfile::Kind::Travel);
    selector.setSwitchEnabled(false, "Uma operação está em andamento.");

    selector.setSwitchEnabled(true, "razão obsoleta");

    EXPECT_TRUE(applyButton(selector)->isEnabled());
    EXPECT_TRUE(captureButton(selector)->isEnabled());
    EXPECT_TRUE(statusLabel(selector)->text().contains("Viagem"));
    EXPECT_FALSE(statusLabel(selector)->text().contains("operação"));
    EXPECT_FALSE(statusLabel(selector)->accessibleDescription().contains("obsoleta"));
}

TEST(EnvironmentProfileSelectorTests, ReenableBeforeFirstActiveKindRestoresNeutralStatus)
{
    EnvironmentProfileSelector selector;
    selector.setSwitchEnabled(false, "Uma operação está em andamento.");

    selector.setSwitchEnabled(true);

    EXPECT_TRUE(statusLabel(selector)->text().contains("ainda não disponível"));
    EXPECT_FALSE(statusLabel(selector)->text().contains("Casa"));
    EXPECT_TRUE(statusLabel(selector)->accessibleDescription().contains("ainda não disponível"));
}

TEST(EnvironmentProfileSelectorTests, SetActiveKindSynchronizesWithoutRequest)
{
    EnvironmentProfileSelector selector;
    QSignalSpy applySpy(&selector, &EnvironmentProfileSelector::applyRequested);
    QSignalSpy captureSpy(&selector, &EnvironmentProfileSelector::captureRequested);

    selector.setActiveKind(EnvironmentProfile::Kind::Presentation);

    EXPECT_EQ(combo(selector)->currentIndex(), 3);
    EXPECT_TRUE(statusLabel(selector)->text().contains("Apresentação"));
    EXPECT_EQ(applySpy.count(), 0);
    EXPECT_EQ(captureSpy.count(), 0);
}

TEST(EnvironmentProfileSelectorTests, FirstActiveKindPreservesPendingUserSelection)
{
    EnvironmentProfileSelector selector;
    auto* profileCombo = combo(selector);
    profileCombo->setCurrentIndex(2);
    ASSERT_TRUE(QMetaObject::invokeMethod(profileCombo, "activated", Q_ARG(int, 2)));

    selector.setActiveKind(EnvironmentProfile::Kind::Office);

    EXPECT_EQ(profileCombo->currentIndex(), 2);
    EXPECT_TRUE(statusLabel(selector)->text().contains("Escritório"));
}

TEST(EnvironmentProfileSelectorTests, ProgrammaticComboChangeBeforeFirstActiveDoesNotCountAsUserSelection)
{
    EnvironmentProfileSelector selector;
    combo(selector)->setCurrentIndex(2);

    selector.setActiveKind(EnvironmentProfile::Kind::Office);

    EXPECT_EQ(combo(selector)->currentIndex(), 1);
}

TEST(EnvironmentProfileSelectorTests, SubsequentActiveUpdatesAlwaysPreservePendingSelection)
{
    EnvironmentProfileSelector selector;
    selector.setActiveKind(EnvironmentProfile::Kind::Home);
    combo(selector)->setCurrentIndex(3);

    selector.setActiveKind(EnvironmentProfile::Kind::Travel);

    EXPECT_EQ(combo(selector)->currentIndex(), 3);
    EXPECT_TRUE(statusLabel(selector)->text().contains("Viagem"));
}

TEST(EnvironmentProfileSelectorTests, InvalidKindFailsSafeWithoutChangingStateOrEmitting)
{
    EnvironmentProfileSelector selector;
    selector.setActiveKind(EnvironmentProfile::Kind::Office);
    QSignalSpy applySpy(&selector, &EnvironmentProfileSelector::applyRequested);
    QSignalSpy captureSpy(&selector, &EnvironmentProfileSelector::captureRequested);
    const int selectedIndex = combo(selector)->currentIndex();
    const QString activeStatus = statusLabel(selector)->text();

    selector.setActiveKind(static_cast<EnvironmentProfile::Kind>(999));

    EXPECT_EQ(combo(selector)->currentIndex(), selectedIndex);
    EXPECT_EQ(statusLabel(selector)->text(), activeStatus);
    EXPECT_EQ(applySpy.count(), 0);
    EXPECT_EQ(captureSpy.count(), 0);
}

TEST(EnvironmentProfileSelectorTests, InvalidInitialActiveKindKeepsNeutralStatus)
{
    EnvironmentProfileSelector selector;

    selector.setActiveKind(static_cast<EnvironmentProfile::Kind>(999));

    EXPECT_TRUE(statusLabel(selector)->text().contains("ainda não disponível"));
    EXPECT_FALSE(statusLabel(selector)->text().contains("Casa"));
}

TEST(EnvironmentProfileSelectorTests, CorruptItemDataNeverEmitsAnAction)
{
    EnvironmentProfileSelector selector;
    auto* profileCombo = combo(selector);
    QSignalSpy applySpy(&selector, &EnvironmentProfileSelector::applyRequested);
    QSignalSpy captureSpy(&selector, &EnvironmentProfileSelector::captureRequested);

    const QList<QVariant> corruptValues = {
        QVariant(),
        QVariant(QString::number(static_cast<int>(EnvironmentProfile::Kind::Office))),
        QVariant(999),
    };
    for (const QVariant& value : corruptValues) {
        profileCombo->setItemData(profileCombo->currentIndex(), value);
        applyButton(selector)->click();
        captureButton(selector)->click();
    }

    EXPECT_EQ(applySpy.count(), 0);
    EXPECT_EQ(captureSpy.count(), 0);
}

TEST(EnvironmentProfileSelectorTests, SpaceReturnAndEnterEmitExactlyOncePerButton)
{
    EnvironmentProfileSelector selector;
    selector.show();
    combo(selector)->setCurrentIndex(2);
    QSignalSpy applySpy(&selector, &EnvironmentProfileSelector::applyRequested);
    QSignalSpy captureSpy(&selector, &EnvironmentProfileSelector::captureRequested);

    const QList<Qt::Key> keys = {Qt::Key_Space, Qt::Key_Return, Qt::Key_Enter};
    for (const Qt::Key key : keys) {
        const int applyBefore = applySpy.count();
        applyButton(selector)->setFocus();
        QTest::keyClick(applyButton(selector), key);
        ASSERT_EQ(applySpy.count(), applyBefore + 1);
        EXPECT_EQ(emittedKind(applySpy, applyBefore), EnvironmentProfile::Kind::Travel);

        const int captureBefore = captureSpy.count();
        captureButton(selector)->setFocus();
        QTest::keyClick(captureButton(selector), key);
        ASSERT_EQ(captureSpy.count(), captureBefore + 1);
        EXPECT_EQ(emittedKind(captureSpy, captureBefore), EnvironmentProfile::Kind::Travel);
    }
}

TEST(EnvironmentProfileSelectorTests, DisabledButtonsIgnoreAllKeyboardActivation)
{
    EnvironmentProfileSelector selector;
    selector.show();
    selector.setSwitchEnabled(false, "Bloqueado para teste.");
    QSignalSpy applySpy(&selector, &EnvironmentProfileSelector::applyRequested);
    QSignalSpy captureSpy(&selector, &EnvironmentProfileSelector::captureRequested);

    for (const Qt::Key key : {Qt::Key_Space, Qt::Key_Return, Qt::Key_Enter}) {
        QTest::keyClick(applyButton(selector), key);
        QTest::keyClick(captureButton(selector), key);
    }

    EXPECT_EQ(applySpy.count(), 0);
    EXPECT_EQ(captureSpy.count(), 0);
}

TEST(EnvironmentProfileSelectorTests, ParentOwnsAndDestroysSelectorSafely)
{
    auto* parent = new QWidget;
    auto* selector = new EnvironmentProfileSelector(parent);
    EXPECT_EQ(selector->parentWidget(), parent);
    EXPECT_NE(combo(*selector), nullptr);

    delete parent;
}
