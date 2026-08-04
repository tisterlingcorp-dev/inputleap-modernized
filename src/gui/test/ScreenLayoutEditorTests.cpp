/* InputLeap -- mouse and keyboard sharing utility */
#include "ScreenLayoutEditorWidget.h"

#include <gtest/gtest.h>
#include <QApplication>
#include <QPushButton>
#include <QSignalSpy>
#include <QTest>

namespace {
const QUuid localId("{11111111-1111-1111-1111-111111111111}");
const QUuid remoteId("{22222222-2222-2222-2222-222222222222}");
ScreenLayout::Device dev(const QUuid& id, const QString& name, int x, int y)
{
    return {id, name, QRect(x, y, 100, 100), {}};
}
}

TEST(ScreenLayoutEditorTests, MovesToEveryAdjacentDirectionAndPreservesUuid)
{
    ScreenLayoutEditorViewModel model(ScreenLayout({dev(localId,"local",0,0),dev(remoteId,"remote",100,0)}), localId);
    EXPECT_TRUE(model.moveAdjacent(remoteId, localId, ScreenLayoutEditorViewModel::Direction::Left));
    EXPECT_EQ(model.device(remoteId)->geometry, QRect(-100,0,100,100));
    EXPECT_TRUE(model.moveAdjacent(remoteId, localId, ScreenLayoutEditorViewModel::Direction::Right));
    EXPECT_EQ(model.device(remoteId)->geometry, QRect(100,0,100,100));
    EXPECT_TRUE(model.moveAdjacent(remoteId, localId, ScreenLayoutEditorViewModel::Direction::Above));
    EXPECT_EQ(model.device(remoteId)->geometry, QRect(0,-100,100,100));
    EXPECT_TRUE(model.moveAdjacent(remoteId, localId, ScreenLayoutEditorViewModel::Direction::Below));
    EXPECT_EQ(model.device(remoteId)->geometry, QRect(0,100,100,100));
    EXPECT_EQ(model.device(remoteId)->uuid, remoteId);
}

TEST(ScreenLayoutEditorTests, RejectsCollisionAndExportsDeterministicLegacyGrid)
{
    const QUuid third("{33333333-3333-3333-3333-333333333333}");
    ScreenLayoutEditorViewModel model(ScreenLayout({dev(localId,"local",0,0),dev(remoteId,"right",100,0),dev(third,"third",0,100)}), localId);
    EXPECT_FALSE(model.moveAdjacent(third, localId, ScreenLayoutEditorViewModel::Direction::Right));
    const auto grid=model.toLegacyGrid(5,3);
    ASSERT_TRUE(grid.has_value());ASSERT_EQ(grid->size(),15);
    EXPECT_EQ((*grid)[7],"local");
    EXPECT_EQ((*grid)[8],"right");
    EXPECT_EQ((*grid)[12],"third");
}

TEST(ScreenLayoutEditorTests, SimpleModeHidesEmptyGridAndAdvancedToggleRestoresIt)
{
    ScreenLayoutEditorWidget widget;
    widget.setLayoutModel(ScreenLayout({dev(localId,"local",0,0),dev(remoteId,"remote",100,0)}),localId);
    EXPECT_TRUE(widget.isSimpleMode());
    EXPECT_EQ(widget.visibleDeviceCount(),2);
    EXPECT_FALSE(widget.legacyGridVisible());
    widget.setTechnicalAdjustmentsVisible(true);
    EXPECT_TRUE(widget.legacyGridVisible());
    EXPECT_EQ(widget.visibleDeviceCount(),2);
}

TEST(ScreenLayoutEditorTests, HoverSnapSignalsAndAccessibilityAreExposed)
{
    ScreenLayoutEditorWidget widget;
    widget.setLayoutModel(ScreenLayout({dev(localId,"local",0,0),dev(remoteId,"remote",100,0)}),localId);
    QSignalSpy hover(&widget,&ScreenLayoutEditorWidget::dropTargetChanged);
    widget.previewDrop(remoteId,localId,ScreenLayoutEditorViewModel::Direction::Above);
    ASSERT_EQ(hover.count(),1);
    EXPECT_FALSE(widget.accessibleName().isEmpty());
    EXPECT_FALSE(widget.accessibleDescription().isEmpty());
    EXPECT_EQ(widget.focusPolicy(),Qt::StrongFocus);
    EXPECT_TRUE(widget.statusText().contains("Acima"));
}

TEST(ScreenLayoutEditorTests, SimulationCanCancelOrFinishWithoutChangingLayout)
{
    ScreenLayoutEditorWidget widget;
    const ScreenLayout initial({dev(localId,"local",0,0),dev(remoteId,"remote",100,0)});
    widget.setLayoutModel(initial,localId);
    QSignalSpy finished(&widget,&ScreenLayoutEditorWidget::simulationFinished);
    widget.startPassageSimulation();
    EXPECT_TRUE(widget.simulationActive());
    EXPECT_TRUE(widget.statusText().contains("simulação",Qt::CaseInsensitive));
    widget.cancelPassageSimulation();
    EXPECT_FALSE(widget.simulationActive());
    EXPECT_EQ(widget.layoutModel().devices()[1].geometry,initial.devices()[1].geometry);
    widget.setSimulationIntervalForTest(1);
    widget.startPassageSimulation();
    QTRY_COMPARE_WITH_TIMEOUT(finished.count(),1,100);
    EXPECT_FALSE(widget.simulationActive());
    EXPECT_EQ(widget.layoutModel().devices()[1].geometry,initial.devices()[1].geometry);
}

TEST(ScreenLayoutEditorTests, KeyboardMovesSelectedCardWithControlArrows)
{
    ScreenLayoutEditorWidget widget;
    widget.setLayoutModel(ScreenLayout({dev(localId,"local",0,0),dev(remoteId,"remote",100,0)}),localId);
    widget.selectDevice(remoteId);
    widget.show();
    widget.setFocus();
    QTest::keyClick(&widget,Qt::Key_Down,Qt::ControlModifier);
    EXPECT_EQ(widget.layoutModel().devices()[1].geometry,QRect(0,100,100,100));
}

TEST(ScreenLayoutEditorTests, MouseDragSnapsCardToChosenSide)
{
    ScreenLayoutEditorWidget widget;widget.resize(500,300);
    widget.setLayoutModel(ScreenLayout({dev(localId,"local",0,0),dev(remoteId,"remote",100,0)}),localId);
    QSignalSpy changed(&widget,&ScreenLayoutEditorWidget::layoutChanged);
    widget.show();QCoreApplication::processEvents();
    QTest::mousePress(&widget,Qt::LeftButton,Qt::NoModifier,QPoint(350,100));
    QTest::mouseMove(&widget,QPoint(70,100),20);
    QTest::mouseRelease(&widget,Qt::LeftButton,Qt::NoModifier,QPoint(70,100));
    ASSERT_EQ(changed.count(),1);
    EXPECT_EQ(widget.layoutModel().devices()[1].geometry,QRect(-100,0,100,100));
}

TEST(ScreenLayoutEditorTests, HeterogeneousSizesSnapWithoutGapAndOversizedGridIsRejected)
{
    auto local=dev(localId,"local",0,0);auto remote=dev(remoteId,"remote",100,0);remote.geometry.setSize({50,50});
    ScreenLayoutEditorViewModel model(ScreenLayout({local,remote}),localId);
    ASSERT_TRUE(model.moveAdjacent(remoteId,localId,ScreenLayoutEditorViewModel::Direction::Left));
    EXPECT_EQ(model.device(remoteId)->geometry,QRect(-50,0,50,50));
    std::vector<ScreenLayout::Device> vertical;for(int i=0;i<5;++i)vertical.push_back(dev(QUuid::createUuid(),QString("d%1").arg(i),0,i*100));
    EXPECT_FALSE(ScreenLayoutEditorViewModel(ScreenLayout(vertical),vertical[0].uuid).toLegacyGrid(5,3).has_value());
    EXPECT_FALSE(ScreenLayoutEditorViewModel(ScreenLayout({local,remote}),QUuid::createUuid()).toLegacyGrid(5,3).has_value());
}

TEST(ScreenLayoutEditorTests, SimpleCanvasPaintsOnlyLocalAndFourRemotes)
{
    std::vector<ScreenLayout::Device> devices;for(int i=0;i<6;++i)devices.push_back(dev(QUuid::createUuid(),QString("d%1").arg(i),i*100,0));
    ScreenLayoutEditorWidget widget;widget.resize(700,300);widget.setLayoutModel(ScreenLayout(devices),devices[5].uuid);widget.show();QCoreApplication::processEvents();
    EXPECT_EQ(widget.interactiveCardCountForTest(),5);
}

TEST(ScreenLayoutEditorTests, ComputerCardSummarizesMonitorsWithoutExposingTechnicalIds)
{
    auto local=dev(localId,"local",0,0);
    local.monitors={{"secret-hardware-id-a",{0,0,50,100}},{"secret-hardware-id-b",{50,0,50,100}}};
    ScreenLayoutEditorWidget widget;widget.resize(400,280);widget.setLayoutModel(ScreenLayout({local}),localId);widget.show();QCoreApplication::processEvents();
    EXPECT_EQ(widget.monitorSummaryForTest(localId),QStringLiteral("2 monitores"));
    const QString accessible=widget.cardAccessibleDescriptionForTest(localId);
    EXPECT_TRUE(accessible.contains(QStringLiteral("2 monitores")));
    EXPECT_FALSE(accessible.contains(QStringLiteral("secret-hardware-id")));
}
