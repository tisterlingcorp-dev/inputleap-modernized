/* InputLeap -- mouse and keyboard sharing utility */
#pragma once

#include "ScreenSetupModel.h"
#include <QWidget>
#include <QTimer>
#include <QHash>

class ScreenLayoutEditorViewModel
{
public:
    enum class Direction { Left, Right, Above, Below };
    ScreenLayoutEditorViewModel() = default;
    ScreenLayoutEditorViewModel(ScreenLayout layout, QUuid localUuid);
    bool moveAdjacent(const QUuid& moving, const QUuid& anchor, Direction direction);
    const ScreenLayout::Device* device(const QUuid& uuid) const;
    const ScreenLayout& layout() const { return layout_; }
    std::optional<QStringList> toLegacyGrid(int columns,int rows) const;
private:
    ScreenLayout layout_;
    QUuid localUuid_;
};

class ScreenLayoutEditorWidget : public QWidget
{
    Q_OBJECT
public:
    explicit ScreenLayoutEditorWidget(QWidget* parent=nullptr);
    void setLayoutModel(const ScreenLayout& layout,const QUuid& localUuid);
    void setDevicePresentation(const QUuid& uuid,const QString& displayName,const QString& operatingSystem);
    const ScreenLayout& layoutModel() const { return model_.layout(); }
    QUuid localUuid() const { return localUuid_; }
    bool isSimpleMode() const { return !technicalVisible_; }
    int visibleDeviceCount() const;
    int interactiveCardCountForTest() const { return cardRects_.size(); }
    QString monitorSummaryForTest(const QUuid& uuid) const;
    QString cardAccessibleDescriptionForTest(const QUuid& uuid) const;
    bool legacyGridVisible() const { return technicalVisible_; }
    void setTechnicalAdjustmentsVisible(bool visible);
    QString statusText() const { return status_; }
    void previewDrop(const QUuid& moving,const QUuid& anchor,ScreenLayoutEditorViewModel::Direction direction);
    void selectDevice(const QUuid& uuid) { selected_=uuid; update(); }
    bool simulationActive() const { return simulationTimer_.isActive(); }
    void startPassageSimulation();
    void cancelPassageSimulation();
    void setSimulationIntervalForTest(int milliseconds) { interval_=milliseconds; }
signals:
    void layoutChanged();
    void dropTargetChanged(const QString& description);
    void simulationFinished();
protected:
    void paintEvent(QPaintEvent*) override;
    void keyPressEvent(QKeyEvent*) override;
    void mousePressEvent(QMouseEvent*) override;
    void mouseMoveEvent(QMouseEvent*) override;
    void mouseReleaseEvent(QMouseEvent*) override;
private:
    static QString directionText(ScreenLayoutEditorViewModel::Direction direction);
    void updateDropTarget(const QPoint& position);
    ScreenLayoutEditorViewModel model_;
    QUuid localUuid_,selected_;
    bool technicalVisible_=false;
    QString status_;
    QTimer simulationTimer_;
    int remaining_=0,interval_=1000;
    QHash<QUuid,QRectF> cardRects_;
    QHash<QUuid,QString> displayNames_,operatingSystems_;
    QUuid dragged_,dropAnchor_;
    QPoint dragStart_;
    ScreenLayoutEditorViewModel::Direction dropDirection_=ScreenLayoutEditorViewModel::Direction::Right;
    bool dragging_=false,hasDropTarget_=false;
};
