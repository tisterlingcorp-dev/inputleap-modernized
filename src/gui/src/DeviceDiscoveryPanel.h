#pragma once
#include "DeviceCard.h"
#include <QFrame>
class QLabel; class QPushButton; class QVBoxLayout; class QTimer;
class DeviceDiscoveryPanel : public QFrame {
    Q_OBJECT
public:
    explicit DeviceDiscoveryPanel(DiscoveredDevicesModel* model, QWidget* parent=nullptr);
    void setConnectionInitiationAllowed(bool allowed);
Q_SIGNALS:
    void connectRequested(const DiscoveredDeviceView&);
    void pairRequested(const DiscoveredDeviceView&);
    void sendFileRequested(const DiscoveredDeviceView&);
    void detailsRequested(const DiscoveredDeviceView&);
    void permissionsRequested(const DiscoveredDeviceView&);
    void renameRequested(const DiscoveredDeviceView&);
    void filesDropped(const QUuid&,const QStringList&);
    void manualAddressRequested();
public Q_SLOTS:
    void setTransferProgress(const QUuid&,const QString&,quint64,quint64);
    void finishTransfer(const QUuid&,bool,const QString&);
private Q_SLOTS: void rebuild(); void refreshRelativeTimes();
private:
    DiscoveredDevicesModel* model_; QVBoxLayout* cards_; QPushButton* more_; QPushButton* manual_;
    bool expanded_ = false;
    bool connectionInitiationAllowed_ = false;
    QTimer* relativeTimer_;
};
