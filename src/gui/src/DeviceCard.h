#pragma once
#include "DiscoveredDevicesModel.h"
#include <QFrame>
class QLabel; class QPushButton; class QProgressBar; class QDragEnterEvent; class QDragMoveEvent; class QDropEvent; class QDragLeaveEvent;

class DeviceCard : public QFrame {
    Q_OBJECT
public:
    explicit DeviceCard(QWidget* parent=nullptr);
    void setDevice(const DiscoveredDeviceView& device);
    void setNow(const QDateTime& now);
    void setConnectionInitiationAllowed(bool allowed) { connectionInitiationAllowed_=allowed; setDevice(device_); }
    void setTransferProgress(const QUuid& deviceUuid,const QString& fileName,quint64 bytesDone,quint64 bytesTotal);
    void finishTransfer(const QUuid& deviceUuid,bool success,const QString& errorMessage);
    QUuid uuid() const { return device_.uuid; }
Q_SIGNALS:
    void connectRequested(const DiscoveredDeviceView& device);
    void pairRequested(const DiscoveredDeviceView& device);
    void sendFileRequested(const DiscoveredDeviceView& device);
    void detailsRequested(const DiscoveredDeviceView& device);
    void permissionsRequested(const DiscoveredDeviceView& device);
    void renameRequested(const DiscoveredDeviceView& device);
    void filesDropped(const QUuid& deviceUuid,const QStringList& paths);
protected:
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dragMoveEvent(QDragMoveEvent* event) override;
    void dragLeaveEvent(QDragLeaveEvent* event) override;
    void dropEvent(QDropEvent* event) override;
private:
    void updateLastContact();
    bool transferEnabled() const;
    void setDropFeedback(bool active,const QString& text={});
    DiscoveredDeviceView device_;
    QDateTime now_;
    bool connectionInitiationAllowed_=false;
    QLabel *name_, *os_, *status_, *compatibility_, *update_, *lastContact_, *transferText_;
    QProgressBar* transferProgress_;
    QPushButton *connect_, *pair_, *sendFile_, *details_, *rename_, *permissions_;
};
