#pragma once
#include "PairingController.h"
#include <QWizard>
class QLineEdit; class QLabel;

class PairingWizard : public QWizard {
    Q_OBJECT
public:
    enum Page { EndpointPage,CodePage,ProfilePage };
    // Client: connects to an inviter already advertising pairingPort.
    PairingWizard(const QUuid& inviter,const QUuid& local,const QHostAddress& address,quint16 port,QWidget* parent=nullptr);
    // Inviter: opens a listener first, then displays its locally generated code.
    PairingWizard(const QUuid& local,const QUuid& remote,const QHostAddress& address=QHostAddress::Any,QWidget* parent=nullptr);
    QString errorText() const;
    void setCodeForTest(const QString&);
    QString displayCode() const { return displayCode_; }
    quint16 pairingPort() const { return controller_.port(); }
    bool isInviter() const { return inviterRole_; }
    QString alias() const;
    void setLocalDeviceMetadata(std::vector<ScreenLayout::Monitor> monitors) { controller_.setLocalDeviceMetadata(std::move(monitors)); }
    void setPeerSupportsDeviceMetadata(bool supported) { controller_.setPeerSupportsDeviceMetadata(supported); }

Q_SIGNALS:
    void cancelledSafely();
    void listenerReady(quint16 port);
    void pairingCompleted(const QUuid& peer,const QByteArray& sessionKey,const QString& alias);
    void authenticatedDeviceMetadata(const QUuid& remoteUuid,const std::vector<ScreenLayout::Monitor>& monitors);
public slots: void reject() override;
protected: bool validateCurrentPage() override;
private:
    void buildUi(); void wireController();
    PairingController controller_; QUuid inviter_,local_,peer_; QHostAddress address_; quint16 port_=0;
    QLineEdit *code_=nullptr,*alias_=nullptr; QLabel* error_=nullptr;
    QString displayCode_; bool confirmed_=false,started_=false,inviterRole_=false;
};
