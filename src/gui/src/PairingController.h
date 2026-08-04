#pragma once
#include "PairingProtocolCodec.h"
#include <QObject>
#include <QHostAddress>
#include <QTimer>
#include <optional>
class QTcpServer; class QTcpSocket;

class PairingController : public QObject {
    Q_OBJECT
public:
    explicit PairingController(QObject* parent=nullptr);
    ~PairingController() override;
    std::optional<PairingService::CreatedInvite> listen(const QUuid& local,const QUuid& remote,const QHostAddress& address=QHostAddress::Any,quint16 port=0);
    void connectTo(const QUuid& inviter,const QUuid& local,const QHostAddress& address,quint16 port);
    void submitCode(const QByteArray& code);
    void setLocalDeviceMetadata(std::vector<ScreenLayout::Monitor> monitors) { localMonitors_=std::move(monitors); }
    void setPeerSupportsDeviceMetadata(bool supported) { peerSupportsMetadata_=supported; }
    void cancel();
    quint16 port() const;
    std::optional<PairingService::PublicInvite> publicInvite() const { return invite_; }
    std::optional<QByteArray> pairKey(const QUuid& peer) const { return service_.pairKey(peer); }
Q_SIGNALS:
    void inviteReceived();
    void pairingPortChanged(quint16 port);
    void paired(const QUuid& peer);
    void authenticatedDeviceMetadata(const QUuid& remoteUuid,const std::vector<ScreenLayout::Monitor>& monitors);
    void failed(const QString& message);
    void cancelled();
private:
    enum class Stage { Idle, WaitingHello, WaitingInvite, WaitingCode, WaitingChallenge, WaitingM1, WaitingM2, WaitingM3, WaitingSuccess, WaitingConfirmed, Paired, Failed };
    void acceptConnection(); void readFrames(); void process(const PairingProtocolCodec::Message&); void send(const PairingProtocolCodec::Message&); void fail(const QString&,bool notifyPeer=true); void armTimeout();
    void sendLocalMetadata();
    PairingService service_; QTcpServer* server_=nullptr; QTcpSocket* socket_=nullptr; QByteArray buffer_,sessionId_; std::optional<PairingService::PublicInvite> invite_; QUuid local_,peer_; QHostAddress fixedAddress_; QTimer timer_; Stage stage_=Stage::Idle; bool serverRole_=false,terminal_=false,metadataSent_=false,metadataReceived_=false,peerSupportsMetadata_=false; std::vector<ScreenLayout::Monitor> localMonitors_;
};
