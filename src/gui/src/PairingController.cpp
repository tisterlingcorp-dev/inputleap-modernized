#include "PairingController.h"
#include <QTcpServer>
#include <QTcpSocket>

namespace {
PairingProtocolCodec::Message flight(PairingProtocolCodec::Type t,const QByteArray& sid,const QByteArray& iid,const QByteArray& value){PairingProtocolCodec::Message m;m.type=t;m.sessionId=sid;m.inviteId=iid;m.value=value;return m;}
QString protocolError(){return QString::fromUtf8("Não foi possível confirmar o código.");}
}
PairingController::PairingController(QObject*p):QObject(p){timer_.setSingleShot(true);timer_.setInterval(300000);connect(&timer_,&QTimer::timeout,this,[this]{fail(QString::fromUtf8("O pareamento expirou."));});}
PairingController::~PairingController(){cancel();}
std::optional<PairingService::CreatedInvite> PairingController::listen(const QUuid&local,const QUuid&remote,const QHostAddress&a,quint16 p){cancel();terminal_=false;serverRole_=true;stage_=Stage::WaitingHello;local_=local;peer_=remote;auto made=service_.createInvite(local,remote);if(!made){fail(QString::fromUtf8("Não foi possível criar o convite."),false);return{};}invite_=made->publicInvite;server_=new QTcpServer(this);connect(server_,&QTcpServer::newConnection,this,&PairingController::acceptConnection);if(!server_->listen(a,p)){fail(QString::fromUtf8("Não foi possível abrir a porta de pareamento."),false);return{};}emit pairingPortChanged(server_->serverPort());armTimeout();return made;}
void PairingController::connectTo(const QUuid&inviter,const QUuid&local,const QHostAddress&a,quint16 p){cancel();terminal_=false;serverRole_=false;stage_=Stage::WaitingInvite;local_=local;peer_=inviter;fixedAddress_=a;socket_=new QTcpSocket(this);connect(socket_,&QTcpSocket::readyRead,this,&PairingController::readFrames);connect(socket_,&QTcpSocket::disconnected,this,[this]{if(!terminal_&&stage_!=Stage::Paired)fail(QString::fromUtf8("A conexão de pareamento foi encerrada."),false);});connect(socket_,&QTcpSocket::errorOccurred,this,[this](auto){if(!terminal_&&stage_!=Stage::Paired)fail(QString::fromUtf8("Não foi possível conectar ao computador."),false);});socket_->connectToHost(a,p);armTimeout();}
void PairingController::acceptConnection(){while(server_->hasPendingConnections()){auto* candidate=server_->nextPendingConnection();if(socket_||stage_!=Stage::WaitingHello){candidate->disconnectFromHost();candidate->deleteLater();continue;}socket_=candidate;fixedAddress_=candidate->peerAddress();server_->close();emit pairingPortChanged(0);connect(socket_,&QTcpSocket::readyRead,this,&PairingController::readFrames);connect(socket_,&QTcpSocket::disconnected,this,[this]{if(!terminal_&&stage_!=Stage::Paired)fail(QString::fromUtf8("A conexão de pareamento foi encerrada."),false);});send(PairingProtocolCodec::invite(*invite_));}}
void PairingController::submitCode(const QByteArray&code){if(serverRole_||!invite_||!socket_||terminal_||stage_!=Stage::WaitingCode)return;if(invite_->localUuid!=peer_||invite_->expectedRemoteUuid!=local_){fail(QString::fromUtf8("O convite pertence a outro computador."));return;}auto h=service_.beginPairing(*invite_,code,local_,peer_);if(!h){fail(protocolError());return;}sessionId_=h->sessionId;stage_=Stage::WaitingChallenge;send(flight(PairingProtocolCodec::Type::Hello,h->sessionId,h->inviteId,h->A));armTimeout();}
void PairingController::readFrames(){if(!socket_||socket_->peerAddress()!=fixedAddress_){fail(QString::fromUtf8("O endereço do computador mudou."));return;}constexpr qint64 MaxBuffered=qint64(PairingProtocolCodec::MaxPayload)+4;if(socket_->bytesAvailable()>MaxBuffered-buffer_.size()){fail(QString::fromUtf8("Mensagem de pareamento grande demais."));return;}buffer_+=socket_->read(MaxBuffered-buffer_.size());for(;;){if(buffer_.size()<4)return;quint32 n=0;for(int i=0;i<4;i++)n=(n<<8)|quint8(buffer_[i]);if(n==0||n>PairingProtocolCodec::MaxPayload){fail(QString::fromUtf8("Mensagem de pareamento grande demais."));return;}if(buffer_.size()<int(n)+4)return;QByteArray frame=buffer_.left(n+4);buffer_.remove(0,n+4);PairingProtocolCodec::Message m;QString e;if(!PairingProtocolCodec::decodeFrame(frame,&m,&e)){if(stage_==Stage::Paired)continue;fail(e);return;}process(m);if(terminal_)return;}}
void PairingController::process(const PairingProtocolCodec::Message&m){
    if(m.type==PairingProtocolCodec::Type::Error){fail(m.error,false);return;}
    if(stage_==Stage::WaitingInvite&&m.type==PairingProtocolCodec::Type::Invite&&!serverRole_){
        if(m.invite.localUuid!=peer_||m.invite.expectedRemoteUuid!=local_){fail(QString::fromUtf8("Identidade do convite não confere."));return;}
        invite_=m.invite;stage_=Stage::WaitingCode;emit inviteReceived();return;
    }
    if(!invite_){fail(QString::fromUtf8("Mensagem fora de ordem."));return;}
    switch(m.type){
    case PairingProtocolCodec::Type::Hello:{
        if(!serverRole_||stage_!=Stage::WaitingHello)break;
        PairingService::ClientHello h{m.sessionId,m.value,m.inviteId};auto x=service_.respondToClient(*invite_,h);
        if(x){sessionId_=x->sessionId;stage_=Stage::WaitingM1;send(flight(PairingProtocolCodec::Type::Challenge,x->sessionId,x->inviteId,x->B));armTimeout();return;}break;}
    case PairingProtocolCodec::Type::Challenge:{
        if(serverRole_||stage_!=Stage::WaitingChallenge||m.sessionId!=sessionId_||m.inviteId!=invite_->inviteId)break;
        PairingService::ServerChallenge x{m.sessionId,m.value,m.inviteId};auto y=service_.answerChallenge(x);
        if(y){stage_=Stage::WaitingM2;send(flight(PairingProtocolCodec::Type::ClientProof,y->sessionId,invite_->inviteId,y->M1));armTimeout();return;}break;}
    case PairingProtocolCodec::Type::ClientProof:{
        if(!serverRole_||stage_!=Stage::WaitingM1||m.sessionId!=sessionId_||m.inviteId!=invite_->inviteId)break;
        auto y=service_.verifyClientProof({m.sessionId,m.value});
        if(y){stage_=Stage::WaitingM3;send(flight(PairingProtocolCodec::Type::ServerProof,y->sessionId,invite_->inviteId,y->M2));armTimeout();return;}break;}
    case PairingProtocolCodec::Type::ServerProof:{
        if(serverRole_||stage_!=Stage::WaitingM2||m.sessionId!=sessionId_||m.inviteId!=invite_->inviteId)break;
        auto y=service_.verifyServerProof({m.sessionId,m.value});
        if(y){stage_=Stage::WaitingSuccess;send(flight(PairingProtocolCodec::Type::FinalAck,y->sessionId,invite_->inviteId,y->M3));armTimeout();return;}break;}
    case PairingProtocolCodec::Type::FinalAck:{
        if(!serverRole_||stage_!=Stage::WaitingM3||m.sessionId!=sessionId_||m.inviteId!=invite_->inviteId)break;
        if(service_.finalize({m.sessionId,m.value})==PairingService::Status::Accepted){send(PairingProtocolCodec::success(m.sessionId));stage_=Stage::WaitingConfirmed;armTimeout();return;}break;}
    case PairingProtocolCodec::Type::Success:
        if(!serverRole_&&stage_==Stage::WaitingSuccess&&m.sessionId==sessionId_&&service_.pairKey(peer_)){send(PairingProtocolCodec::confirmed(m.sessionId));stage_=Stage::Paired;timer_.stop();emit paired(peer_);return;}break;
    case PairingProtocolCodec::Type::Confirmed:
        if(serverRole_&&stage_==Stage::WaitingConfirmed&&m.sessionId==sessionId_&&service_.pairKey(peer_)){stage_=Stage::Paired;timer_.stop();emit paired(peer_);sendLocalMetadata();return;}break;
    case PairingProtocolCodec::Type::DeviceMetadata:{
        if(stage_!=Stage::Paired||!peerSupportsMetadata_||metadataReceived_)break;
        auto key=service_.pairKey(peer_);
        if(!key||!PairingProtocolCodec::authenticateDeviceMetadata(m,*key,sessionId_,invite_->inviteId,peer_,local_))return;
        metadataReceived_=true;emit authenticatedDeviceMetadata(peer_,m.monitors);
        if(!serverRole_)sendLocalMetadata();
        return;}
    default:break;
    }
    fail(protocolError());
}
void PairingController::send(const PairingProtocolCodec::Message&m){auto f=PairingProtocolCodec::encode(m);if(socket_&&!f.isEmpty())socket_->write(f);}
void PairingController::sendLocalMetadata(){if(!peerSupportsMetadata_||metadataSent_||localMonitors_.empty()||stage_!=Stage::Paired||!invite_)return;auto key=service_.pairKey(peer_);if(!key)return;auto message=PairingProtocolCodec::deviceMetadata(*key,sessionId_,invite_->inviteId,local_,peer_,localMonitors_);if(message){metadataSent_=true;send(*message);}}
void PairingController::fail(const QString&e,bool notify){if(terminal_)return;if(notify&&socket_)send(PairingProtocolCodec::error(e));stage_=Stage::Failed;terminal_=true;timer_.stop();emit failed(e);if(socket_)socket_->disconnectFromHost();}
void PairingController::armTimeout(){timer_.start();}
quint16 PairingController::port()const{return server_?server_->serverPort():0;}
void PairingController::cancel(){timer_.stop();bool active=socket_||server_;if(active&&!peer_.isNull())service_.revoke(peer_);terminal_=true;metadataSent_=false;metadataReceived_=false;stage_=Stage::Idle;buffer_.clear();sessionId_.clear();invite_.reset();if(socket_){socket_->abort();socket_->deleteLater();socket_=nullptr;}if(server_){server_->close();server_->deleteLater();server_=nullptr;}if(active)emit cancelled();}
