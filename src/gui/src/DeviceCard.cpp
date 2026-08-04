#include "DeviceCard.h"
#include "DeviceCardDropPolicy.h"
#include "EndpointPolicy.h"
#include <QLabel>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QHostAddress>
#include <QProgressBar>
#include <QDragEnterEvent>
#include <QDragMoveEvent>
#include <QDropEvent>
#include <QStyle>
#include <algorithm>

namespace {
QString statusText(DeviceConnectionModel::State state,DeviceConnectionModel::Direction direction) {
    switch(state) {
    case DeviceConnectionModel::State::Available:return QObject::tr("● Disponível");
    case DeviceConnectionModel::State::Connecting:return QObject::tr("◌ Conectando…");
    case DeviceConnectionModel::State::Connected:
        if(direction==DeviceConnectionModel::Direction::LocalControlsRemote)return QObject::tr("● Conectado — você controla este computador");
        if(direction==DeviceConnectionModel::Direction::RemoteControlsLocal)return QObject::tr("● Conectado — este computador controla o seu");
        return QObject::tr("● Conectado");
    case DeviceConnectionModel::State::Controlling:return QObject::tr("◆ Você controla este computador");
    case DeviceConnectionModel::State::Transferring:return QObject::tr("⇧ Transferindo arquivos");
    case DeviceConnectionModel::State::Incompatible:return QObject::tr("⚠ Versão incompatível");
    case DeviceConnectionModel::State::Error:return QObject::tr("! Não foi possível conectar");
    case DeviceConnectionModel::State::Offline:return QObject::tr("○ Offline");
    }
    return QObject::tr("○ Offline");
}
bool hasUsableAddress(const QSet<QString>& addresses) { return !EndpointPolicy::firstUsable(addresses.values()).isEmpty(); }
}
DeviceCard::DeviceCard(QWidget* parent):QFrame(parent) {
    setObjectName("discoveredDeviceCard"); setFocusPolicy(Qt::StrongFocus);
    auto* root=new QVBoxLayout(this); root->setContentsMargins(10,8,10,8); root->setSpacing(5);
    auto* top=new QHBoxLayout; name_=new QLabel(this); name_->setObjectName("deviceNameLabel"); name_->setStyleSheet("font-weight:600");
    os_=new QLabel(this); os_->setObjectName("deviceOsLabel"); top->addWidget(name_,1); top->addWidget(os_); root->addLayout(top);
    status_=new QLabel(this); status_->setObjectName("deviceStatusLabel"); compatibility_=new QLabel(this); compatibility_->setObjectName("deviceCompatibilityLabel");
    auto* stateRow=new QHBoxLayout; stateRow->addWidget(status_); stateRow->addWidget(compatibility_,1); root->addLayout(stateRow);
    update_=new QLabel(this); update_->setObjectName("deviceUpdateLabel"); update_->setStyleSheet("font-weight:600;color:#b45309"); update_->hide(); root->addWidget(update_);
    lastContact_=new QLabel(this); lastContact_->setObjectName("deviceLastContactLabel"); root->addWidget(lastContact_);
    transferText_=new QLabel(this); transferText_->setObjectName("deviceTransferText"); transferText_->hide(); root->addWidget(transferText_);
    transferProgress_=new QProgressBar(this); transferProgress_->setObjectName("deviceTransferProgress"); transferProgress_->setRange(0,100); transferProgress_->hide(); root->addWidget(transferProgress_);
    auto* actions=new QHBoxLayout; connect_=new QPushButton(tr("Conectar"),this); connect_->setObjectName("deviceConnectButton");
    pair_=new QPushButton(tr("Parear"),this); pair_->setObjectName("devicePairButton"); sendFile_=new QPushButton(tr("Enviar arquivo"),this); sendFile_->setObjectName("deviceSendFileButton");
    rename_=new QPushButton(tr("Renomear"),this); rename_->setObjectName("deviceRenameButton"); details_=new QPushButton(tr("Detalhes"),this); details_->setObjectName("deviceDetailsButton"); permissions_=new QPushButton(tr("Permissões"),this); permissions_->setObjectName("devicePermissionsButton");
    for(auto* b:{connect_,pair_,sendFile_,rename_,details_,permissions_}) { b->setFocusPolicy(Qt::StrongFocus); actions->addWidget(b); } root->addLayout(actions);
    connect(connect_,&QPushButton::clicked,this,[this]{emit connectRequested(device_);}); connect(pair_,&QPushButton::clicked,this,[this]{emit pairRequested(device_);});
    connect(sendFile_,&QPushButton::clicked,this,[this]{emit sendFileRequested(device_);}); connect(details_,&QPushButton::clicked,this,[this]{emit detailsRequested(device_);}); connect(rename_,&QPushButton::clicked,this,[this]{emit renameRequested(device_);}); connect(permissions_,&QPushButton::clicked,this,[this]{emit permissionsRequested(device_);});
}
void DeviceCard::setDevice(const DiscoveredDeviceView& d) {
    device_=d; name_->setText(d.displayName); os_->setText(d.operatingSystem); status_->setText(statusText(d.state,d.direction));
    compatibility_->setText(!d.compatible?d.negotiation.base.reason:(d.pairedThisSession?tr("Pareado nesta sessão"):d.negotiation.base.reason));
    compatibility_->setToolTip(d.negotiation.base.technical);
    update_->setVisible(d.updateAvailable);
    update_->setText(d.updateAvailable ? tr("Atualização disponível neste computador") : QString());
    update_->setAccessibleName(update_->text());
    QString tone="muted",color="#64748b"; if(d.state==DeviceConnectionModel::State::Connected||d.state==DeviceConnectionModel::State::Controlling){tone="success";color="#15803d";}else if(d.state==DeviceConnectionModel::State::Available||d.state==DeviceConnectionModel::State::Connecting){tone="info";color="#2563eb";}else if(d.state==DeviceConnectionModel::State::Transferring){tone="transfer";color="#7e22ce";}else if(d.state==DeviceConnectionModel::State::Error||d.state==DeviceConnectionModel::State::Incompatible){tone="warning";color="#b91c1c";}
    status_->setProperty("stateTone",tone); status_->setStyleSheet(QString("font-weight:600;color:%1").arg(color)); status_->setAccessibleName(tr("Estado: %1").arg(status_->text())); status_->setAccessibleDescription(tr("Indicador %1 com ícone e texto; não depende apenas de cor.").arg(tone));
    const bool usable=hasUsableAddress(d.addresses), available=d.state==DeviceConnectionModel::State::Available;
    connect_->setVisible(available||!d.compatible); connect_->setEnabled(connectionInitiationAllowed_&&d.role==ZeroconfRole::Server&&available&&d.compatible&&d.discoveryAvailable&&d.controlPort&&usable);
    const auto pairing=d.negotiation.capability(CapabilityId::Pairing);
    pair_->setVisible(available&&d.compatible); pair_->setEnabled(available&&d.discoveryAvailable&&!d.pairedThisSession&&pairing.protocolCompatible()); pair_->setText(d.pairedThisSession?tr("Pareado nesta sessão"):tr("Parear"));
    pair_->setToolTip(pairing.protocolCompatible()?(d.pairingPort?tr("Digite o código mostrado no outro computador ou mostre um código neste computador."):tr("Este computador não está mostrando um código; você ainda pode mostrar um código aqui.")):pairing.reason);
    const bool active=d.state==DeviceConnectionModel::State::Connected||d.state==DeviceConnectionModel::State::Controlling;
    sendFile_->setVisible(active&&d.capabilities.contains(ZeroconfCapability::FileTransfer)&&d.transferPort&&usable); permissions_->setVisible(!d.uuid.isNull()); permissions_->setEnabled(!d.uuid.isNull());
    sendFile_->setEnabled(d.negotiation.capabilityAllowed(CapabilityId::FileTransfer));
    sendFile_->setToolTip(d.negotiation.capability(CapabilityId::FileTransfer).reason); details_->show();
    setAcceptDrops(transferEnabled());
    setAccessibleName(tr("Computador %1, %2, %3").arg(d.displayName,d.operatingSystem,status_->text()));
    name_->setAccessibleName(tr("Nome do computador")); os_->setAccessibleName(tr("Sistema operacional: %1").arg(d.operatingSystem)); connect_->setAccessibleName(tr("Conectar a %1").arg(d.displayName)); details_->setAccessibleName(tr("Ver detalhes de %1").arg(d.displayName)); rename_->setAccessibleName(tr("Renomear %1").arg(d.displayName));
    updateLastContact();
}
bool DeviceCard::transferEnabled() const { return (device_.state==DeviceConnectionModel::State::Connected||device_.state==DeviceConnectionModel::State::Controlling)&&device_.negotiation.capabilityAllowed(CapabilityId::FileTransfer)&&device_.capabilities.contains(ZeroconfCapability::FileTransfer)&&device_.transferPort&&hasUsableAddress(device_.addresses); }
void DeviceCard::setDropFeedback(bool active,const QString& text){setProperty("dropActive",active);style()->unpolish(this);style()->polish(this);if(active&&!text.isEmpty())setAccessibleDescription(text);else updateLastContact();}
void DeviceCard::dragEnterEvent(QDragEnterEvent* e){const auto r=DeviceCardDropPolicy::evaluate(e->mimeData());if(transferEnabled()&&r.accepted){e->setDropAction(Qt::CopyAction);e->accept();setDropFeedback(true,tr("Solte para enviar a %1.").arg(device_.displayName));}else{e->ignore();setDropFeedback(false);}}
void DeviceCard::dragMoveEvent(QDragMoveEvent* e){const auto r=DeviceCardDropPolicy::evaluate(e->mimeData());if(transferEnabled()&&r.accepted){e->setDropAction(Qt::CopyAction);e->accept();}else e->ignore();}
void DeviceCard::dragLeaveEvent(QDragLeaveEvent* e){setDropFeedback(false);e->accept();}
void DeviceCard::dropEvent(QDropEvent* e){const auto r=DeviceCardDropPolicy::evaluate(e->mimeData());setDropFeedback(false);if(!transferEnabled()||!r.accepted){e->ignore();return;}e->setDropAction(Qt::CopyAction);e->accept();emit filesDropped(device_.uuid,r.paths);}
void DeviceCard::setTransferProgress(const QUuid& id,const QString& fileName,quint64 done,quint64 total){if(id!=device_.uuid)return;const int value=total?static_cast<int>((done*100)/total):0;transferProgress_->setValue(value);transferProgress_->show();transferText_->setText(tr("Enviando %1 — %2%").arg(fileName).arg(value));transferText_->setAccessibleName(transferText_->text());transferText_->show();}
void DeviceCard::finishTransfer(const QUuid& id,bool,const QString&){if(id!=device_.uuid)return;transferProgress_->hide();transferText_->hide();}
void DeviceCard::setNow(const QDateTime& now){now_=now;updateLastContact();}
void DeviceCard::updateLastContact(){
    if(!lastContact_)return; const QDateTime now=now_.isValid()?now_:QDateTime::currentDateTimeUtc(); QString relative=tr("desconhecido");
    if(device_.lastObserved.isValid()){const qint64 seconds=(std::max)(qint64(0),device_.lastObserved.secsTo(now));if(seconds<60)relative=tr("agora");else if(seconds<3600)relative=tr("há %1 min").arg(seconds/60);else if(seconds<86400)relative=tr("há %1 h").arg(seconds/3600);else relative=tr("há %1 d").arg(seconds/86400);}
    lastContact_->setText(tr("Último contato: %1").arg(relative)); lastContact_->setAccessibleName(lastContact_->text());setAccessibleDescription(tr("Cartão de dispositivo real. %1").arg(lastContact_->text()));
}
