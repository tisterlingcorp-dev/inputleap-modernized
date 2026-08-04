#include "DeviceDiscoveryPanel.h"
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QTimer>

DeviceDiscoveryPanel::DeviceDiscoveryPanel(DiscoveredDevicesModel* model,QWidget* parent):QFrame(parent),model_(model) {
    setObjectName("deviceDiscoveryPanel"); setAccessibleName(tr("Computadores encontrados"));
    auto* root=new QVBoxLayout(this); root->setContentsMargins(0,8,0,0); root->setSpacing(6);
    auto* title=new QLabel(tr("Computadores encontrados"),this); title->setObjectName("discoveryTitle"); title->setAccessibleName(tr("Computadores encontrados")); root->addWidget(title);
    cards_=new QVBoxLayout; cards_->setSpacing(6); root->addLayout(cards_);
    more_=new QPushButton(this); more_->setObjectName("discoveryMoreButton"); more_->setFlat(true); root->addWidget(more_);
    manual_=new QPushButton(tr("Informar endereço manualmente"),this); manual_->setObjectName("manualAddressButton"); manual_->setFlat(true); manual_->setAccessibleName(tr("Informar endereço manualmente")); root->addWidget(manual_,0,Qt::AlignLeft);
    connect(more_, &QPushButton::clicked, this, [this] { expanded_ = !expanded_; rebuild(); });
    connect(manual_,&QPushButton::clicked,this,&DeviceDiscoveryPanel::manualAddressRequested);
    relativeTimer_=new QTimer(this); relativeTimer_->setInterval(30000); connect(relativeTimer_,&QTimer::timeout,this,&DeviceDiscoveryPanel::refreshRelativeTimes); relativeTimer_->start();
    connect(model_,&DiscoveredDevicesModel::devicesChanged,this,&DeviceDiscoveryPanel::rebuild); rebuild();
}
void DeviceDiscoveryPanel::rebuild() {
    if (model_->count() <= 4) expanded_ = false;
    while(auto* item=cards_->takeAt(0)){ delete item->widget(); delete item; }
    const auto devices = expanded_ ? model_->devices() : model_->visibleDevices();
    for(const auto& device:devices) { auto* card=new DeviceCard(this); card->setConnectionInitiationAllowed(connectionInitiationAllowed_); card->setDevice(device);
        connect(card,&DeviceCard::connectRequested,this,&DeviceDiscoveryPanel::connectRequested); connect(card,&DeviceCard::pairRequested,this,&DeviceDiscoveryPanel::pairRequested);
        connect(card,&DeviceCard::sendFileRequested,this,&DeviceDiscoveryPanel::sendFileRequested); connect(card,&DeviceCard::detailsRequested,this,&DeviceDiscoveryPanel::detailsRequested); connect(card,&DeviceCard::permissionsRequested,this,&DeviceDiscoveryPanel::permissionsRequested);
        connect(card,&DeviceCard::renameRequested,this,&DeviceDiscoveryPanel::renameRequested); connect(card,&DeviceCard::filesDropped,this,&DeviceDiscoveryPanel::filesDropped); cards_->addWidget(card); }
    const int hidden=model_->hiddenCount();
    more_->setText(expanded_ ? tr("Mostrar menos") : tr("Ver mais (%1)").arg(hidden));
    more_->setVisible(hidden>0 || (expanded_ && model_->count()>4));
    setVisible(model_->count()>0);
}
void DeviceDiscoveryPanel::refreshRelativeTimes(){const auto now=QDateTime::currentDateTimeUtc();for(auto* card:findChildren<DeviceCard*>(QString(),Qt::FindDirectChildrenOnly))card->setNow(now);}
void DeviceDiscoveryPanel::setConnectionInitiationAllowed(bool allowed){if(connectionInitiationAllowed_==allowed)return;connectionInitiationAllowed_=allowed;rebuild();}
void DeviceDiscoveryPanel::setTransferProgress(const QUuid& id,const QString& name,quint64 done,quint64 total){for(auto* card:findChildren<DeviceCard*>(QString(),Qt::FindDirectChildrenOnly))card->setTransferProgress(id,name,done,total);}
void DeviceDiscoveryPanel::finishTransfer(const QUuid& id,bool success,const QString& error){for(auto* card:findChildren<DeviceCard*>(QString(),Qt::FindDirectChildrenOnly))card->finishTransfer(id,success,error);}
