/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2014-2016 Symless Ltd.
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ZeroconfBrowser.h"

#include <QtCore/QSocketNotifier>
#include <QtCore/QDateTime>
#include <QtCore/QTimer>
#include <QtCore/QtEndian>
#include <QtNetwork/QHostInfo>
#include <QtNetwork/QHostAddress>
#include <algorithm>

struct ZeroconfBrowser::Operation {
    ZeroconfBrowser* owner = nullptr;
    DNSServiceRef ref = nullptr;
    std::unique_ptr<QSocketNotifier> notifier;
    QString key;
    QString serviceName;
    QByteArray wireTxt;
    quint16 port = 0;
    quint64 token = 0;
    bool cancelled = false;
    ~Operation() { notifier.reset(); if (ref) DNSServiceRefDeallocate(ref); }
};

ZeroconfBrowser::ZeroconfBrowser(QObject* parent) :
    QObject(parent),
    m_DnsServiceRef(nullptr),
    discoveryCache_([] { return QDateTime::currentMSecsSinceEpoch(); }, 15000)
{
    expiryTimer_ = new QTimer(this);
    expiryTimer_->setInterval(1000);
    connect(expiryTimer_, &QTimer::timeout, this, &ZeroconfBrowser::expireAdvertisements);
    expiryTimer_->start();
}

ZeroconfBrowser::~ZeroconfBrowser()
{
    if (expiryTimer_) expiryTimer_->stop();
    socket_.reset();
    for (auto& op : operations_) { op->cancelled = true; op->notifier.reset(); }
    operations_.clear();
    if (m_DnsServiceRef) {
        DNSServiceRefDeallocate(m_DnsServiceRef);
        m_DnsServiceRef = nullptr;
    }
}

ZeroconfDiscoveryEvent ZeroconfBrowser::observeAdvertisement(const ZeroconfMetadata& metadata,
    const QString& address, quint32 interfaceIndex)
{
    const auto event = discoveryCache_.observe(metadata, address, interfaceIndex);
    const auto devices = discoveryCache_.devices();
    const auto found = std::find_if(devices.cbegin(), devices.cend(), [&](const auto& item) { return item.uuid == metadata.uuid; });
    if (found != devices.cend()) {
        if (event == ZeroconfDiscoveryEvent::Found) Q_EMIT advertisementFound(*found);
        else if (event == ZeroconfDiscoveryEvent::Updated) Q_EMIT advertisementUpdated(*found);
    }
    return event;
}

void ZeroconfBrowser::removeAdvertisement(const QUuid& uuid, quint32 interfaceIndex)
{
    if (const auto lost = discoveryCache_.remove(uuid, interfaceIndex)) Q_EMIT advertisementLost(*lost);
}

void ZeroconfBrowser::removeAdvertisementAddress(const QUuid& uuid, const QString& address, quint32 interfaceIndex)
{
    if (const auto lost = discoveryCache_.removeAddress(uuid, address, interfaceIndex)) Q_EMIT advertisementLost(*lost);
}

void ZeroconfBrowser::expireAdvertisements()
{
    for (const auto& lost : discoveryCache_.expire()) Q_EMIT advertisementLost(lost);
}

void ZeroconfBrowser::browseForType(const QString& type)
{
    m_BrowsingType = type;
    DNSServiceErrorType err = DNSServiceBrowse(&m_DnsServiceRef, 0, 0,
        type.toUtf8().constData(), nullptr, browseReply, this);

    if (err != kDNSServiceErr_NoError) {
        Q_EMIT error(err);
    }
    else {
        int sockFD = DNSServiceRefSockFD(m_DnsServiceRef);
        if (sockFD == -1) {
            Q_EMIT error(kDNSServiceErr_Invalid);
        }
        else {
            socket_ = std::make_unique<QSocketNotifier>(sockFD, QSocketNotifier::Read, this);
            connect(socket_.get(), &QSocketNotifier::activated, this, &ZeroconfBrowser::socketReadyRead);
        }
    }
}

void ZeroconfBrowser::socketReadyRead()
{
    DNSServiceErrorType err = DNSServiceProcessResult(m_DnsServiceRef);
    if (err != kDNSServiceErr_NoError) {
        Q_EMIT error(err);
    }
}

void ZeroconfBrowser::browseReply(DNSServiceRef, DNSServiceFlags flags,
            quint32 interfaceIndex, DNSServiceErrorType errorCode, const char* serviceName,
            const char* regType, const char* replyDomain, void* context)
{
    auto* browser = static_cast<ZeroconfBrowser*>(context);
    if (errorCode != kDNSServiceErr_NoError) { Q_EMIT browser->error(errorCode); return; }
    ZeroconfRecord record(serviceName, regType, replyDomain);
    const QString key = instanceKey(record.serviceName, record.registeredType, record.replyDomain, interfaceIndex);
    if (flags & kDNSServiceFlagsAdd) {
        browser->instanceRecords_.insert(key, record);
        browser->startResolve(record.serviceName, record.registeredType, record.replyDomain, interfaceIndex);
    } else {
        browser->instanceRecords_.remove(key);
        browser->cancelOperation(key);
        const auto uuid = browser->coordinator_.cancel(key);
        if (uuid) browser->removeAdvertisement(*uuid, interfaceIndex);
    }
    browser->m_Records.clear();
    for (const auto& item : browser->instanceRecords_) if (!browser->m_Records.contains(item)) browser->m_Records.append(item);
    if (!(flags & kDNSServiceFlagsMoreComing)) Q_EMIT browser->currentRecordsChanged(browser->m_Records);
}

QString ZeroconfBrowser::instanceKey(const QString& name,const QString& type,const QString& domain,quint32 interfaceIndex)
{ return name + QChar::Null + type + QChar::Null + domain + QChar::Null + QString::number(interfaceIndex); }

void ZeroconfBrowser::startResolve(const QString& name,const QString& type,const QString& domain,quint32 interfaceIndex)
{
    const QString key=instanceKey(name,type,domain,interfaceIndex);
    cancelOperation(key);
    auto op=std::make_unique<Operation>(); op->owner=this; op->serviceName=name; op->key=key;
    op->token=coordinator_.begin(key,name,interfaceIndex);
    const auto err=DNSServiceResolve(&op->ref,0,interfaceIndex,name.toUtf8().constData(),type.toUtf8().constData(),domain.toUtf8().constData(),resolveReply,op.get());
    if(err!=kDNSServiceErr_NoError){Q_EMIT error(err);return;} const int fd=DNSServiceRefSockFD(op->ref); if(fd<0){Q_EMIT error(kDNSServiceErr_Invalid);return;}
    auto* raw=op.get(); op->notifier=std::make_unique<QSocketNotifier>(fd,QSocketNotifier::Read,this); connect(op->notifier.get(),&QSocketNotifier::activated,this,[this,raw]{processOperation(raw);}); operations_.push_back(std::move(op));
}

void ZeroconfBrowser::processOperation(Operation* op)
{
    if (!op || op->cancelled || !op->ref) return;
    const auto err=DNSServiceProcessResult(op->ref);
    if(err!=kDNSServiceErr_NoError) { Q_EMIT error(err); removeOperation(op); }
}
void ZeroconfBrowser::removeOperation(Operation* op)
{
    if (!op) return;
    op->cancelled=true;
    if (op->notifier) op->notifier->setEnabled(false);
    const QString key=op->key; const quint64 token=op->token;
    QMetaObject::invokeMethod(this,[this,key,token]{
        operations_.erase(std::remove_if(operations_.begin(),operations_.end(),[&](const auto& p){return p->key==key && p->token==token;}),operations_.end());
    },Qt::QueuedConnection);
}

void ZeroconfBrowser::cancelOperation(const QString& key)
{
    for (auto& op : operations_) if (op->key==key) removeOperation(op.get());
}

void ZeroconfBrowser::resolveReply(DNSServiceRef,DNSServiceFlags,quint32 interfaceIndex,DNSServiceErrorType errorCode,const char*,const char* hosttarget,quint16 port,quint16 txtLen,const unsigned char* txtRecord,void* context)
{
    auto* op=static_cast<Operation*>(context); auto* browser=op->owner;
    if(errorCode!=kDNSServiceErr_NoError){Q_EMIT browser->error(errorCode);browser->removeOperation(op);return;}
    const QByteArray wire(reinterpret_cast<const char*>(txtRecord),txtLen);
    const quint16 hostPort=qFromBigEndian(port);
    if (!browser->coordinator_.setResolved(op->key,op->token,wire,hostPort)) { browser->removeOperation(op); return; }
    const QString key=op->key, host=QString::fromUtf8(hosttarget); const quint64 token=op->token;
    QMetaObject::invokeMethod(browser,[browser,key,token,host,interfaceIndex]{browser->beginAddressLookup(key,token,host,interfaceIndex);},Qt::QueuedConnection);
}

void ZeroconfBrowser::beginAddressLookup(const QString& key,quint64 token,const QString& host,quint32 interfaceIndex)
{
    auto it=std::find_if(operations_.begin(),operations_.end(),[&](const auto& p){return p->key==key && p->token==token && !p->cancelled;});
    if(it==operations_.end() || !coordinator_.active(key,token)) return;
    Operation* op=it->get();
    op->notifier.reset();
    if(op->ref) DNSServiceRefDeallocate(op->ref);
    op->ref=nullptr;
    const QString serviceName=op->serviceName;
    QHostInfo::lookupHost(host, this, [this,key,token,serviceName,interfaceIndex](const QHostInfo& info) {
        auto it=std::find_if(operations_.begin(),operations_.end(),[&](const auto& p){return p->key==key && p->token==token && !p->cancelled;});
        if(it==operations_.end() || !coordinator_.active(key,token)) return;
        if(info.error()!=QHostInfo::NoError) {
            Q_EMIT error(kDNSServiceErr_Unknown);
            removeOperation(it->get());
            return;
        }
        for(const auto& address : info.addresses()) {
            const QString text=address.toString();
            const auto decision=coordinator_.address(key,token,true,text,0);
            using Route=ZeroconfDiscoveryCoordinator::Route;
            if(decision.route==Route::CompatibleAdd) observeAdvertisement(*decision.metadata,text,interfaceIndex);
            else if(decision.route==Route::Legacy) Q_EMIT legacyAdvertisement(serviceName,interfaceIndex);
            else if(decision.route==Route::Incompatible) {
                if(decision.metadata) {
                    instanceUuids_[key]=decision.metadata->uuid;
                    observeAdvertisement(*decision.metadata,text,interfaceIndex);
                }
                Q_EMIT advertisementDiagnostic(ZeroconfParseStatus::Incompatible,decision.detail);
            }
            else if(decision.route==Route::Malformed || decision.route==Route::InvalidAddress)
                Q_EMIT advertisementDiagnostic(ZeroconfParseStatus::Malformed,decision.detail);
        }
        removeOperation(it->get());
    });
}

void ZeroconfBrowser::addressReply(DNSServiceRef,DNSServiceFlags flags,quint32 interfaceIndex,DNSServiceErrorType errorCode,const char*,const struct sockaddr* address,quint32 ttl,void* context)
{
    auto* op=static_cast<Operation*>(context); auto* browser=op->owner;
    if(errorCode!=kDNSServiceErr_NoError){Q_EMIT browser->error(errorCode);browser->removeOperation(op);return;}
    const QString text=address ? QHostAddress(address).toString() : QString();
    const auto decision=browser->coordinator_.address(op->key,op->token,flags&kDNSServiceFlagsAdd,text,ttl);
    using Route=ZeroconfDiscoveryCoordinator::Route;
    if(decision.route==Route::CompatibleAdd) browser->observeAdvertisement(*decision.metadata,text,interfaceIndex);
    else if(decision.route==Route::CompatibleRemove) browser->removeAdvertisementAddress(decision.metadata->uuid,text,interfaceIndex);
    else if(decision.route==Route::Legacy) Q_EMIT browser->legacyAdvertisement(op->serviceName,interfaceIndex);
    else if(decision.route==Route::Incompatible) {
        if (decision.metadata) {
            browser->instanceUuids_[op->key] = decision.metadata->uuid;
            if (flags & kDNSServiceFlagsAdd)
                browser->observeAdvertisement(*decision.metadata, text, interfaceIndex);
            else
                browser->removeAdvertisementAddress(decision.metadata->uuid, text, interfaceIndex);
        }
        Q_EMIT browser->advertisementDiagnostic(ZeroconfParseStatus::Incompatible,decision.detail);
    }
    else if(decision.route==Route::Malformed || decision.route==Route::InvalidAddress) Q_EMIT browser->advertisementDiagnostic(ZeroconfParseStatus::Malformed,decision.detail);
}
