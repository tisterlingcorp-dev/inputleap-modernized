#include "NetworkRecoveryCoordinator.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QNetworkAddressEntry>
#include <QNetworkInformation>
#include <QNetworkInterface>
#include <QTimer>
#include <algorithm>
#ifdef Q_OS_WIN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
namespace {
using AddressCallback=void (CALLBACK*)(void*,void*,int);
using NotifyAddressChange=ULONG (WINAPI*)(USHORT,AddressCallback,void*,unsigned char,HANDLE*);
using CancelAddressChange=ULONG (WINAPI*)(HANDLE);
void CALLBACK unicastAddressChanged(void* context, void*, int)
{
    auto* coordinator=static_cast<NetworkRecoveryCoordinator*>(context);
    QMetaObject::invokeMethod(coordinator,[coordinator]{coordinator->observeNetworkNow();},Qt::QueuedConnection);
}
}
#endif

NetworkRecoveryCoordinator::NetworkRecoveryCoordinator(ContextProvider context, Action refresh,
    Action reconnect, Action notice, Action pauseReconnect, Action resumeReconnect,
    Action resetBudget, QObject* parent)
    : QObject(parent), contextProvider_(std::move(context))
{
    timer_=new QTimer(this); timer_->setSingleShot(true);
    policy_=std::make_unique<NetworkRecoveryPolicy>(
        []{return QDateTime::currentMSecsSinceEpoch();},
        [this](int ms,quint64 gen){timerGeneration_=gen;timer_->start(ms);},
        [this]{timer_->stop();}, std::move(refresh), std::move(reconnect), std::move(notice),
        std::move(pauseReconnect), std::move(resumeReconnect), std::move(resetBudget));
    connect(timer_,&QTimer::timeout,this,[this]{syncContext();policy_->timerFired(timerGeneration_);});
    if (qApp) qApp->installNativeEventFilter(this);
    if (QNetworkInformation::loadDefaultBackend()) {
        connect(QNetworkInformation::instance(),&QNetworkInformation::reachabilityChanged,
                this,[this]{observeNetworkNow();});
    }
#ifdef Q_OS_WIN
    const HMODULE module=LoadLibraryW(L"iphlpapi.dll");
    if(module) {
        ipHelperModule_=module;
        const auto notify=reinterpret_cast<NotifyAddressChange>(GetProcAddress(module,"NotifyUnicastIpAddressChange"));
        HANDLE handle=nullptr;
        if(notify && notify(0,unicastAddressChanged,this,FALSE,&handle)==NO_ERROR) addressChangeHandle_=handle;
    }
#endif
    syncContext(); observeNetworkNow();
}

NetworkRecoveryCoordinator::~NetworkRecoveryCoordinator()
{
#ifdef Q_OS_WIN
    if(addressChangeHandle_ && ipHelperModule_) {
        const auto cancel=reinterpret_cast<CancelAddressChange>(GetProcAddress(static_cast<HMODULE>(ipHelperModule_),"CancelMibChangeNotify2"));
        if(cancel) cancel(static_cast<HANDLE>(addressChangeHandle_));
        addressChangeHandle_=nullptr;
    }
    if(ipHelperModule_) { FreeLibrary(static_cast<HMODULE>(ipHelperModule_)); ipHelperModule_=nullptr; }
#endif
    if (qApp) qApp->removeNativeEventFilter(this);
    timer_->stop();
}

void NetworkRecoveryCoordinator::syncContext(){policy_->setContext(contextProvider_());}
void NetworkRecoveryCoordinator::suspendForTest(){syncContext();policy_->suspended();}
void NetworkRecoveryCoordinator::resumeForTest(){syncContext();policy_->resumed();}
void NetworkRecoveryCoordinator::observeNetworkNow(){syncContext();policy_->networkSnapshotChanged(privacySafeSnapshot());}

QString NetworkRecoveryCoordinator::privacySafeSnapshot() const
{
    QStringList tokens;
    for(const auto& iface:QNetworkInterface::allInterfaces()) {
        if(!(iface.flags()&QNetworkInterface::IsUp)||!(iface.flags()&QNetworkInterface::IsRunning)||
           (iface.flags()&QNetworkInterface::IsLoopBack)) continue;
        const QString prefix=QStringLiteral("%1:%2:").arg(iface.index()).arg(int(iface.type()));
        for(const auto& e:iface.addressEntries()) {
            const auto a=e.ip(); if(a.isLoopback()||a.isMulticast()||a.isNull())continue;
            // Raw addresses exist only transiently inside this one-way in-memory digest.
            tokens.append(prefix+(a.protocol()==QAbstractSocket::IPv4Protocol?QStringLiteral("v4:"):QStringLiteral("v6:"))+
                QString::fromLatin1(QCryptographicHash::hash(a.toString().toUtf8(),QCryptographicHash::Sha256).toHex().left(16)));
        }
    }
    if(tokens.isEmpty()) return QStringLiteral("offline");
    tokens.sort(Qt::CaseSensitive);
    return QStringLiteral("online:")+QString::fromLatin1(QCryptographicHash::hash(tokens.join(';').toUtf8(),QCryptographicHash::Sha256).toHex());
}

bool NetworkRecoveryCoordinator::nativeEventFilter(const QByteArray&,void* raw,qintptr*)
{
#ifdef Q_OS_WIN
    const MSG* msg=static_cast<const MSG*>(raw);
    if(msg->message==WM_POWERBROADCAST) {
        if(msg->wParam==PBT_APMSUSPEND) suspendForTest();
        else if(msg->wParam==PBT_APMRESUMEAUTOMATIC) resumeForTest();
    } else if(msg->message==WM_DEVICECHANGE) {
        QTimer::singleShot(0,this,&NetworkRecoveryCoordinator::observeNetworkNow);
    }
#else
    Q_UNUSED(raw);
#endif
    return false;
}
