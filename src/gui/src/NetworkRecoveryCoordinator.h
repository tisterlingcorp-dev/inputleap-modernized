#pragma once

#include "NetworkRecoveryPolicy.h"
#include <QAbstractNativeEventFilter>
#include <QObject>
#include <functional>
#include <memory>

class QTimer;
class NetworkRecoveryCoordinator final : public QObject, public QAbstractNativeEventFilter
{
    Q_OBJECT
public:
    using ContextProvider=std::function<NetworkRecoveryPolicy::Context()>;
    using Action=std::function<void()>;
    NetworkRecoveryCoordinator(ContextProvider, Action refresh, Action reconnect,
                               Action notice, Action pauseReconnect,
                               Action resumeReconnect, Action resetBudget,
                               QObject* parent=nullptr);
    ~NetworkRecoveryCoordinator() override;
    bool nativeEventFilter(const QByteArray&, void* message, qintptr* result) override;
    void observeNetworkNow();
    void suspendForTest();
    void resumeForTest();
private:
    QString privacySafeSnapshot() const;
    void syncContext();
    ContextProvider contextProvider_;
    QTimer* timer_=nullptr;
    quint64 timerGeneration_=0;
    std::unique_ptr<NetworkRecoveryPolicy> policy_;
#ifdef Q_OS_WIN
    void* addressChangeHandle_=nullptr;
    void* ipHelperModule_=nullptr;
#endif
};
