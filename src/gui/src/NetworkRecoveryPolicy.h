#pragma once

#include <QString>
#include <functional>

class NetworkRecoveryPolicy
{
public:
    enum class Role { Client, Server };
    struct Context {
        Role role = Role::Client;
        bool serviceOwned = false;
        bool userIntendedStarted = false;
        bool stablyConnected = false;
        bool transferActive = false;
        bool operator==(const Context& o) const {
            return role==o.role && serviceOwned==o.serviceOwned &&
                   userIntendedStarted==o.userIntendedStarted &&
                   stablyConnected==o.stablyConnected && transferActive==o.transferActive;
        }
    };
    using Clock=std::function<qint64()>;
    using Schedule=std::function<void(int,quint64)>;
    using Action=std::function<void()>;
    static constexpr int DebounceMs=1500;
    static constexpr int DiscoverySettleMs=1500;

    NetworkRecoveryPolicy(Clock, Schedule, Action cancel, Action refresh,
                          Action reconnect, Action notice, Action pauseReconnect,
                          Action resumeReconnect, Action resetReconnectBudget);
    void setContext(const Context&);
    void networkSnapshotChanged(const QString& privacySafeFingerprint);
    void suspended();
    void resumed();
    void timerFired(quint64 generation);
    quint64 generation() const { return generation_; }

private:
    enum class Stage { Idle, Debounce, Settle };
    void queueRecovery();
    Clock clock_; Schedule schedule_; Action cancel_,refresh_,reconnect_,notice_;
    Action pauseReconnect_,resumeReconnect_,resetReconnectBudget_;
    Context context_;
    QString snapshot_;
    quint64 generation_=0;
    qint64 lastActionMs_=-1;
    Stage stage_=Stage::Idle;
    bool suspended_=false;
    bool resumeRecovery_=false;
};
