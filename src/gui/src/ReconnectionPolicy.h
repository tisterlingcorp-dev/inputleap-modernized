#pragma once

#include <QHash>
#include <QString>
#include <QUuid>
#include <functional>
#include <optional>

class ReconnectionPolicy
{
public:
    enum class Failure { Network, Refused, Timeout, DnsStale, Unknown,
                         Authentication, Certificate, Pairing, Incompatible, Policy, UserStop };
    enum class Notice { FirstFailure, DelayTierChanged, Terminal, Exhausted, Recovery };

    static constexpr int MaxAttempts = 10;
    static constexpr qint64 BudgetMs = 5 * 60 * 1000;
    static constexpr qint64 StableWindowMs = 10 * 1000;

    using Clock = std::function<qint64()>;
    using Jitter = std::function<int(int, int)>;
    using Schedule = std::function<void(int, quint64)>;
    using CancelSchedule = std::function<void()>;
    using EndpointResolver = std::function<std::optional<QString>(const QUuid&)>;
    using Attempt = std::function<bool(const QString&)>;
    using Notify = std::function<void(Notice)>;

    ReconnectionPolicy(Clock clock, Jitter jitter, Schedule schedule, CancelSchedule cancelSchedule,
                       EndpointResolver resolver, Attempt attempt, Notify notify);

    void beginUuid(const QUuid& uuid);
    void beginManual(const QString& exactEndpoint);
    bool failed(Failure failure);
    void timerFired(quint64 generation);
    void attemptFinished();
    void connected();
    bool confirmStable();
    void pause();
    void resume(bool resetBudget = true);
    void resetBudget();
    void cancel();

    bool active() const { return active_; }
    bool attemptInFlight() const { return attemptInFlight_; }
    int consecutiveAttempts() const { return attempts_; }
    QUuid targetUuid() const { return targetUuid_; }
    quint64 generation() const { return generation_; }

private:
    bool terminal(Failure failure) const;
    int baseDelay(int attempt) const;
    void exhaust();

    Clock clock_;
    Jitter jitter_;
    Schedule schedule_;
    CancelSchedule cancelSchedule_;
    EndpointResolver resolver_;
    Attempt attempt_;
    Notify notify_;
    QUuid targetUuid_;
    QString manualEndpoint_;
    qint64 startedMs_ = 0;
    qint64 connectedMs_ = -1;
    int attempts_ = 0;
    int lastTier_ = 0;
    quint64 generation_ = 0;
    bool active_ = false;
    bool attemptInFlight_ = false;
    bool timerPending_ = false;
    bool firstFailureNotified_ = false;
    bool paused_ = false;
};
