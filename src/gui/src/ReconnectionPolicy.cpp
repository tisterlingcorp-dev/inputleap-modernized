#include "ReconnectionPolicy.h"
#include <algorithm>
#include <utility>

ReconnectionPolicy::ReconnectionPolicy(Clock clock, Jitter jitter, Schedule schedule,
                                       CancelSchedule cancelSchedule, EndpointResolver resolver,
                                       Attempt attempt, Notify notify)
    : clock_(std::move(clock)), jitter_(std::move(jitter)), schedule_(std::move(schedule)),
      cancelSchedule_(std::move(cancelSchedule)), resolver_(std::move(resolver)),
      attempt_(std::move(attempt)), notify_(std::move(notify))
{
}

void ReconnectionPolicy::beginUuid(const QUuid& uuid)
{
    cancel();
    if (uuid.isNull()) return;
    targetUuid_ = uuid;
    startedMs_ = clock_();
    active_ = true;
}

void ReconnectionPolicy::beginManual(const QString& exactEndpoint)
{
    cancel();
    if (exactEndpoint.trimmed().isEmpty()) return;
    manualEndpoint_ = exactEndpoint.trimmed();
    startedMs_ = clock_();
    active_ = true;
}

bool ReconnectionPolicy::terminal(Failure failure) const
{
    switch (failure) {
    case Failure::Authentication: case Failure::Certificate: case Failure::Pairing:
    case Failure::Incompatible: case Failure::Policy: case Failure::UserStop:
        return true;
    default: return false;
    }
}

int ReconnectionPolicy::baseDelay(int attempt) const
{
    const int shift = (std::min)(attempt - 1, 5);
    return (std::min)(1000 * (1 << shift), 30000);
}

bool ReconnectionPolicy::failed(Failure failure)
{
    if (!active_ || paused_) return false;
    if (timerPending_ || attemptInFlight_) return true;
    attemptInFlight_ = false;
    connectedMs_ = -1;
    if (terminal(failure)) {
        cancelSchedule_(); ++generation_; active_ = false;
        notify_(Notice::Terminal);
        return false;
    }
    const int limit = failure == Failure::Unknown ? 3 : MaxAttempts;
    if (attempts_ >= limit || clock_() - startedMs_ > BudgetMs) {
        exhaust();
        return false;
    }
    ++attempts_;
    const int tier = baseDelay(attempts_);
    if (!firstFailureNotified_) {
        firstFailureNotified_ = true;
        notify_(Notice::FirstFailure);
    }
    else if (tier != lastTier_) {
        notify_(Notice::DelayTierChanged);
    }
    lastTier_ = tier;
    const int bounded = (std::clamp)(jitter_(tier, 20), tier * 80 / 100, tier * 120 / 100);
    const quint64 token = ++generation_;
    timerPending_ = true;
    schedule_(bounded, token);
    return true;
}

void ReconnectionPolicy::timerFired(quint64 generation)
{
    if (!active_ || paused_ || generation != generation_ || attemptInFlight_) return;
    timerPending_ = false;
    std::optional<QString> endpoint;
    if (!targetUuid_.isNull()) endpoint = resolver_(targetUuid_);
    else if (!manualEndpoint_.isEmpty()) endpoint = manualEndpoint_;
    if (!endpoint || endpoint->isEmpty()) { failed(Failure::Network); return; }
    attemptInFlight_ = attempt_(*endpoint);
    if (!attemptInFlight_) failed(Failure::Unknown);
}

void ReconnectionPolicy::attemptFinished()
{
    attemptInFlight_ = false;
}

void ReconnectionPolicy::connected()
{
    if (!active_) return;
    attemptInFlight_ = false;
    timerPending_ = false;
    cancelSchedule_();
    ++generation_;
    connectedMs_ = clock_();
}

bool ReconnectionPolicy::confirmStable()
{
    if (!active_ || connectedMs_ < 0 || clock_() - connectedMs_ < StableWindowMs) return false;
    attempts_ = 0;
    lastTier_ = 0;
    firstFailureNotified_ = false;
    connectedMs_ = -1;
    startedMs_ = clock_();
    notify_(Notice::Recovery);
    return true;
}

void ReconnectionPolicy::exhaust()
{
    cancelSchedule_();
    ++generation_;
    active_ = false;
    attemptInFlight_ = false;
    timerPending_ = false;
    notify_(Notice::Exhausted);
}

void ReconnectionPolicy::pause()
{
    if (!active_ || paused_) return;
    cancelSchedule_();
    ++generation_;
    timerPending_ = false;
    attemptInFlight_ = false;
    paused_ = true;
}

void ReconnectionPolicy::resetBudget()
{
    startedMs_ = clock_();
    attempts_ = 0;
    lastTier_ = 0;
    firstFailureNotified_ = false;
}

void ReconnectionPolicy::resume(bool reset)
{
    if (!active_ || !paused_) return;
    paused_ = false;
    if (reset) resetBudget();
}

void ReconnectionPolicy::cancel()
{
    cancelSchedule_();
    ++generation_;
    targetUuid_ = {};
    manualEndpoint_.clear();
    startedMs_ = clock_();
    connectedMs_ = -1;
    attempts_ = 0;
    lastTier_ = 0;
    active_ = false;
    attemptInFlight_ = false;
    timerPending_ = false;
    firstFailureNotified_ = false;
    paused_ = false;
}
