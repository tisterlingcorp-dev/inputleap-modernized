#include "NetworkRecoveryPolicy.h"
#include <utility>

NetworkRecoveryPolicy::NetworkRecoveryPolicy(Clock clock, Schedule schedule, Action cancel,
    Action refresh, Action reconnect, Action notice, Action pauseReconnect,
    Action resumeReconnect, Action resetReconnectBudget)
    : clock_(std::move(clock)), schedule_(std::move(schedule)), cancel_(std::move(cancel)),
      refresh_(std::move(refresh)), reconnect_(std::move(reconnect)), notice_(std::move(notice)),
      pauseReconnect_(std::move(pauseReconnect)), resumeReconnect_(std::move(resumeReconnect)),
      resetReconnectBudget_(std::move(resetReconnectBudget)) {}

void NetworkRecoveryPolicy::setContext(const Context& context)
{
    if (context_ == context) return;
    context_=context;
    if (!context_.userIntendedStarted) {
        cancel_(); ++generation_; stage_=Stage::Idle; resumeRecovery_=false;
    }
}

void NetworkRecoveryPolicy::networkSnapshotChanged(const QString& fingerprint)
{
    if (fingerprint.isEmpty()) return;
    if (snapshot_.isEmpty()) { snapshot_=fingerprint; return; }
    if (snapshot_==fingerprint) return;
    snapshot_=fingerprint;
    if (fingerprint==QStringLiteral("offline")) return;
    if (!suspended_) queueRecovery();
}

void NetworkRecoveryPolicy::suspended()
{
    if (suspended_) return;
    suspended_=true; cancel_(); ++generation_; stage_=Stage::Idle;
    pauseReconnect_();
}

void NetworkRecoveryPolicy::resumed()
{
    if (!suspended_ && resumeRecovery_) { queueRecovery(); return; }
    suspended_=false; resumeRecovery_=true; queueRecovery();
}

void NetworkRecoveryPolicy::queueRecovery()
{
    if(!context_.userIntendedStarted) return;
    cancel_();
    const quint64 token=++generation_;
    stage_=Stage::Debounce;
    schedule_(DebounceMs,token);
}

void NetworkRecoveryPolicy::timerFired(quint64 token)
{
    if (token!=generation_) return;
    if (stage_==Stage::Debounce) {
        // Minimum interval is folded into the single coalesced timer; no polling.
        const qint64 elapsed=lastActionMs_<0 ? DebounceMs : clock_()-lastActionMs_;
        if (elapsed<DebounceMs) { schedule_(int(DebounceMs-elapsed),token); return; }
        if (resumeRecovery_) {
            resumeRecovery_=false; resumeReconnect_(); resetReconnectBudget_();
        }
        refresh_(); notice_(); lastActionMs_=clock_();
        stage_=Stage::Settle; schedule_(DiscoverySettleMs,token); return;
    }
    if (stage_==Stage::Settle) {
        stage_=Stage::Idle;
        if (context_.role==Role::Client && context_.serviceOwned &&
            context_.userIntendedStarted && !context_.stablyConnected) reconnect_();
    }
}
