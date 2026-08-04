#pragma once

#include <algorithm>
#include <optional>

class ZeroconfRegistrationState
{
public:
    enum class State { Idle, Pending, Registered };
    bool begin() { if (state_ != State::Idle) return false; state_ = State::Pending; return true; }
    bool confirm() { if (state_ != State::Pending) return false; state_ = State::Registered; return true; }
    void fail() { state_ = State::Idle; }
    State state() const { return state_; }
    bool isRegistered() const { return state_ == State::Registered; }
private:
    State state_ = State::Idle;
};

class ZeroconfRetryPolicy
{
public:
    ZeroconfRetryPolicy(int initialMs = 2000, int maximumMs = 30000) : initial_(initialMs), maximum_(maximumMs), next_(initialMs) {}
    std::optional<int> fail() { if (pending_) return {}; pending_ = true; const int delay = next_; next_ = (std::min)(maximum_, next_ * 2); return delay; }
    void retryStarted() { pending_ = false; }
    void confirm() { pending_ = false; next_ = initial_; }
    bool pending() const { return pending_; }
    int nextDelayMs() const { return next_; }
private:
    int initial_;
    int maximum_;
    int next_;
    bool pending_ = false;
};
