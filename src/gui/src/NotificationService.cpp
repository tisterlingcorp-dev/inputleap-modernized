#include "NotificationService.h"

#include <QDateTime>

#include <limits>

NotificationService::NotificationService(Clock clock, QObject* parent)
    : QObject(parent),
      clock_(std::move(clock))
{
    if (!clock_)
        clock_ = [] { return QDateTime::currentMSecsSinceEpoch(); };
    qRegisterMetaType<NotificationService::Event>();
}

bool NotificationService::publish(const QString& key, const QString& title,
                                  const QString& message, Severity severity,
                                  qint64 rateLimitMs)
{
    if (key.isEmpty() || title.isEmpty() || message.isEmpty() || rateLimitMs < 0)
        return false;
    State& state = states_[key];
    const qint64 now = clock_();
    if (state.lastRaisedMs != std::numeric_limits<qint64>::min() &&
        now >= state.lastRaisedMs && now - state.lastRaisedMs < rateLimitMs) {
        ++state.suppressedCount;
        return false;
    }
    Event event{key, title, message, severity, state.suppressedCount};
    state.lastRaisedMs = now;
    state.suppressedCount = 0;
    emit notificationRaised(event);
    return true;
}

void NotificationService::reset(const QString& key)
{
    states_.remove(key);
}
