#include "ReconnectionPolicy.h"
#include <gtest/gtest.h>

namespace {
struct Harness {
    qint64 now = 0;
    QVector<QPair<quint64, int>> timers;
    QVector<QString> attempts;
    QVector<ReconnectionPolicy::Notice> notices;
    QHash<QUuid, QString> endpoints;
    bool attemptStarts = true;
    ReconnectionPolicy policy{
        [this] { return now; },
        [](int delay, int) { return delay; },
        [this](int delay, quint64 generation) { timers.append({generation, delay}); },
        [this] { timers.clear(); },
        [this](const QUuid& uuid) -> std::optional<QString> {
            const auto it = endpoints.constFind(uuid);
            return it == endpoints.cend() ? std::nullopt : std::optional<QString>(*it);
        },
        [this](const QString& endpoint) { attempts.append(endpoint); return attemptStarts; },
        [this](ReconnectionPolicy::Notice notice) { notices.append(notice); }
    };
};
}

TEST(ReconnectionPolicyTests, ExponentialBackoffIsBoundedAndJitterInjected)
{
    Harness h; const QUuid id = QUuid::createUuid(); h.policy.beginUuid(id);
    const int expected[] = {1000, 2000, 4000, 8000, 16000, 30000, 30000};
    for (int delay : expected) {
        ASSERT_TRUE(h.policy.failed(ReconnectionPolicy::Failure::Network));
        ASSERT_FALSE(h.timers.isEmpty()); EXPECT_EQ(h.timers.last().second, delay);
        const auto timer = h.timers.takeLast(); h.policy.timerFired(timer.first);
        h.policy.attemptFinished();
    }
}

TEST(ReconnectionPolicyTests, RetryRefetchesEndpointByUuidAndIgnoresAliasCollision)
{
    Harness h; const QUuid intended = QUuid::createUuid(); const QUuid attacker = QUuid::createUuid();
    h.endpoints[intended] = "192.0.2.10:24800"; h.endpoints[attacker] = "192.0.2.66:24800";
    h.policy.beginUuid(intended); ASSERT_TRUE(h.policy.failed(ReconnectionPolicy::Failure::DnsStale));
    h.endpoints[intended] = "192.0.2.11:24800";
    const auto timer = h.timers.last(); h.policy.timerFired(timer.first);
    ASSERT_EQ(h.attempts.size(), 1); EXPECT_EQ(h.attempts.first(), "192.0.2.11:24800");
}

TEST(ReconnectionPolicyTests, ManualLegacyRetriesOnlyExactHostname)
{
    Harness h; h.policy.beginManual("server.example:24800");
    ASSERT_TRUE(h.policy.failed(ReconnectionPolicy::Failure::Network));
    h.policy.timerFired(h.timers.last().first);
    ASSERT_EQ(h.attempts.size(), 1); EXPECT_EQ(h.attempts.first(), "server.example:24800");
}

TEST(ReconnectionPolicyTests, StopModeChangeAndStaleGenerationCancel)
{
    Harness h; h.policy.beginUuid(QUuid::createUuid()); h.policy.failed(ReconnectionPolicy::Failure::Timeout);
    const quint64 stale = h.timers.last().first; h.policy.cancel(); h.policy.timerFired(stale);
    EXPECT_TRUE(h.attempts.isEmpty()); EXPECT_FALSE(h.policy.active());
}

TEST(ReconnectionPolicyTests, TerminalSecurityFailuresNeverRetry)
{
    for (auto reason : {ReconnectionPolicy::Failure::Authentication, ReconnectionPolicy::Failure::Certificate,
                        ReconnectionPolicy::Failure::Pairing, ReconnectionPolicy::Failure::Incompatible,
                        ReconnectionPolicy::Failure::Policy}) {
        Harness h; h.policy.beginUuid(QUuid::createUuid());
        EXPECT_FALSE(h.policy.failed(reason)); EXPECT_TRUE(h.timers.isEmpty());
        ASSERT_FALSE(h.notices.isEmpty()); EXPECT_EQ(h.notices.last(), ReconnectionPolicy::Notice::Terminal);
    }
}

TEST(ReconnectionPolicyTests, AttemptOverlapIsBlocked)
{
    Harness h; h.policy.beginUuid(QUuid::createUuid()); h.endpoints[h.policy.targetUuid()] = "host:1";
    h.policy.failed(ReconnectionPolicy::Failure::Network); const auto timer = h.timers.last();
    h.policy.timerFired(timer.first); h.policy.timerFired(timer.first);
    EXPECT_EQ(h.attempts.size(), 1);
}

TEST(ReconnectionPolicyTests, MissingPeerConsumesBudgetAndExhausts)
{
    Harness h; h.policy.beginUuid(QUuid::createUuid());
    for (int i = 0; i < 10; ++i) {
        ASSERT_TRUE(h.policy.failed(ReconnectionPolicy::Failure::Network));
        const auto timer = h.timers.takeLast(); h.policy.timerFired(timer.first); h.policy.attemptFinished();
    }
    EXPECT_FALSE(h.policy.failed(ReconnectionPolicy::Failure::Network));
    ASSERT_FALSE(h.notices.isEmpty()); EXPECT_EQ(h.notices.last(), ReconnectionPolicy::Notice::Exhausted);
}

TEST(ReconnectionPolicyTests, StableSuccessResetsBackoffAndAntiSpamNotices)
{
    Harness h; h.policy.beginUuid(QUuid::createUuid());
    h.policy.failed(ReconnectionPolicy::Failure::Network);
    h.policy.attemptFinished(); h.policy.failed(ReconnectionPolicy::Failure::Network);
    EXPECT_EQ(std::count(h.notices.begin(), h.notices.end(), ReconnectionPolicy::Notice::FirstFailure), 1);
    h.policy.connected(); h.now += ReconnectionPolicy::StableWindowMs; EXPECT_TRUE(h.policy.confirmStable());
    EXPECT_EQ(h.policy.consecutiveAttempts(), 0);
    ASSERT_TRUE(h.policy.failed(ReconnectionPolicy::Failure::Network)); EXPECT_EQ(h.timers.last().second, 1000);
    EXPECT_EQ(h.notices.last(), ReconnectionPolicy::Notice::FirstFailure);
}

TEST(ReconnectionPolicyTests, DisconnectBeforeStableSchedulesAgainAndFailedStartIsRetried)
{
    Harness h; const QUuid id=QUuid::createUuid(); h.endpoints[id]="host:24800"; h.policy.beginUuid(id);
    ASSERT_TRUE(h.policy.failed(ReconnectionPolicy::Failure::Network));
    h.policy.connected();
    ASSERT_TRUE(h.policy.failed(ReconnectionPolicy::Failure::Network));
    ASSERT_FALSE(h.timers.isEmpty());
    h.attemptStarts=false; const auto timer=h.timers.takeLast(); h.policy.timerFired(timer.first);
    EXPECT_FALSE(h.timers.isEmpty());
    EXPECT_FALSE(h.policy.attemptInFlight());
}

TEST(ReconnectionPolicyTests, TimeBudgetExhaustsWithoutOverflow)
{
    Harness h; h.policy.beginUuid(QUuid::createUuid()); h.now = ReconnectionPolicy::BudgetMs + 1;
    EXPECT_FALSE(h.policy.failed(ReconnectionPolicy::Failure::Unknown));
    EXPECT_EQ(h.notices.last(), ReconnectionPolicy::Notice::Exhausted);
}

TEST(ReconnectionPolicyTests, SuspendPausesTimersAndResumeResetsElapsedBudgetWithoutLosingTarget)
{
    Harness h; const QUuid id=QUuid::createUuid(); h.endpoints[id]="new-address";
    h.policy.beginUuid(id); h.policy.failed(ReconnectionPolicy::Failure::Network);
    const auto stale=h.timers.last().first; h.policy.pause();
    h.now += 8LL*60*60*1000; h.policy.timerFired(stale);
    EXPECT_TRUE(h.attempts.isEmpty()); EXPECT_EQ(h.policy.targetUuid(), id);
    h.policy.resume(true); EXPECT_TRUE(h.policy.failed(ReconnectionPolicy::Failure::Network));
    h.policy.timerFired(h.timers.last().first);
    EXPECT_EQ(h.attempts.last(), "new-address");
}
