#include "NetworkRecoveryPolicy.h"
#include <gtest/gtest.h>
#include <QPair>
#include <QStringList>
#include <QVector>

namespace {
struct Harness {
    qint64 now = 0;
    QVector<QPair<quint64, int>> timers;
    QStringList order;
    int pauses = 0;
    int resumes = 0;
    int budgetResets = 0;
    NetworkRecoveryPolicy policy{
        [this]{ return now; },
        [this](int delay, quint64 generation){ timers.append({generation, delay}); },
        [this]{ timers.clear(); },
        [this]{ order << "refresh"; },
        [this]{ order << "reconnect"; },
        [this]{ order << "notice"; },
        [this]{ ++pauses; }, [this]{ ++resumes; }, [this]{ ++budgetResets; }
    };
    void fireLast() { const auto t=timers.takeLast(); policy.timerFired(t.first); }
};
NetworkRecoveryPolicy::Context client() {
    NetworkRecoveryPolicy::Context c; c.role=NetworkRecoveryPolicy::Role::Client;
    c.serviceOwned=true; c.userIntendedStarted=true; return c;
}
}

TEST(NetworkRecoveryPolicyTests, ResumeStormCoalescesAndOrdersDiscoveryBeforeReconnect)
{
    Harness h; h.policy.setContext(client());
    h.policy.suspended(); h.policy.resumed(); h.policy.resumed();
    ASSERT_EQ(h.timers.size(), 1); EXPECT_EQ(h.pauses, 1);
    h.fireLast(); EXPECT_EQ(h.order, (QStringList{"refresh", "notice"}));
    ASSERT_EQ(h.timers.size(), 1); h.fireLast();
    EXPECT_EQ(h.order, (QStringList{"refresh", "notice", "reconnect"}));
    EXPECT_EQ(h.resumes, 1); EXPECT_EQ(h.budgetResets, 1);
}

TEST(NetworkRecoveryPolicyTests, IpChangeTriggersButIdenticalPrivateSnapshotDoesNot)
{
    Harness h; h.policy.setContext(client());
    h.policy.networkSnapshotChanged("if=7;up;v4-private");
    EXPECT_TRUE(h.timers.isEmpty()); // first observation is baseline, not recovery
    h.policy.networkSnapshotChanged("if=7;up;v4-private"); EXPECT_TRUE(h.timers.isEmpty());
    h.policy.networkSnapshotChanged("if=8;up;v4-private"); ASSERT_EQ(h.timers.size(), 1);
}

TEST(NetworkRecoveryPolicyTests, ServerOnlyReannouncesAndConnectedClientIsNotDisrupted)
{
    Harness server; auto s=client(); s.role=NetworkRecoveryPolicy::Role::Server; server.policy.setContext(s);
    server.policy.networkSnapshotChanged("a"); server.policy.networkSnapshotChanged("b"); server.fireLast(); server.fireLast();
    EXPECT_EQ(server.order, (QStringList{"refresh", "notice"}));

    Harness connected; auto c=client(); c.stablyConnected=true; connected.policy.setContext(c);
    connected.policy.networkSnapshotChanged("a"); connected.policy.networkSnapshotChanged("b"); connected.fireLast(); connected.fireLast();
    EXPECT_EQ(connected.order, (QStringList{"refresh", "notice"}));
}

TEST(NetworkRecoveryPolicyTests, DesktopUserStopAndModeChangeCancelStaleCallbacks)
{
    Harness h; auto c=client(); c.serviceOwned=false; h.policy.setContext(c);
    h.policy.networkSnapshotChanged("a"); h.policy.networkSnapshotChanged("b"); auto stale=h.timers.last().first;
    c.userIntendedStarted=false; h.policy.setContext(c); h.policy.timerFired(stale);
    EXPECT_TRUE(h.order.isEmpty());
}

TEST(NetworkRecoveryPolicyTests, TransferIsUnaffectedAndUuidEndpointOwnershipStaysExternal)
{
    Harness h; auto c=client(); c.transferActive=true; h.policy.setContext(c);
    h.policy.networkSnapshotChanged("old-ip"); h.policy.networkSnapshotChanged("new-ip"); h.fireLast(); h.fireLast();
    EXPECT_EQ(h.order, (QStringList{"refresh", "notice", "reconnect"}));
}

TEST(NetworkRecoveryPolicyTests, OfflineAndStoppedEventsDoNotClaimRecovery)
{
    Harness h; auto c=client(); h.policy.setContext(c);
    h.policy.networkSnapshotChanged("online:a");
    h.policy.networkSnapshotChanged("offline");
    EXPECT_TRUE(h.timers.isEmpty());
    c.userIntendedStarted=false; h.policy.setContext(c);
    h.policy.networkSnapshotChanged("online:b");
    EXPECT_TRUE(h.timers.isEmpty());
    EXPECT_TRUE(h.order.isEmpty());
}

TEST(NetworkRecoveryPolicyTests, LongSuspendStartsFreshBudgetAndStaleGenerationIsDiscarded)
{
    Harness h; h.policy.setContext(client()); h.policy.suspended(); h.now += 8LL*60*60*1000;
    h.policy.resumed(); const auto stale=h.timers.last().first; h.policy.resumed();
    h.policy.timerFired(stale); EXPECT_TRUE(h.order.isEmpty()); h.fireLast();
    EXPECT_EQ(h.budgetResets, 1); EXPECT_EQ(h.order.first(), "refresh");
}
