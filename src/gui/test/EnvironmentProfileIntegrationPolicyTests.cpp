#include "EnvironmentProfileIntegrationPolicy.h"

#include <gtest/gtest.h>

#include <QThread>

TEST(EnvironmentProfileIntegrationPolicyTests, ProcessTransitionAndExpectedStartedBothKeepBusy)
{
    EnvironmentProfileIntegrationPolicy policy;
    EXPECT_FALSE(policy.busy(false, false));

    EXPECT_TRUE(policy.beginProcessTransition());
    EXPECT_TRUE(policy.busy(false, false));
    EXPECT_TRUE(policy.completeProcessTransition());
    EXPECT_FALSE(policy.busy(false, false));
    EXPECT_TRUE(policy.busy(true, false));
    EXPECT_TRUE(policy.busy(false, true));
}

TEST(EnvironmentProfileIntegrationPolicyTests, ProcessTransitionCanOnlyBeChangedOnOwnerThread)
{
    EnvironmentProfileIntegrationPolicy policy;
    bool changed = true;
    QThread worker;
    QObject object;
    object.moveToThread(&worker);
    QObject::connect(&worker, &QThread::started, &object, [&] {
        changed = policy.beginProcessTransition();
        worker.quit();
    });
    worker.start();
    worker.wait();

    EXPECT_FALSE(changed);
    EXPECT_FALSE(policy.processTransitionBusy());
}

TEST(EnvironmentProfileIntegrationPolicyTests, SameUuidTransfersAreReferenceCounted)
{
    EnvironmentProfileIntegrationPolicy policy;
    const QUuid uuid(QStringLiteral("{11111111-1111-1111-1111-111111111111}"));

    EXPECT_TRUE(policy.transferStarted(uuid));
    EXPECT_TRUE(policy.transferStarted(uuid));
    EXPECT_EQ(policy.transferCount(uuid), 2);
    EXPECT_TRUE(policy.busy(false, false));

    EXPECT_TRUE(policy.transferFinished(uuid));
    EXPECT_EQ(policy.transferCount(uuid), 1);
    EXPECT_TRUE(policy.busy(false, false));

    EXPECT_TRUE(policy.transferFinished(uuid));
    EXPECT_EQ(policy.transferCount(uuid), 0);
    EXPECT_FALSE(policy.busy(false, false));
    EXPECT_FALSE(policy.transferFinished(uuid));
    EXPECT_EQ(policy.transferCount(uuid), 0);
}

TEST(EnvironmentProfileIntegrationPolicyTests, ManagedDenialStopsBeforeGlobalGate)
{
    int profileCalls = 0;
    int globalCalls = 0;
    const bool allowed = EnvironmentProfileIntegrationPolicy::deviceAllows(
        DevicePermissions::SendFiles,
        [&] { ++profileCalls; return false; },
        [&] { ++globalCalls; return true; });
    EXPECT_FALSE(allowed);
    EXPECT_EQ(profileCalls, 1);
    EXPECT_EQ(globalCalls, 0);
}

TEST(EnvironmentProfileIntegrationPolicyTests, ManagedAllowThenGlobalDenyPreservesOrder)
{
    QString order;
    const bool allowed = EnvironmentProfileIntegrationPolicy::deviceAllows(
        DevicePermissions::ShareClipboard,
        [&] { order += QLatin1Char('p'); return true; },
        [&] { order += QLatin1Char('g'); return false; });
    EXPECT_FALSE(allowed);
    EXPECT_EQ(order, QStringLiteral("pg"));
}

TEST(EnvironmentProfileIntegrationPolicyTests, OpenSafeFilesBypassesProfileAndUsesGlobalGate)
{
    int profileCalls = 0;
    int globalCalls = 0;
    const bool allowed = EnvironmentProfileIntegrationPolicy::deviceAllows(
        DevicePermissions::OpenSafeFiles,
        [&] { ++profileCalls; return false; },
        [&] { ++globalCalls; return true; });
    EXPECT_TRUE(allowed);
    EXPECT_EQ(profileCalls, 0);
    EXPECT_EQ(globalCalls, 1);
}

TEST(EnvironmentProfileIntegrationPolicyTests, UnknownNoneAndCompositePermissionsFailClosedWithoutCallbacks)
{
    for (const auto permission : {
             DevicePermissions::None,
             static_cast<DevicePermissions::Permission>(1u << 12),
             DevicePermissions::SendFiles | DevicePermissions::ReceiveFiles}) {
        int profileCalls = 0;
        int globalCalls = 0;
        EXPECT_FALSE(EnvironmentProfileIntegrationPolicy::deviceAllows(
            permission,
            [&] { ++profileCalls; return true; },
            [&] { ++globalCalls; return true; }));
        EXPECT_EQ(profileCalls, 0);
        EXPECT_EQ(globalCalls, 0);
    }
}
