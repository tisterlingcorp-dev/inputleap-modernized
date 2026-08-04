/*
 * InputLeap -- controlled transfer performance tests
 */
#include "../src/TransferPerformance.h"

#include <gtest/gtest.h>
#include <QUuid>

TEST(PerformancePolicyTests, DefaultsAreConservativeAndUnlimited)
{
    const PerformancePolicy policy;
    EXPECT_EQ(policy.maxConcurrent(), 1);
    EXPECT_EQ(policy.bandwidthBytesPerSecond(), 0u);
}

TEST(PerformancePolicyTests, ClampsUntrustedSettingsToSafeBounds)
{
    const PerformancePolicy low(-4, 1);
    EXPECT_EQ(low.maxConcurrent(), 1);
    EXPECT_EQ(low.bandwidthBytesPerSecond(), PerformancePolicy::MinimumBandwidthBytesPerSecond);

    const PerformancePolicy high(99, std::numeric_limits<quint64>::max());
    EXPECT_EQ(high.maxConcurrent(), PerformancePolicy::MaximumConcurrentTransfers);
    EXPECT_EQ(high.bandwidthBytesPerSecond(), PerformancePolicy::MaximumBandwidthBytesPerSecond);

    const PerformancePolicy unlimited(2, 0);
    EXPECT_EQ(unlimited.bandwidthBytesPerSecond(), 0u);
}

TEST(PerformancePolicyTests, AllowsParallelQueueItemsOnlyForDistinctStablePeers)
{
    PerformancePolicy policy(2, 0);
    const QUuid first = QUuid::createUuid();
    const QUuid second = QUuid::createUuid();
    const QSet<QUuid> active{first};
    EXPECT_FALSE(policy.canStartQueuedPeer(first, active));
    EXPECT_TRUE(policy.canStartQueuedPeer(second, active));
    EXPECT_FALSE(policy.canStartQueuedPeer({}, active));
    EXPECT_FALSE(policy.canStartQueuedPeer(second, QSet<QUuid>{first, QUuid::createUuid()}));
    EXPECT_FALSE(policy.canStartQueuedPeer(second,QSet<QUuid>{QUuid()}));
}

TEST(TransferEstimatorTests, ResumeOffsetDoesNotInflateSpeedAndEtaStartsUnknown)
{
    TransferEstimator estimator;
    auto first = estimator.sample(1000, 8 * 1024 * 1024, 16 * 1024 * 1024);
    EXPECT_FALSE(first.bytesPerSecond.has_value());
    EXPECT_FALSE(first.remainingSeconds.has_value());

    auto second = estimator.sample(2000, 9 * 1024 * 1024, 16 * 1024 * 1024);
    ASSERT_TRUE(second.bytesPerSecond.has_value());
    EXPECT_NEAR(*second.bytesPerSecond, 1024.0 * 1024.0, 1.0);
    ASSERT_TRUE(second.remainingSeconds.has_value());
    EXPECT_EQ(*second.remainingSeconds, 7u);
}

TEST(TransferEstimatorTests, IgnoresNonMonotonicSamplesAndSmoothsRates)
{
    TransferEstimator estimator(0.5);
    estimator.sample(100, 0, 1000);
    auto steady = estimator.sample(1100, 100, 1000);
    ASSERT_TRUE(steady.bytesPerSecond.has_value());
    EXPECT_DOUBLE_EQ(*steady.bytesPerSecond, 100.0);
    auto stale = estimator.sample(900, 500, 1000);
    EXPECT_DOUBLE_EQ(*stale.bytesPerSecond, 100.0);
    auto regressed = estimator.sample(2100, 50, 1000);
    EXPECT_DOUBLE_EQ(*regressed.bytesPerSecond, 100.0);
    auto faster = estimator.sample(2100, 300, 1000);
    EXPECT_NEAR(*faster.bytesPerSecond, 150.0, 0.001);
}

TEST(TransferEstimatorTests, HandlesLogicalLargeFileWithoutAllocationOrOverflow)
{
    TransferEstimator estimator;const quint64 gib=1024ull*1024*1024;
    estimator.sample(0,3*gib,8*gib);const auto estimate=estimator.sample(2000,4*gib,8*gib);
    ASSERT_TRUE(estimate.bytesPerSecond);EXPECT_NEAR(*estimate.bytesPerSecond,double(gib)/2.0,1.0);
    ASSERT_TRUE(estimate.remainingSeconds);EXPECT_EQ(*estimate.remainingSeconds,8u);
}

TEST(BandwidthThrottleTests, PacesManySmallChunksByAggregateBytes)
{
    qint64 now=0;BandwidthThrottle throttle(1024,[&]{return now;},[&](int ms){now+=ms;});
    for(int i=0;i<101;++i)ASSERT_TRUE(throttle.beforeSend(10,{}));
    EXPECT_GE(now,970);EXPECT_LE(now,1000);
}

TEST(BandwidthThrottleTests, UnlimitedPathHasNoClockOrSleepOverhead)
{
    int clockCalls = 0;
    int sleepCalls = 0;
    BandwidthThrottle throttle(0, [&] { ++clockCalls; return qint64(0); },
        [&](int) { ++sleepCalls; });
    EXPECT_TRUE(throttle.beforeSend(64 * 1024, {}));
    EXPECT_EQ(clockCalls, 0);
    EXPECT_EQ(sleepCalls, 0);
}

TEST(BandwidthThrottleTests, PacesDeterministicallyAndSleepIsCancellationAware)
{
    qint64 now = 0;
    QList<int> sleeps;
    BandwidthThrottle throttle(1024, [&] { return now; }, [&](int ms) {
        sleeps.append(ms);
        now += ms;
    });
    EXPECT_TRUE(throttle.beforeSend(1024, {})); // one-chunk burst
    EXPECT_TRUE(throttle.beforeSend(1024, {}));
    EXPECT_EQ(now, 1000);
    EXPECT_GT(sleeps.size(), 1); // bounded slices, never one long uninterruptible sleep

    int cancellationChecks = 0;
    EXPECT_FALSE(throttle.beforeSend(1024, [&] { return ++cancellationChecks >= 2; }));
    EXPECT_LT(now, 2000);
}
