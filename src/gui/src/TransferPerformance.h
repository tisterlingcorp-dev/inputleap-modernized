/*
 * InputLeap -- controlled file-transfer performance policy
 */
#pragma once

#include <QSet>
#include <QUuid>
#include <QtGlobal>

#include <functional>
#include <optional>

class PerformancePolicy
{
public:
    static constexpr int MaximumConcurrentTransfers = 2;
    static constexpr quint64 MinimumBandwidthBytesPerSecond = 64 * 1024;
    static constexpr quint64 MaximumBandwidthBytesPerSecond = 1024ull * 1024 * 1024;

    explicit PerformancePolicy(int maxConcurrent = 1, quint64 bandwidthBytesPerSecond = 0);

    int maxConcurrent() const { return max_concurrent_; }
    quint64 bandwidthBytesPerSecond() const { return bandwidth_bytes_per_second_; }
    bool canStartQueuedPeer(const QUuid& peer, const QSet<QUuid>& activePeers) const;

private:
    int max_concurrent_ = 1;
    quint64 bandwidth_bytes_per_second_ = 0;
};

class TransferEstimator
{
public:
    struct Estimate {
        std::optional<double> bytesPerSecond;
        std::optional<quint64> remainingSeconds;
    };

    explicit TransferEstimator(double ewmaAlpha = 0.25);
    Estimate sample(qint64 monotonicMilliseconds, quint64 confirmedBytes, quint64 totalBytes);

private:
    double alpha_;
    bool initialized_ = false;
    qint64 last_milliseconds_ = 0;
    quint64 last_bytes_ = 0;
    std::optional<double> rate_;
};

class BandwidthThrottle
{
public:
    using Clock = std::function<qint64()>;
    using Sleeper = std::function<void(int)>;
    using Cancel = std::function<bool()>;

    explicit BandwidthThrottle(quint64 bytesPerSecond, Clock clock = {}, Sleeper sleeper = {});
    bool beforeSend(quint64 bytes, const Cancel& cancelled);

private:
    quint64 bytes_per_second_;
    Clock clock_;
    Sleeper sleeper_;
    bool started_ = false;
    qint64 next_send_milliseconds_ = 0;
};
