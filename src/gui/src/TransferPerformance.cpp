/*
 * InputLeap -- controlled file-transfer performance policy
 */
#include "TransferPerformance.h"

#include <QElapsedTimer>
#include <QThread>

#include <algorithm>
#include <cmath>
#include <memory>

PerformancePolicy::PerformancePolicy(int maxConcurrent, quint64 bandwidthBytesPerSecond) :
    max_concurrent_(std::clamp(maxConcurrent, 1, MaximumConcurrentTransfers)),
    bandwidth_bytes_per_second_(bandwidthBytesPerSecond == 0 ? 0 :
        std::clamp(bandwidthBytesPerSecond, MinimumBandwidthBytesPerSecond, MaximumBandwidthBytesPerSecond))
{
}

bool PerformancePolicy::canStartQueuedPeer(const QUuid& peer, const QSet<QUuid>& activePeers) const
{
    return !peer.isNull()&&!activePeers.contains(QUuid())&&activePeers.size()<max_concurrent_&&!activePeers.contains(peer);
}

TransferEstimator::TransferEstimator(double ewmaAlpha) : alpha_(std::clamp(ewmaAlpha, 0.01, 1.0))
{
}

TransferEstimator::Estimate TransferEstimator::sample(qint64 milliseconds, quint64 confirmedBytes, quint64 totalBytes)
{
    if (!initialized_) {
        initialized_ = true;
        last_milliseconds_ = milliseconds;
        last_bytes_ = confirmedBytes;
        return {};
    }
    if (milliseconds <= last_milliseconds_ || confirmedBytes < last_bytes_) {
        Estimate result{rate_, {}};
        if (rate_ && *rate_ > 0.0 && totalBytes > confirmedBytes)
            result.remainingSeconds = quint64(std::ceil(double(totalBytes - confirmedBytes) / *rate_));
        return result;
    }

    const double seconds = double(milliseconds - last_milliseconds_) / 1000.0;
    const double instantaneous = double(confirmedBytes - last_bytes_) / seconds;
    if (instantaneous > 0.0)
        rate_ = rate_ ? alpha_ * instantaneous + (1.0 - alpha_) * *rate_ : instantaneous;
    last_milliseconds_ = milliseconds;
    last_bytes_ = confirmedBytes;

    Estimate result{rate_, {}};
    if (rate_ && *rate_ > 0.0 && totalBytes > confirmedBytes)
        result.remainingSeconds = quint64(std::ceil(double(totalBytes - confirmedBytes) / *rate_));
    return result;
}

BandwidthThrottle::BandwidthThrottle(quint64 bytesPerSecond, Clock clock, Sleeper sleeper) :
    bytes_per_second_(bytesPerSecond)
{
    if (bytes_per_second_ == 0) return;
    if (clock) clock_ = std::move(clock);
    else {
        auto timer = std::make_shared<QElapsedTimer>();
        timer->start();
        clock_ = [timer] { return timer->elapsed(); };
    }
    sleeper_ = sleeper ? std::move(sleeper) : Sleeper([](int ms) { QThread::msleep(unsigned(ms)); });
}

bool BandwidthThrottle::beforeSend(quint64 bytes, const Cancel& cancelled)
{
    // This branch is the entire default-path cost: no clock query and no sleep.
    if (bytes_per_second_ == 0 || bytes == 0) return !(cancelled && cancelled());
    if (cancelled && cancelled()) return false;

    qint64 now = clock_();
    if (!started_) {
        started_ = true;
        next_send_milliseconds_ = now;
    }
    while (now < next_send_milliseconds_) {
        if (cancelled && cancelled()) return false;
        const int slice = int(std::min<qint64>(50, next_send_milliseconds_ - now));
        sleeper_(std::max(1, slice));
        now = clock_();
    }
    const qint64 duration = qint64(std::ceil(double(bytes) * 1000.0 / double(bytes_per_second_)));
    next_send_milliseconds_ = std::max(now, next_send_milliseconds_) + duration;
    return !(cancelled && cancelled());
}
