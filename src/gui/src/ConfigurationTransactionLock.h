/* InputLeap -- process- and thread-safe configuration transaction lock. */
#pragma once

#include <QDir>
#include <QLockFile>

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

class ConfigurationTransactionLock
{
public:
    explicit ConfigurationTransactionLock(int timeoutMs = 5000,
                                          const QString& lockPath = path())
    {
        const auto caller = std::this_thread::get_id();
        const auto timeout = std::chrono::milliseconds(timeoutMs);
        std::unique_lock stateLock(state_mutex_);
        if (depth_ != 0 && owner_thread_ == caller && reentry_blocked_depth_ != 0)
            return;
        if (!state_changed_.wait_for(stateLock, timeout, [caller] {
                return depth_ == 0 || (owner_thread_ == caller && reentry_blocked_depth_ == 0);
            })) {
            return;
        }

        if (depth_ == 0) {
            auto fileLock = std::make_unique<QLockFile>(lockPath);
            stateLock.unlock();
            const bool fileLocked = fileLock->tryLock(timeoutMs);
            stateLock.lock();
            if (!fileLocked || depth_ != 0) {
                fileLock.reset();
                return;
            }
            file_lock_ = std::move(fileLock);
            owner_thread_ = caller;
        }
        ++depth_;
        acquisition_thread_ = caller;
        acquisition_depth_ = depth_;
        locked_ = true;
    }

    ~ConfigurationTransactionLock()
    {
        if (!locked_) return;
        std::unique_lock stateLock(state_mutex_);
        if (depth_ <= 0 || owner_thread_ != acquisition_thread_)
            std::terminate();
        --depth_;
        if (reentry_blocked_depth_ == acquisition_depth_)
            reentry_blocked_depth_ = 0;
        if (depth_ == 0) {
            file_lock_.reset();
            owner_thread_ = {};
            reentry_blocked_depth_ = 0;
            stateLock.unlock();
            state_changed_.notify_all();
        }
    }

    ConfigurationTransactionLock(const ConfigurationTransactionLock&) = delete;
    ConfigurationTransactionLock& operator=(const ConfigurationTransactionLock&) = delete;
    ConfigurationTransactionLock(ConfigurationTransactionLock&&) = delete;
    ConfigurationTransactionLock& operator=(ConfigurationTransactionLock&&) = delete;

    bool isLocked() const noexcept { return locked_; }

    bool sealReentrantAcquisition() noexcept
    {
        std::lock_guard stateLock(state_mutex_);
        const auto caller = std::this_thread::get_id();
        if (!locked_ || acquisition_thread_ != caller || owner_thread_ != caller ||
            acquisition_depth_ != depth_)
            return false;
        reentry_blocked_depth_ = acquisition_depth_;
        return true;
    }

    static QString path()
    {
        return QDir(QDir::tempPath()).filePath(
            QStringLiteral("inputleap-configuration-transaction.lock"));
    }

private:
    inline static std::mutex state_mutex_;
    inline static std::condition_variable state_changed_;
    inline static std::thread::id owner_thread_;
    inline static int depth_ = 0;
    inline static int reentry_blocked_depth_ = 0;
    inline static std::unique_ptr<QLockFile> file_lock_;

    std::thread::id acquisition_thread_;
    int acquisition_depth_ = 0;
    bool locked_ = false;
};
