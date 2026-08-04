#pragma once

#include <mutex>
#include <utility>

namespace inputleap {

class SocketJobRegistration final {
public:
    template<typename RegisterJob>
    bool registerJob(RegisterJob&& registerJob)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_) {
            return false;
        }
        std::forward<RegisterJob>(registerJob)();
        return true;
    }

    template<typename RemoveJob>
    void close(RemoveJob&& removeJob)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
        std::forward<RemoveJob>(removeJob)();
    }

private:
    std::mutex mutex_;
    bool closed_ = false;
};

} // namespace inputleap
