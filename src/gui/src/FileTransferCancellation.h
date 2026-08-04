/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#pragma once

#include <atomic>
#include <memory>

class FileTransferCancellation
{
public:
    FileTransferCancellation() : state_(std::make_shared<std::atomic_bool>(false)) { }

    void cancel() const noexcept { state_->store(true, std::memory_order_release); }
    bool isCancelled() const noexcept { return state_->load(std::memory_order_acquire); }

private:
    std::shared_ptr<std::atomic_bool> state_;
};
