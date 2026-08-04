/*
 * InputLeap -- mouse and keyboard sharing utility
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 */

#pragma once

#include "platform/synwinhk.h"

#include <atomic>

namespace inputleap {

class MSWindowsHookMode
{
public:
    using Storage = std::atomic<EHookMode>;

    class Snapshot
    {
    public:
        explicit Snapshot(EHookMode mode) noexcept : m_mode(mode)
        {
        }

        EHookMode value() const noexcept
        {
            return m_mode;
        }

    private:
        EHookMode m_mode;
    };

    explicit MSWindowsHookMode(EHookMode mode) noexcept : m_mode(mode)
    {
    }

    void store(EHookMode mode) noexcept
    {
        m_mode.store(mode, std::memory_order_release);
    }

    Snapshot snapshot() const noexcept
    {
        return Snapshot{m_mode.load(std::memory_order_acquire)};
    }

private:
    Storage m_mode;
};

} // namespace inputleap
