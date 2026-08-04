/*
 * InputLeap -- mouse and keyboard sharing utility
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 */

#include "platform/MSWindowsHookMode.h"

#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <type_traits>

namespace inputleap {
namespace {

TEST(MSWindowsHookModeTests, PublishesRelayModeAcrossThreads)
{
    static_assert(std::is_same_v<MSWindowsHookMode::Storage, std::atomic<EHookMode>>);

    MSWindowsHookMode mode{kHOOK_WATCH_JUMP_ZONE};
    std::thread writer([&] { mode.store(kHOOK_RELAY_EVENTS); });
    writer.join();

    EXPECT_EQ(kHOOK_RELAY_EVENTS, mode.snapshot().value());
}

TEST(MSWindowsHookModeTests, SnapshotRemainsStableWhenPublishedModeChanges)
{
    MSWindowsHookMode mode{kHOOK_WATCH_JUMP_ZONE};
    const auto eventMode = mode.snapshot();

    mode.store(kHOOK_RELAY_EVENTS);

    EXPECT_EQ(kHOOK_WATCH_JUMP_ZONE, eventMode.value());
    EXPECT_EQ(kHOOK_RELAY_EVENTS, mode.snapshot().value());
}

} // namespace
} // namespace inputleap
