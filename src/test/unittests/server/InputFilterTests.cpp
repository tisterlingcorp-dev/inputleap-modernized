/* InputLeap -- mouse and keyboard sharing utility */
#include "server/InputFilter.h"

#include <gtest/gtest.h>

using inputleap::InputFilter;

TEST(InputFilterTests, KeyboardBroadcastFormatPreservesScreenNames)
{
    const InputFilter::KeyboardBroadcastAction action(
        InputFilter::KeyboardBroadcastAction::kOn, {"left", "right"});

    EXPECT_EQ(action.format(), "keyboardBroadcast(on,left:right)");
}

TEST(InputFilterTests, KeyboardBroadcastFormatHandlesEmptyAndAllScreens)
{
    const InputFilter::KeyboardBroadcastAction empty(
        InputFilter::KeyboardBroadcastAction::kToggle, {});
    const InputFilter::KeyboardBroadcastAction all(
        InputFilter::KeyboardBroadcastAction::kOff, {"*"});

    EXPECT_EQ(empty.format(), "keyboardBroadcast(toggle)");
    EXPECT_EQ(all.format(), "keyboardBroadcast(off)");
}
