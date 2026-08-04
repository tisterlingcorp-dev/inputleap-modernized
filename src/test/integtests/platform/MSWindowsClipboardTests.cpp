/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2011 Nick Bolton
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "platform/MSWindowsClipboard.h"
#include "platform/IMSWindowsClipboardFacade.h"
#include "inputleap/Clipboard.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <Shlobj.h>
#include <shellapi.h>
#include <cstring>

namespace inputleap {

class MSWindowsClipboardTests : public ::testing::Test
{
protected:
    virtual void SetUp()
    {
        emptyClipboard();
    }

    virtual void TearDown()
    {
        emptyClipboard();
    }

private:
    void emptyClipboard()
    {
        MSWindowsClipboard clipboard(nullptr);
        if (clipboard.open(0)) {
            clipboard.clear();
            clipboard.close();
        }
    }
};

class MockFacade : public IMSWindowsClipboardFacade
{
public:
    MOCK_METHOD2(write, void(HANDLE, UINT));
};

class NativeFileDropClipboard
{
public:
    ~NativeFileDropClipboard()
    {
        if (clipboardOpen_) CloseClipboard();
        if (data_ != nullptr) GlobalFree(data_);
        if (window_ != nullptr) DestroyWindow(window_);
    }

    HWND createOwnerWindow()
    {
        window_ = CreateWindowExW(
            0, L"STATIC", L"InputLeap clipboard test owner", WS_POPUP,
            0, 0, 0, 0, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
        return window_;
    }

    HGLOBAL allocate(SIZE_T bytes)
    {
        data_ = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes);
        return data_;
    }

    bool open()
    {
        for (int attempt = 0; attempt < 20; ++attempt) {
            clipboardOpen_ = OpenClipboard(window_) != FALSE;
            if (clipboardOpen_) return true;
            Sleep(10);
        }
        return false;
    }

    bool empty() const
    {
        return EmptyClipboard() == TRUE;
    }

    HANDLE transfer(UINT format)
    {
        HANDLE transferred = SetClipboardData(format, data_);
        if (transferred != nullptr) data_ = nullptr;
        return transferred;
    }

    bool close()
    {
        if (!clipboardOpen_) return true;
        if (CloseClipboard() == FALSE) return false;
        clipboardOpen_ = false;
        return true;
    }

private:
    HWND window_{nullptr};
    HGLOBAL data_{nullptr};
    bool clipboardOpen_{false};
};

TEST_F(MSWindowsClipboardTests, emptyUnowned_openCalled_returnsTrue)
{
    MSWindowsClipboard clipboard(nullptr);
    clipboard.open(0);

    bool actual = clipboard.emptyUnowned();

    EXPECT_EQ(true, actual);
}

TEST_F(MSWindowsClipboardTests, empty_openCalled_returnsTrue)
{
    MSWindowsClipboard clipboard(nullptr);
    clipboard.open(0);

    bool actual = clipboard.clear();

    EXPECT_EQ(true, actual);
}

TEST_F(MSWindowsClipboardTests, empty_singleFormat_hasReturnsFalse)
{
    MSWindowsClipboard clipboard(nullptr);
    clipboard.open(0);
    clipboard.add(MSWindowsClipboard::kText, "test string!");

    clipboard.clear();

    bool actual = clipboard.has(MSWindowsClipboard::kText);
    EXPECT_EQ(false, actual);
}

TEST_F(MSWindowsClipboardTests, add_newValue_valueWasStored)
{
    MSWindowsClipboard clipboard(nullptr);
    clipboard.open(0);

    clipboard.add(IClipboard::kText, "test string!");

    std::string actual = clipboard.get(IClipboard::kText);
    EXPECT_EQ("test string!", actual);
}

TEST_F(MSWindowsClipboardTests, add_newValue_writeWasCalled)
{
    MockFacade facade;
    EXPECT_CALL(facade, write(testing::_, testing::_));

    MSWindowsClipboard clipboard(nullptr);
    clipboard.setFacade(facade);
    clipboard.open(0);

    clipboard.add(IClipboard::kText, "test string!");
}

TEST_F(MSWindowsClipboardTests, add_replaceValue_valueWasReplaced)
{
    MSWindowsClipboard clipboard(nullptr);
    clipboard.open(0);

    clipboard.add(IClipboard::kText, "test string!");
    clipboard.add(IClipboard::kText, "other string");

    std::string actual = clipboard.get(IClipboard::kText);
    EXPECT_EQ("other string", actual);
}

TEST_F(MSWindowsClipboardTests, open_timeIsZero_returnsTrue)
{
    MSWindowsClipboard clipboard(nullptr);

    bool actual = clipboard.open(0);

    EXPECT_EQ(true, actual);
}

TEST_F(MSWindowsClipboardTests, open_timeIsOne_returnsTrue)
{
    MSWindowsClipboard clipboard(nullptr);

    bool actual = clipboard.open(1);

    EXPECT_EQ(true, actual);
}

TEST_F(MSWindowsClipboardTests, close_isOpen_noErrors)
{
    MSWindowsClipboard clipboard(nullptr);
    clipboard.open(0);

    clipboard.close();

    // can't assert anything
}

// looks like this test may fail intermittently:
// * http://buildbot.symless.com:8000/builders/trunk-win32/builds/246/steps/shell_3/logs/stdio
/*TEST_F(MSWindowsClipboardTests, getTime_openWithNoEmpty_returnsOne)
{
    MSWindowsClipboard clipboard(nullptr);
    clipboard.open(1);

    MSWindowsClipboard::Time actual = clipboard.getTime();

    // this behavior is different to that of Clipboard which only
    // returns the value passed into open(t) after empty() is called.
    EXPECT_EQ(1, actual);
}*/

// this also fails intermittently:
// http://buildbot.symless.com:8000/builders/trunk-win32/builds/266/steps/shell_3/logs/stdio
/*TEST_F(MSWindowsClipboardTests, getTime_openAndEmpty_returnsOne)
{
    MSWindowsClipboard clipboard(nullptr);
    clipboard.open(1);
    clipboard.empty();

    MSWindowsClipboard::Time actual = clipboard.getTime();

    EXPECT_EQ(1, actual);
}*/

TEST_F(MSWindowsClipboardTests, has_withFormatAdded_returnsTrue)
{
    MSWindowsClipboard clipboard(nullptr);
    clipboard.open(0);
    clipboard.clear();
    clipboard.add(IClipboard::kText, "test string!");

    bool actual = clipboard.has(IClipboard::kText);

    EXPECT_EQ(true, actual);
}

TEST_F(MSWindowsClipboardTests, has_withNoFormats_returnsFalse)
{
    MSWindowsClipboard clipboard(nullptr);
    clipboard.open(0);
    clipboard.clear();

    bool actual = clipboard.has(IClipboard::kText);

    EXPECT_EQ(false, actual);
}

TEST_F(MSWindowsClipboardTests, get_withNoFormats_returnsEmpty)
{
    MSWindowsClipboard clipboard(nullptr);
    clipboard.open(0);
    clipboard.clear();

    std::string actual = clipboard.get(IClipboard::kText);

    EXPECT_EQ("", actual);
}

TEST_F(MSWindowsClipboardTests, get_withFormatAdded_returnsExpected)
{
    MSWindowsClipboard clipboard(nullptr);
    clipboard.open(0);
    clipboard.clear();
    clipboard.add(IClipboard::kText, "test string!");

    std::string actual = clipboard.get(IClipboard::kText);

    EXPECT_EQ("test string!", actual);
}

TEST_F(MSWindowsClipboardTests, copy_externalFileDrop_preservesFileList)
{
    const wchar_t filePath[] = L"C:\\Temp\\inputleap-file-clipboard-probe.txt";
    const SIZE_T bytes = sizeof(DROPFILES) + sizeof(filePath) + sizeof(wchar_t);
    NativeFileDropClipboard nativeClipboard;
    const HWND owner = nativeClipboard.createOwnerWindow();
    ASSERT_NE(nullptr, owner);
    HGLOBAL nativeData = nativeClipboard.allocate(bytes);
    ASSERT_NE(nullptr, nativeData);

    auto* drop = static_cast<DROPFILES*>(GlobalLock(nativeData));
    ASSERT_NE(nullptr, drop);
    drop->pFiles = sizeof(DROPFILES);
    drop->fWide = TRUE;
    std::memcpy(reinterpret_cast<char*>(drop) + drop->pFiles, filePath, sizeof(filePath));
    GlobalUnlock(nativeData);

    ASSERT_TRUE(nativeClipboard.open());
    ASSERT_TRUE(nativeClipboard.empty());
    ASSERT_NE(nullptr, nativeClipboard.transfer(CF_HDROP));
    ASSERT_TRUE(nativeClipboard.close());

    MSWindowsClipboard source(owner);
    Clipboard destination;
    ASSERT_TRUE(Clipboard::copy(&destination, &source));
    ASSERT_TRUE(destination.open(0));
    EXPECT_TRUE(destination.has(IClipboard::kFileList));
    EXPECT_EQ("C:\\Temp\\inputleap-file-clipboard-probe.txt",
              destination.get(IClipboard::kFileList));
    destination.close();
}

TEST_F(MSWindowsClipboardTests, is_owned_by_us_defaultState_noError)
{
    MSWindowsClipboard clipboard(nullptr);
    clipboard.open(0);

    bool actual = clipboard.is_owned_by_us();

    EXPECT_EQ(true, actual);
}

} // namespace inputleap
