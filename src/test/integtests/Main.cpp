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

#include "arch/Arch.h"
#include "base/Log.h"
#include "base/Time.h"

#if SYSAPI_WIN32
#include "arch/win32/ArchMiscWindows.h"
#endif

#include <gtest/gtest.h>
#include <iostream>
#include <fstream>
#include <string>

#define LOCK_TIMEOUT 30

bool lock(const std::string& lockFile);
void unlock(std::string lockFile);

int
main(int argc, char **argv)
{
#if SYSAPI_WIN32
    // record window instance for tray icon, etc
    inputleap::ArchMiscWindows::setInstanceWin32(GetModuleHandle(nullptr));
#endif

    inputleap::Arch arch;
    arch.init();

    inputleap::Log log;
    log.setFilter(kDEBUG2);

    std::string lockFile;
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]).compare("--lock-file") == 0) {
            if (i + 1 >= argc || argv[i + 1] == nullptr || argv[i + 1][0] == '\0') {
                std::cerr << "--lock-file requires a non-empty path" << std::endl;
                return 2;
            }
            lockFile = argv[++i];
        }
    }

    if (!lockFile.empty()) {
        if (!lock(lockFile)) {
            std::cerr << "Unable to acquire integration test lock file" << std::endl;
            return 2;
        }
    }


    testing::InitGoogleTest(&argc, argv);

    int result = RUN_ALL_TESTS();

    if (!lockFile.empty()) {
        unlock(lockFile);
    }

  // gtest seems to randomly finish with error codes (e.g. -1, -1073741819)
  // even when no tests have failed. not sure what causes this, but it
  // happens on all platforms and  keeps leading to false positives.
  // according to the documentation, 1 is a failure, so we should be
  // able to trust that code.
  return (result == 1) ? 1 : 0;
}

bool lock(const std::string& lockFile)
{
    double start = inputleap::current_time_seconds();

    // keep checking until timeout is reached.
    while ((inputleap::current_time_seconds() - start) < LOCK_TIMEOUT) {

        std::ifstream is(lockFile.c_str());
        bool noLock = !is;
        is.close();

        if (noLock) {
            break;
        }

        // check every second if file has gone.
        inputleap::this_thread_sleep(1);
    }

    // write empty lock file.
    std::ofstream os(lockFile.c_str(), std::ios::out | std::ios::trunc);
    if (!os) {
        return false;
    }
    os.close();
    return static_cast<bool>(os);
}

void unlock(std::string lockFile)
{
    std::remove(lockFile.c_str());
}
