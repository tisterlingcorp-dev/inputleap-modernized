# InputLeap -- mouse and keyboard sharing utility
# Copyright (C) 2012-2016 Symless Ltd.
# Copyright (C) 2011 Nick Bolton
#
# This package is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# found in the file LICENSE that should have accompanied this file.
#
# This package is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

include_directories (./lib)
include_directories (${CMAKE_CURRENT_BINARY_DIR}/lib)

add_subdirectory(lib)

add_subdirectory(client)
add_subdirectory(server)

if (WIN32)
    add_subdirectory(daemon)
endif()

if(INPUTLEAP_BUILD_TESTS)
    include(../cmake/gtest.cmake)
    add_subdirectory(test/integtests)
    add_subdirectory(test/unittests)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(
        NAME safe-release-smoke-policy
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/helpers/test_safe_release_smoke_policy.py
    )
    add_test(
        NAME platform-screen-logging-wrapper-policy
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/helpers/test_platform_screen_logging_wrapper_policy.py
    )
    add_test(
        NAME dependency-download-policy
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/helpers/test_dependency_download_policy.py
    )
endif()

if(INPUTLEAP_BUILD_GUI)
    add_subdirectory(gui)
endif()
