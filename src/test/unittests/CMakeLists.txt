# InputLeap -- mouse and keyboard sharing utility
# Copyright (C) 2012-2016 Symless Ltd.
# Copyright (C) 2009 Nick Bolton
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

file(GLOB_RECURSE headers "*.h")
file(GLOB_RECURSE sources "*.cpp")

set(protocol_fixture_emitter_source "../helpers/ProtocolFixtureEmitter.cpp")
list(APPEND sources ${protocol_fixture_emitter_source})

file(GLOB_RECURSE remove_platform "platform/*")
list(REMOVE_ITEM headers ${remove_platform})
list(REMOVE_ITEM sources ${remove_platform})

if (NOT BUILD_MSWINDOWS)
    list(REMOVE_ITEM sources
        "${CMAKE_CURRENT_SOURCE_DIR}/inputleap/DaemonCommandPolicyTests.cpp")
endif()

file(GLOB_RECURSE global_headers "../../test/global/*.h")
file(GLOB_RECURSE global_sources "../../test/global/*.cpp")

list(APPEND headers ${global_headers})
list(APPEND sources ${global_sources})

file(GLOB_RECURSE mock_headers "../../test/mock/*.h")
file(GLOB_RECURSE mock_sources "../../test/mock/*.cpp")

list(APPEND headers ${mock_headers})
list(APPEND sources ${mock_sources})

# platform
if (BUILD_MSWINDOWS)
    file(GLOB mswin_sources "platform/MSWindows*.cpp")
    file(GLOB mswin_headers "platform/MSWindows*.h")
endif()
if (BUILD_CARBON)
    file(GLOB carbon_sources "platform/OSX*.cpp")
    file(GLOB carbon_headers "platform/OSX*.h")
endif()
if (BUILD_XWINDOWS)
    file(GLOB xwin_sources "platform/XWindows*.cpp")
    file(GLOB xwin_headers "platform/XWindows*.h")
endif()

list(APPEND sources ${mswin_sources} ${carbon_sources} ${xwin_sources})
list(APPEND headers ${mswin_headers} ${carbon_headers} ${xwin_headers})

include_directories(
    ../../
    ../../../ext
)

if (UNIX)
    include_directories(
        ../../..
    )
endif()

if(INPUTLEAP_ADD_HEADERS)
    list(APPEND sources ${headers})
endif()

add_executable(unittests ${sources})
target_compile_definitions(unittests PRIVATE INPUTLEAP_PROTOCOL_FIXTURE_EMITTER_NO_MAIN)
target_link_libraries(unittests
    base client server common io net platform server synlib mt arch ipc ${GTEST_LIBRARIES} ${GMOCK_LIBRARIES} ${libs} OpenSSL::SSL OpenSSL::Crypto)

add_executable(protocol-fixture-emitter ${protocol_fixture_emitter_source})
target_link_libraries(protocol-fixture-emitter synlib base io common arch ipc OpenSSL::Crypto)

if (BUILD_MSWINDOWS)
    if (NOT TARGET ipcpeerprocessclienthelper)
        add_executable(ipcpeerprocessclienthelper ../helpers/IpcPeerProcessClientHelper.cpp)
    endif()
    if (NOT TARGET inputleap-watchdog-fixture-helper)
        add_executable(inputleap-watchdog-fixture-helper
            ../helpers/WatchdogProcessFixtureHelper.cpp)
    endif()
    add_dependencies(unittests ipcpeerprocessclienthelper inputleap-watchdog-fixture-helper)
    target_compile_definitions(unittests PRIVATE
        INPUTLEAP_WATCHDOG_FIXTURE_HELPER_PATH="$<TARGET_FILE:inputleap-watchdog-fixture-helper>")
endif()

add_test(NAME unittests
         COMMAND unittests
         WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

execute_process(
    COMMAND git rev-parse HEAD
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    RESULT_VARIABLE protocol_fixture_git_result
    OUTPUT_VARIABLE protocol_fixture_source_revision
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)
if (NOT protocol_fixture_git_result EQUAL 0 OR protocol_fixture_source_revision STREQUAL "")
    set(protocol_fixture_source_revision "unavailable")
endif()
include(TestBigEndian)
test_big_endian(protocol_fixture_big_endian)
if (protocol_fixture_big_endian)
    set(protocol_fixture_endianness "big")
else()
    set(protocol_fixture_endianness "little")
endif()
set(protocol_fixture_compiler "${CMAKE_CXX_COMPILER_ID}-${CMAKE_CXX_COMPILER_VERSION}")
find_package(Python3 REQUIRED COMPONENTS Interpreter)
target_compile_definitions(protocol-fixture-emitter PRIVATE
    PROTOCOL_FIXTURE_SOURCE_REVISION="${protocol_fixture_source_revision}"
    PROTOCOL_FIXTURE_PLATFORM="${CMAKE_SYSTEM_NAME}"
    PROTOCOL_FIXTURE_ARCHITECTURE="${CMAKE_SYSTEM_PROCESSOR}"
    PROTOCOL_FIXTURE_COMPILER="${protocol_fixture_compiler}"
    PROTOCOL_FIXTURE_ENDIANNESS="${protocol_fixture_endianness}")

add_test(NAME protocol-fixture-emitter-cli
    COMMAND ${CMAKE_COMMAND}
        "-DEMITTER=$<TARGET_FILE:protocol-fixture-emitter>"
        "-DOUTPUT_DIR=${CMAKE_CURRENT_BINARY_DIR}/protocol-fixture-emitter-cli"
        "-DFROZEN_DIR=${CMAKE_CURRENT_SOURCE_DIR}/../fixtures/rust-r0-wire"
        "-DSOURCE_MANIFEST=${CMAKE_SOURCE_DIR}/docs/architecture/rust-rewrite/r0-source-manifest.json"
        "-DSOURCE_MANIFEST_CHECKER=${CMAKE_SOURCE_DIR}/.hermes/scripts/generate-rust-r0-source-manifest.py"
        "-DPYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
        "-DEXPECTED_SOURCE_REVISION=${protocol_fixture_source_revision}"
        "-DEXPECTED_PLATFORM=${CMAKE_SYSTEM_NAME}"
        "-DEXPECTED_ARCHITECTURE=${CMAKE_SYSTEM_PROCESSOR}"
        "-DEXPECTED_COMPILER=${protocol_fixture_compiler}"
        "-DEXPECTED_ENDIANNESS=${protocol_fixture_endianness}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/../helpers/VerifyProtocolFixtureEmitter.cmake.in")
set_tests_properties(protocol-fixture-emitter-cli PROPERTIES
    LABELS "rust-r0;protocol-fixtures")
