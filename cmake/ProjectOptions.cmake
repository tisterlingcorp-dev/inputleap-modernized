option(INPUTLEAP_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(INPUTLEAP_ENABLE_CLANG_TIDY "Run clang-tidy while compiling" OFF)
option(INPUTLEAP_WARNINGS_AS_ERRORS "Treat project warnings as errors" OFF)

function(inputleap_setup_project_options)
    add_library(inputleap_project_options INTERFACE)
    target_compile_features(inputleap_project_options INTERFACE cxx_std_20)

    if(MSVC)
        # Match the non-MSVC policy below: callback/interface parameters may be
        # intentionally unused, while project code keeps every other level-4
        # warning active. CMake-provided external include directories retain
        # their external warning level instead of leaking dependency template
        # diagnostics into /WX builds.
        target_compile_options(inputleap_project_options INTERFACE
            /W4 /permissive- /wd4100)
        if(INPUTLEAP_WARNINGS_AS_ERRORS)
            target_compile_options(inputleap_project_options INTERFACE /WX)
        endif()
    else()
        target_compile_options(inputleap_project_options INTERFACE
            -Wall -Wextra -Wpedantic -Wno-unused-parameter)
        if(INPUTLEAP_WARNINGS_AS_ERRORS)
            target_compile_options(inputleap_project_options INTERFACE -Werror)
        endif()
    endif()

    if(INPUTLEAP_ENABLE_SANITIZERS)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            # The legacy Event type erasure retrieves derived IPC payloads
            # through their base type. Keep the remaining UBSan checks active
            # while that event representation is modernized separately.
            target_compile_options(inputleap_project_options INTERFACE
                -fsanitize=address,undefined -fno-sanitize=vptr -fno-omit-frame-pointer)
            target_link_options(inputleap_project_options INTERFACE
                -fsanitize=address,undefined -fno-omit-frame-pointer)
        else()
            message(FATAL_ERROR "INPUTLEAP_ENABLE_SANITIZERS currently requires GCC or Clang")
        endif()
    endif()

    if(INPUTLEAP_ENABLE_CLANG_TIDY)
        find_program(INPUTLEAP_CLANG_TIDY_EXECUTABLE NAMES clang-tidy REQUIRED)
        set(INPUTLEAP_CLANG_TIDY_COMMAND
            "${INPUTLEAP_CLANG_TIDY_EXECUTABLE};--use-color"
            CACHE INTERNAL "clang-tidy command for InputLeap targets")
    endif()
endfunction()

function(inputleap_apply_project_options)
    foreach(target IN LISTS ARGN)
        if(TARGET ${target})
            # The legacy project still uses the plain target_link_libraries
            # signature. Keep this call plain until the individual targets are
            # migrated to keyword signatures.
            target_link_libraries(${target} inputleap_project_options)
            if(INPUTLEAP_ENABLE_CLANG_TIDY)
                set_property(TARGET ${target} PROPERTY CXX_CLANG_TIDY "${INPUTLEAP_CLANG_TIDY_COMMAND}")
            endif()
        endif()
    endforeach()
endfunction()