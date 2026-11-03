# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

cmake_minimum_required(VERSION 3.20)

# The actual version is defined below, from Git or the archive.
project(bpfilter
    VERSION 0.0.0
    DESCRIPTION "BPF-based packet filtering framework"
    LANGUAGES C CXX
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/tools/cmake")

include(GitVersion)

# Only use Git if the sources are the root of a repository: an archive could be
# extracted into an unrelated repository.
if (EXISTS ${CMAKE_SOURCE_DIR}/.git)
    get_version_from_git()
else ()
    get_version_from_archive()
endif ()

# Store the number of CPUs in a variable, can be used to parallelize commands
include(ProcessorCount)
ProcessorCount(CPU_COUNT)
if(CPU_COUNT EQUAL 0)
    set(CPU_COUNT 1)
endif()

include(GNUInstallDirs)

option(WITH_DOCS "Define the documentation targets" ON)
option(WITH_TESTS "Default value of the unset WITH_TESTS_<TYPE> options" ON)
option(ENABLE_COVERAGE "Build with code coverage support" OFF)

# Test types are plain variables because an option would cache the value of
# WITH_TESTS from the first configuration. An explicit -DWITH_TESTS_<TYPE>
# always wins, use -UWITH_TESTS_<TYPE> to restore the default.
foreach (test_type UNIT E2E INTEGRATION FUZZING CHECKS BENCHMARKS)
    if (NOT DEFINED WITH_TESTS_${test_type})
        set(WITH_TESTS_${test_type} ${WITH_TESTS})
    endif ()
endforeach ()

set(TESTS_E2E_KERNEL_PATH "" CACHE PATH
    "Path to a Linux stable Git clone for end-to-end kernel tests"
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(BF_CONTACT "Quentin Deslandes <qde@naccy.de>")

if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to 'release' as none was specified.")
  set(CMAKE_BUILD_TYPE "release" CACHE STRING "Choose the type of build." FORCE)
else ()
    set(BF_VALID_BUILD_TYPE "debug;release")
    string(TOLOWER ${CMAKE_BUILD_TYPE} BF_LOWER_BUILD_TYPE)
    list(FIND BF_VALID_BUILD_TYPE ${BF_LOWER_BUILD_TYPE} BF_BUILD_TYPE_INDEX)
    if (${BF_BUILD_TYPE_INDEX} EQUAL -1)
        message(FATAL_ERROR "CMAKE_BUILD_TYPE must be either 'debug' or 'release' (default), not '${CMAKE_BUILD_TYPE}'")
    endif ()
endif ()

# Ensure artefacts are moved to a common directory
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/output/include/bpfilter)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/output/lib/pkgconfig)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output/sbin)

add_library(bf_global_flags INTERFACE)
target_compile_options(bf_global_flags
    INTERFACE
        -std=gnu17 -Wall -Wextra -fPIC
        $<$<BOOL:${ENABLE_COVERAGE}>:-fprofile-arcs -ftest-coverage>
        $<$<CONFIG:debug>:-O0 -g3 -ggdb -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined>
        $<$<CONFIG:release>:-O2>
)
target_include_directories(bf_global_flags
    SYSTEM INTERFACE
        ${CMAKE_SOURCE_DIR}/src/external
)
target_link_options(bf_global_flags
    INTERFACE
        $<$<BOOL:${ENABLE_COVERAGE}>:-fprofile-arcs -ftest-coverage>
        $<$<CONFIG:debug>:-fsanitize=address -fsanitize=undefined>
)

add_library(bf_global_flags_cxx INTERFACE)
target_compile_options(bf_global_flags_cxx
    INTERFACE
        -std=c++20 -Wall -Wextra -fPIC
        $<$<CONFIG:debug>:-O0 -g3 -ggdb -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined>
        $<$<CONFIG:release>:-O2>
)
target_link_options(bf_global_flags_cxx
    INTERFACE
        $<$<CONFIG:debug>:-fsanitize=address -fsanitize=undefined>
)

add_subdirectory(src/libbpfilter)
add_subdirectory(src/bfcli)

if (WITH_DOCS)
    add_subdirectory(doc)
endif ()

set(CMAKE_CTEST_ARGUMENTS "--output-on-failure;--label-exclude;fuzzing")
enable_testing()
add_subdirectory(tests)

include(ConfigSummary)
bf_print_config_summary()
