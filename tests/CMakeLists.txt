# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

# - Build targets before running the tests of the current directory
#
# Define a CTest fixture to build the targets required by the tests defined so
# far in the current directory. `make test` and `ctest` will then build what
# they need, instead of running missing or outdated binaries.
#
# Params:
# - GROUP: name of the group the tests belong to.
# - ARGN: targets to build.
function(bf_tests_build GROUP)
    get_directory_property(tests TESTS)

    add_test(NAME "build.${GROUP}"
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${ARGN}
    )

    # The lock prevents concurrent fixtures from compiling the same objects.
    set_tests_properties("build.${GROUP}" PROPERTIES
        FIXTURES_SETUP "build.${GROUP}"
        LABELS "${GROUP}"
        RESOURCE_LOCK "bf_build"
    )

    set_tests_properties(${tests} PROPERTIES
        FIXTURES_REQUIRED "build.${GROUP}"
    )
endfunction()

if (WITH_TESTS_UNIT OR WITH_TESTS_E2E)
    add_subdirectory(harness)
endif ()

if (WITH_TESTS_UNIT)
    add_subdirectory(unit)
endif ()

if (WITH_TESTS_E2E)
    add_subdirectory(e2e)
endif ()

if (WITH_TESTS_E2E AND TESTS_E2E_KERNEL_PATH)
    add_subdirectory(kernel)
endif ()

if (WITH_TESTS_FUZZING)
    add_subdirectory(fuzz)
endif ()

if (WITH_TESTS_INTEGRATION)
    add_subdirectory(integration)
endif ()

if (WITH_TESTS_CHECKS)
    add_subdirectory(check)
endif ()

if (WITH_TESTS_BENCHMARKS)
    add_subdirectory(benchmarks)
endif ()

if (CMAKE_GENERATOR STREQUAL "Unix Makefiles")
    # Make has no jobserver for -j1. Pass its normalized -jN value to CTest
    # explicitly, rather than letting bare --parallel choose the CPU count.
    string(CONCAT BF_TEST_LAUNCHER
        "CTEST_PARALLEL_LEVEL="
        "$(if $(filter -j,$(MAKEFLAGS)),${CPU_COUNT},"
        "$(or $(patsubst -j%,%,$(firstword $(filter -j%,$(MAKEFLAGS)))),1))"
    )

    # CMake creates the built-in test target after configuration, so it can
    # only inherit a launcher from the top-level directory. Every custom
    # command gets the variable, but only CTest reads it.
    set_property(DIRECTORY ${CMAKE_SOURCE_DIR} PROPERTY RULE_LAUNCH_CUSTOM
        "${BF_TEST_LAUNCHER}"
    )
endif()

if (ENABLE_COVERAGE)
    include(ProcessorCount)

    find_program(LCOV_BIN lcov REQUIRED)
    find_program(GENHTML_BIN genhtml REQUIRED)

    ProcessorCount(N)
    if(N EQUAL 0)
        set(N 1)
    endif()

    add_custom_target(coverage
        COMMAND
            ${LCOV_BIN}
                --capture
                --directory ${CMAKE_BINARY_DIR}
                --output-file ${CMAKE_CURRENT_BINARY_DIR}/raw_coverage.lcov
                --parallel ${N}
                --branch-coverage
                --quiet
        # Only keep the coverage for bpfilter's source files, not the tests.
        COMMAND
            ${LCOV_BIN}
                --output-file ${CMAKE_BINARY_DIR}/coverage.lcov
                --extract ${CMAKE_CURRENT_BINARY_DIR}/raw_coverage.lcov
                --ignore-errors unused
                --branch-coverage
                --parallel ${N}
                --quiet
                "${CMAKE_SOURCE_DIR}/src/libbpfilter\\*"
        COMMAND
            ${LCOV_BIN}
                --summary ${CMAKE_BINARY_DIR}/coverage.lcov
                --branch-coverage
        COMMAND
			${GENHTML_BIN}
				--output-directory ${CMAKE_BINARY_DIR}/coverage
                --branch-coverage
                --css-file ${CMAKE_CURRENT_SOURCE_DIR}/coverage.css
				${CMAKE_BINARY_DIR}/coverage.lcov > /dev/null;
        BYPRODUCTS
            ${CMAKE_BINARY_DIR}/coverage.lcov
            ${CMAKE_BINARY_DIR}/coverage/index.html
        COMMENT "Generate the coverage.lcov summary file"
    )

    # The dependency file only exists if the documentation is configured.
    if (WITH_DOCS)
        add_custom_command(TARGET coverage POST_BUILD
            COMMAND
                cp ${CMAKE_BINARY_DIR}/.coverage_report.d.full ${CMAKE_BINARY_DIR}/.coverage_report.d
        )
    endif ()
endif()
