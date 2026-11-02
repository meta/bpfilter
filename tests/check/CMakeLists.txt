# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_program(RUN_CLANG_TIDY_BIN NAMES run-clang-tidy-18 run-clang-tidy REQUIRED)
find_program(CLANG_FORMAT_BIN NAMES clang-format-18 clang-format REQUIRED)

file(GLOB_RECURSE bf_srcs
    ${CMAKE_SOURCE_DIR}/src/core/*.h            ${CMAKE_SOURCE_DIR}/src/core/*.c
    ${CMAKE_SOURCE_DIR}/src/libbpfilter/*.h     ${CMAKE_SOURCE_DIR}/src/libbpfilter/*.c
    ${CMAKE_SOURCE_DIR}/src/bfcli/*.h           ${CMAKE_SOURCE_DIR}/src/bfcli/*.c
)

file(GLOB_RECURSE bf_test_srcs
    ${CMAKE_SOURCE_DIR}/tests/*.h               ${CMAKE_SOURCE_DIR}/tests/*.c
    ${CMAKE_SOURCE_DIR}/tests/*.hpp             ${CMAKE_SOURCE_DIR}/tests/*.cpp
)
set(bf_all_srcs ${bf_srcs} ${bf_test_srcs})

# Only report diagnostics from headers in the project source tree. This
# excludes build-generated headers (flex/bison output, version.h, rawstubs.h
# and the elfstub .inc.c files) which we don't write by hand and shouldn't be
# held to clang-tidy's style rules.
set(LINT_HEADER_FILTER "^${CMAKE_SOURCE_DIR}/src/(core|libbpfilter|bfcli)/.*")

add_test(NAME "check.lint"
    COMMAND
        ${RUN_CLANG_TIDY_BIN}
            -config-file=${CMAKE_SOURCE_DIR}/.clang-tidy
            -p ${CMAKE_BINARY_DIR}
            -header-filter=${LINT_HEADER_FILTER}
            -extra-arg=-fno-caret-diagnostics
            -j ${CPU_COUNT}
            ${bf_srcs}
)

add_test(NAME "check.iwyu"
    COMMAND
        /usr/bin/iwyu_tool.py
            -p ${CMAKE_BINARY_DIR}
            ${CMAKE_SOURCE_DIR}/src/libbpfilter/cgen/program.c
)

set_tests_properties("check.lint" PROPERTIES
    LABELS "check"
)

add_test(NAME "check.checkstyle"
    COMMAND
        ${CLANG_FORMAT_BIN}
            --style=file:${CMAKE_SOURCE_DIR}/.clang-format
            --dry-run
            --Werror
            ${bf_all_srcs}
)

set_tests_properties("check.checkstyle" PROPERTIES
    LABELS "check"
)

find_program(SG_BIN NAMES ast-grep)

if(SG_BIN)
    set(SG_CONFIG ${CMAKE_SOURCE_DIR}/tests/check/ast-grep/sgconfig.yml)

    add_test(NAME "check.astgrep.test"
        COMMAND ${SG_BIN} test --config ${SG_CONFIG}
    )

    add_test(NAME "check.astgrep"
        COMMAND ${SG_BIN} scan --config ${SG_CONFIG}
            ${CMAKE_SOURCE_DIR}/src/libbpfilter
            ${CMAKE_SOURCE_DIR}/src/bfcli
            --off=assert-pointer-params
            --off=doxygen-prefer-backticks
            --off=doxygen-public-functions
            --off=no-direct-free
            --off=single-line-comment-style
    )

    set_tests_properties("check.astgrep.test" "check.astgrep" PROPERTIES
        LABELS "check"
    )
endif()

add_custom_target(fixstyle
    COMMAND
        ${CLANG_FORMAT_BIN}
            --style=file:${CMAKE_SOURCE_DIR}/.clang-format
            -i
            ${bf_all_srcs}
    COMMENT "Fixing style for all the source files"
)

add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L check
    COMMENT "Running check tests"
)

bf_tests_build(check libbpfilter bfcli)
