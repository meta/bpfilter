# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

# - Add a line to the configuration summary
#
# Params:
#   - OUTPUT: name of the variable containing the summary.
#   - LABEL: left column of the line.
#   - VALUE: right column of the line.
function(_bf_summary_add_line OUTPUT LABEL VALUE)
    string(LENGTH "${LABEL}" label_len)
    math(EXPR padding_len "25 - ${label_len}")
    string(REPEAT " " ${padding_len} padding)

    set(${OUTPUT} "${${OUTPUT}}  ${LABEL}${padding}${VALUE}\n" PARENT_SCOPE)
endfunction()

# - Print a summary of the project's configuration
#
# This function should be called last, so the summary stands out from the
# messages printed during configuration. CMake's own closing messages
# ("Configuring done"...) will still follow it.
#
# Colors are used if stderr, where NOTICE messages go, is a terminal, unless
# NO_COLOR is set. CMake pipes the output of its child processes, so a child
# has to open CMake's stderr to know if it is a terminal.
function(bf_print_config_summary)
    if ("$ENV{NO_COLOR}" STREQUAL "")
        execute_process(
            COMMAND sh -c "test -t 0 < /proc/$PPID/fd/2"
            RESULT_VARIABLE tty_result
            OUTPUT_QUIET
            ERROR_QUIET
        )

        if (tty_result EQUAL 0)
            string(ASCII 27 esc)
            set(title "${esc}[1;36m")
            set(on "${esc}[32m")
            set(off "${esc}[2m")
            set(reset "${esc}[0m")
        endif ()
    endif ()

    set(version "${PROJECT_VERSION}${PROJECT_VERSION_SUFFIX}")
    set(summary "\n${title}bpfilter ${version} configuration${reset}\n\n")

    _bf_summary_add_line(summary "Build type" "${CMAKE_BUILD_TYPE}")
    _bf_summary_add_line(summary "Install prefix" "${CMAKE_INSTALL_PREFIX}")
    _bf_summary_add_line(summary "C compiler"
        "${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}"
    )
    _bf_summary_add_line(summary "libbpf" "${bpf_VERSION}")
    string(APPEND summary "\n")

    foreach (option IN ITEMS
        WITH_DOCS
        WITH_TESTS_UNIT
        WITH_TESTS_E2E
        WITH_TESTS_INTEGRATION
        WITH_TESTS_FUZZING
        WITH_TESTS_CHECKS
        WITH_TESTS_BENCHMARKS
        ENABLE_COVERAGE
    )
        if (${option})
            _bf_summary_add_line(summary "${option}" "${on}ON${reset}")
        else ()
            _bf_summary_add_line(summary "${option}" "${off}OFF${reset}")
        endif ()
    endforeach ()

    message(NOTICE "${summary}")
endfunction()
