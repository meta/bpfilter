# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

# - Define a new C test
#
# Create a new C-based test for bpfilter.
#
# Params:
# - GROUP: name of the group to add the test to.
# - SOURCE: source file defining the test.
#
# C-based tests are configured to be automatically build before running, which
# is different from CTest's default behaviour.
function(bf_add_c_test GROUP SOURCE)
    find_package(cmocka REQUIRED)

    set(source_wo_ext ${SOURCE})
    cmake_path(REMOVE_EXTENSION source_wo_ext)
    string(REPLACE "/" "." target_suffix "${source_wo_ext}")

    set(target_name "${GROUP}.${target_suffix}")

    add_executable(${target_name} EXCLUDE_FROM_ALL ${SOURCE})

    # CMocka doesn't automatically discover the tests, -Wunused-function ensures
    # we run all the tests defined in a source file.
    target_compile_options(${target_name}
        PRIVATE
            -Werror=unused-function
    )

    target_link_libraries(${target_name}
        PRIVATE
            bf_global_flags
            libbpfilter
            mock
            harness
            cmocka
    )

    add_dependencies(unit_bin ${target_name})
    target_include_directories(${target_name}
      PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src/libbpfilter
    )

    add_test(NAME ${target_name}
        COMMAND $<TARGET_FILE:${target_name}>
    )

    set_tests_properties(${target_name} PROPERTIES
        ENVIRONMENT "LD_PRELOAD=${ASAN_LIB_PATH}:$<TARGET_FILE:mock>"
    )
    set_tests_properties(${target_name} PROPERTIES LABELS "${GROUP}")
endfunction()

# In debug builds, we need to preload the ASan library for the tests to run, before the mock library.
if(CMAKE_BUILD_TYPE STREQUAL "debug")
    execute_process(
        COMMAND sh -c "ldconfig -p | awk '/libasan\\.so\\.[0-9]+ /{print $NF; exit}'"
        OUTPUT_VARIABLE ASAN_LIB_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

add_custom_target(unit_bin
    DEPENDS libbpfilter
    COMMENT "Building unit test binaries"
)

add_custom_target(unit
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L unit
    DEPENDS unit_bin
    COMMENT "Running unit tests"
)

bf_add_c_test(unit libbpfilter/bpf.c)
bf_add_c_test(unit libbpfilter/btf.c)
bf_add_c_test(unit libbpfilter/chain.c)
bf_add_c_test(unit libbpfilter/api.c)
bf_add_c_test(unit libbpfilter/counter.c)
bf_add_c_test(unit libbpfilter/ctx.c)
bf_add_c_test(unit libbpfilter/dump.c)
bf_add_c_test(unit libbpfilter/flavor.c)
bf_add_c_test(unit libbpfilter/helper.c)
bf_add_c_test(unit libbpfilter/hook.c)
bf_add_c_test(unit libbpfilter/if.c)
bf_add_c_test(unit libbpfilter/io.c)
bf_add_c_test(unit libbpfilter/core/hashset.c)
bf_add_c_test(unit libbpfilter/core/list.c)
bf_add_c_test(unit libbpfilter/core/lock.c)
bf_add_c_test(unit libbpfilter/core/vector.c)
bf_add_c_test(unit libbpfilter/logger.c)
bf_add_c_test(unit libbpfilter/matcher.c)
bf_add_c_test(unit libbpfilter/pack.c)
bf_add_c_test(unit libbpfilter/rule.c)
bf_add_c_test(unit libbpfilter/set.c)
bf_add_c_test(unit libbpfilter/verdict.c)
bf_add_c_test(unit libbpfilter/version.c)

bf_tests_build(unit unit_bin)
