# SPDX-License-Identifier: GPL-2.0-only

get_filename_component(
    TESTS_E2E_KERNEL_PATH "${TESTS_E2E_KERNEL_PATH}" ABSOLUTE
    BASE_DIR "${CMAKE_SOURCE_DIR}"
)

set(kernel_root "${TESTS_E2E_KERNEL_PATH}")

get_property(e2e_tests DIRECTORY ${CMAKE_SOURCE_DIR}/tests/e2e PROPERTY TESTS)
list(FILTER e2e_tests INCLUDE REGEX "^e2e\\.")

function(bf_add_kernel_tests requested_version)
    cmake_parse_arguments(ARG "" "NAME" "KERNEL_CONFIG;BOOT_ARGUMENT" ${ARGN})

    execute_process(
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/resolve-version
            --separator ";"
            "${kernel_root}" "${requested_version}"
        OUTPUT_VARIABLE kernel_release
        OUTPUT_STRIP_TRAILING_WHITESPACE
        COMMAND_ERROR_IS_FATAL ANY
    )
    list(GET kernel_release 0 kernel_revision)
    list(GET kernel_release 1 version)

    set(build_args "")
    if(ARG_NAME)
        string(APPEND version "-${ARG_NAME}")
        list(APPEND build_args --localversion "-${ARG_NAME}")
    endif()

    set(build_target "kernel.build.${version}")
    set(build_fixture "kernel.build[${version}]")

    foreach(option IN LISTS ARG_KERNEL_CONFIG)
        list(APPEND build_args --config "${option}")
    endforeach()

    set(boot_args "")
    foreach(argument IN LISTS ARG_BOOT_ARGUMENT)
        list(APPEND boot_args "--boot-argument=${argument}")
    endforeach()

    set_property(GLOBAL APPEND PROPERTY BF_TEST_KERNEL_VERSIONS "${version}")

    add_custom_target(${build_target}
        COMMAND
            ${CMAKE_CURRENT_SOURCE_DIR}/buildkernel
                --sources "${kernel_root}"
                --revision "${kernel_revision}"
                --output "${CMAKE_BINARY_DIR}/kernel/${version}"
                ${build_args}
        VERBATIM
    )

    add_test(NAME "${build_fixture}"
        COMMAND
            ${CMAKE_COMMAND}
                --build ${CMAKE_BINARY_DIR}
                --target ${build_target}
                --parallel ${CPU_COUNT}
    )

    set_tests_properties("${build_fixture}"
        PROPERTIES
            LABELS "kernel;${version}"
            FIXTURES_SETUP "${build_fixture}"
            PROCESSORS ${CPU_COUNT}
    )

    foreach(test IN LISTS e2e_tests)
        add_test(NAME "kernel.${test}[${version}]"
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/harness
                --kernel "${CMAKE_BINARY_DIR}/kernel/${version}/build"
                --build-dir ${CMAKE_BINARY_DIR}
                --test ${test} --memory 1G --cpus 1
                ${boot_args}
        )
        set_tests_properties(
            "kernel.${test}[${version}]"
                PROPERTIES
                    LABELS "kernel;${version}"
                    FIXTURES_REQUIRED "build.e2e;${build_fixture}"
        )
    endforeach()
endfunction()

# Test the supported LTS kernels, the first oldest supported by bpfilter,
# and the latest kernel.
bf_add_kernel_tests(6.6)
bf_add_kernel_tests(6.12)
bf_add_kernel_tests(6.18)
bf_add_kernel_tests(7.3)

add_custom_target(kernel
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L "^kernel$"
    COMMENT "Running e2e tests inside test kernels"
)
