# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

# - Compile stub BPF programs to be integrated into a target
#
# This function performs a multi-steps process to compile BPF programs and
# make them available to a C binary:
#   1. Compile the C BPF programs into an ELF file using clang.
#   2. Use xxd to generate a C source file containing two symbols: an array of
#      bytes defining the ELF file, and an integer to define its length.
#   3. Generate a header file declaring an array of custom structures
#      representing all the ELF stubs available.
#
# Each generated C source file is added to the target as a dependency *but not
# compiled*. The generated header in step 3 will include those header files
# directly.
#
# Params:
#   - TARGET: name of the target to define stubs for.
#   - DIR: directory containing the source files for the stubs.
#   - SYM_PREFIX: prefix of the C symbols.
#   - DECL_HDR_PATH: path to the generated header file. The caller is
#     responsible for adding the containing directory to the list of include
#     directory for the taret.
#   - STUBS: list of strings defining the name of the stubs sources.
#     bf_target_add_elfstubs() will look for the stubs following the pattern:
#     ${DIR}/${STUB_NAME}.bpf.c.
function(bf_target_add_elfstubs TARGET)
    cmake_parse_arguments(PARSE_ARGV 1 _LOCAL
        ""
        "DIR;SYM_PREFIX;DECL_HDR_PATH"
        "STUBS"
    )

    find_program(CLANG_BIN clang REQUIRED)
    find_program(XXD_BIN xxd REQUIRED)
    find_program(SED_BIN sed REQUIRED)

    list(LENGTH _LOCAL_STUBS N_STUBS)
    set_property(TARGET ${TARGET} PROPERTY BF_ELFSTUB_COUNT ${N_STUBS})

    set(ELFSTUBS_ELF_DIR ${CMAKE_CURRENT_BINARY_DIR}/elfstubs/elf)
    set(ELFSTUBS_INC_DIR ${CMAKE_CURRENT_BINARY_DIR}/elfstubs/src)
    file(MAKE_DIRECTORY ${ELFSTUBS_ELF_DIR} ${ELFSTUBS_INC_DIR})

    set(DECL_TEMPLATE_PATH ${CMAKE_SOURCE_DIR}/tools/cmake/rawstubs.h.in)

    foreach(_stub IN LISTS _LOCAL_STUBS)
        string(REGEX REPLACE "[/.]" "_" SYM_NAME "${ELFSTUBS_ELF_DIR}/${_stub}.o")

        add_custom_command(
            COMMAND
                ${CLANG_BIN}
                    -O2
                    -target bpf
                    -g
                    -I ${CMAKE_SOURCE_DIR}/src/libbpfilter/include
                    -I ${CMAKE_SOURCE_DIR}/src/libbpfilter
                    -I ${CMAKE_SOURCE_DIR}/src/external/include
                    -c ${_LOCAL_DIR}/${_stub}.bpf.c
                    -o ${ELFSTUBS_ELF_DIR}/${_stub}.o
            COMMAND
                ${XXD_BIN}
                    -i
                    ${ELFSTUBS_ELF_DIR}/${_stub}.o
                    ${ELFSTUBS_INC_DIR}/${_stub}.inc.c
            # The following sed commands will perform two operations:
            # - Ensure the symbols defined are static const
            # - Name the symbols as ${_LOCAL_SYM_PREFIX}/${_stub}(_len). This can be
            #   done using `xxd -n` but it's not supported on EPEL9.
            COMMAND
                ${SED_BIN}
                    -i 's/^unsigned char .*\\[\\]/static const unsigned char ${_LOCAL_SYM_PREFIX}${_stub}\\[\\]/'
                    ${ELFSTUBS_INC_DIR}/${_stub}.inc.c
            COMMAND
                ${SED_BIN}
                    -i 's/^unsigned int .*_len \\=/static const unsigned int ${_LOCAL_SYM_PREFIX}${_stub}_len \\=/'
                    ${ELFSTUBS_INC_DIR}/${_stub}.inc.c
            DEPENDS
                ${_LOCAL_DIR}/${_stub}.bpf.c
                ${DECL_TEMPLATE_PATH}
                ${CMAKE_SOURCE_DIR}/src/libbpfilter/include/bpfilter/runtime.h
                ${CMAKE_SOURCE_DIR}/src/libbpfilter/cgen/runtime.h
            OUTPUT
                ${ELFSTUBS_INC_DIR}/${_stub}.inc.c
            COMMENT "Generate ${_stub} stub"
        )

        set(HDR_INC "${HDR_INC}#include \"${_stub}.inc.c\"\n")
        set(HDR_DECL "${HDR_DECL}{ .elf = ${_LOCAL_SYM_PREFIX}${_stub}, .len = ${_LOCAL_SYM_PREFIX}${_stub}_len, },\n")

        # Add the source file containing the ELF file to the sources of the
        # given target, so the target will be build when the stub changes. It
        # will be included in the generated private header, so it should be
        # marked as header file.
        target_sources(${TARGET} PRIVATE ${ELFSTUBS_INC_DIR}/${_stub}.inc.c)
        set_source_files_properties(${ELFSTUBS_INC_DIR}/${_stub}.inc.c
            PROPERTIES
                HEADER_FILE_ONLY ON
        )

        message(VERBOSE "  - ${_stub}")
    endforeach()

    configure_file(${DECL_TEMPLATE_PATH} ${_LOCAL_DECL_HDR_PATH} @ONLY)
    target_sources(${TARGET} PRIVATE ${_LOCAL_DECL_HDR_PATH})

    target_include_directories(${TARGET} PRIVATE ${ELFSTUBS_INC_DIR})
endfunction()
