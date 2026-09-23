# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_package(PkgConfig REQUIRED)
pkg_check_modules(bpf REQUIRED IMPORTED_TARGET libbpf)

include(ElfStubs)

set(libbpfilter_srcs
    # Public interface
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/bpfilter.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/bpf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/bpf_types.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/btf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/chain.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/counter.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/ctx.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/dump.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/elfstub.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/flavor.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/helper.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/hook.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/if.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/io.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/core/hashset.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/core/list.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/core/vector.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/logger.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/matcher.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/pack.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/rule.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/runtime.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/set.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/limit.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/verdict.h

    # Private sources and headers
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/btf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/chain.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cli.c
    ${CMAKE_CURRENT_SOURCE_DIR}/counter.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ctx.c
    ${CMAKE_CURRENT_SOURCE_DIR}/dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/elfstub.c
    ${CMAKE_CURRENT_SOURCE_DIR}/flavor.c
    ${CMAKE_CURRENT_SOURCE_DIR}/helper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hook.c
    ${CMAKE_CURRENT_SOURCE_DIR}/if.c
    ${CMAKE_CURRENT_SOURCE_DIR}/io.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/hashset.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/list.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/lock.h             ${CMAKE_CURRENT_SOURCE_DIR}/core/lock.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/vector.c
    ${CMAKE_CURRENT_SOURCE_DIR}/logger.c
    ${CMAKE_CURRENT_SOURCE_DIR}/matcher.c
    ${CMAKE_CURRENT_SOURCE_DIR}/pack.c
    ${CMAKE_CURRENT_SOURCE_DIR}/rule.c
    ${CMAKE_CURRENT_SOURCE_DIR}/set.c
    ${CMAKE_CURRENT_SOURCE_DIR}/limit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verdict.c
    ${CMAKE_CURRENT_SOURCE_DIR}/version.c

    # Code generation engine
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgen.h              ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgen.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgroup_skb.h        ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgroup_skb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgroup_sock_addr.h  ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgroup_sock_addr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/dump.h              ${CMAKE_CURRENT_SOURCE_DIR}/cgen/dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/fixup.h             ${CMAKE_CURRENT_SOURCE_DIR}/cgen/fixup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/handle.h            ${CMAKE_CURRENT_SOURCE_DIR}/cgen/handle.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/jmp.h               ${CMAKE_CURRENT_SOURCE_DIR}/cgen/jmp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/cmp.h       ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/cmp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/meta.h      ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/meta.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/set.h       ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/set.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/nf.h                ${CMAKE_CURRENT_SOURCE_DIR}/cgen/nf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/packet.h            ${CMAKE_CURRENT_SOURCE_DIR}/cgen/packet.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/printer.h           ${CMAKE_CURRENT_SOURCE_DIR}/cgen/printer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/program.h           ${CMAKE_CURRENT_SOURCE_DIR}/cgen/program.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/prog/link.h         ${CMAKE_CURRENT_SOURCE_DIR}/cgen/prog/link.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/prog/map.h          ${CMAKE_CURRENT_SOURCE_DIR}/cgen/prog/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/runtime.h
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/stub.h              ${CMAKE_CURRENT_SOURCE_DIR}/cgen/stub.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/swich.h             ${CMAKE_CURRENT_SOURCE_DIR}/cgen/swich.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/tc.h                ${CMAKE_CURRENT_SOURCE_DIR}/cgen/tc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/xdp.h               ${CMAKE_CURRENT_SOURCE_DIR}/cgen/xdp.c

    # External
    ${CMAKE_SOURCE_DIR}/src/external/include/mpack.h
    ${CMAKE_SOURCE_DIR}/src/external/mpack.c
    ${CMAKE_SOURCE_DIR}/src/external/include/disasm.h   ${CMAKE_SOURCE_DIR}/src/external/disasm.c
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/bpfilter.pc.in
    ${CMAKE_BINARY_DIR}/output/lib/pkgconfig/bpfilter.pc
    @ONLY
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/bpfilter/version.h
    @ONLY
)

add_library(libbpfilter
    SHARED
        ${libbpfilter_srcs}
)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/cgen)
bf_target_add_elfstubs(libbpfilter
    DIR ${CMAKE_CURRENT_SOURCE_DIR}/bpf
    SYM_PREFIX "_bf_rawstubs_"
    DECL_HDR_PATH ${CMAKE_CURRENT_BINARY_DIR}/include/cgen/rawstubs.h
    STUBS
        "parse_ipv6_eh"
        "parse_ipv6_nh"
        "update_counters"
        "pkt_log"
        "flow_hash"
        "sock_addr_log"
        "pkt_5_tuple_log"
        "limit"
)

target_compile_definitions(libbpfilter
    PRIVATE
        # MPack should use the C standard library API
        MPACK_STDLIB
)

target_include_directories(libbpfilter
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_BINARY_DIR}/include
)

# Vendored kernel headers are SYSTEM so clang-tidy's --system-headers=false
# default skips the reserved identifiers they use.
target_include_directories(libbpfilter SYSTEM
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/external/include
)

target_link_libraries(libbpfilter
    PRIVATE
        bf_global_flags
        m
    PUBLIC
        PkgConfig::bpf
)

set_target_properties(libbpfilter PROPERTIES OUTPUT_NAME bpfilter)
set_target_properties(libbpfilter PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})

install(TARGETS libbpfilter)

install(
    DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}/include/bpfilter
        ${CMAKE_CURRENT_BINARY_DIR}/include/bpfilter
    TYPE INCLUDE
    FILES_MATCHING PATTERN "*.h"
)

install(
    FILES ${CMAKE_BINARY_DIR}/output/lib/pkgconfig/bpfilter.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
