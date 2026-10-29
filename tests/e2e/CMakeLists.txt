# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

find_package(cmocka REQUIRED)

add_executable(setuserns EXCLUDE_FROM_ALL
    ${CMAKE_CURRENT_SOURCE_DIR}/setuserns.c
)

target_link_libraries(setuserns
    PRIVATE
        bf_global_flags
        libbpfilter
)

function(bf_add_e2e_shell_test GROUP SOURCE)
    cmake_parse_arguments(
        ARG
        "ROOT"
        ""
        ""
        ${ARGN}
    )

    set(source_wo_ext ${SOURCE})
    cmake_path(REMOVE_EXTENSION source_wo_ext)
    string(REPLACE "/" "." target_suffix "${source_wo_ext}")

    set(target_name "${GROUP}.${target_suffix}")

    if (ARG_ROOT)
        # Run each privileged test in its own network and mount namespaces.
        # make_sandbox creates a veth pair and keeps one end outside the
        # sandbox, with an address and a route. In a shared network namespace,
        # two concurrent tests could use the same subnet and send packets to
        # each other's sandbox. The mount namespace holds the sandbox's mounts
        # (netns and bpffs), so the kernel removes them when the test exits,
        # even if the test is killed.
        set(AS_ROOT ${CMAKE_SOURCE_DIR}/tools/asroot
            unshare --mount --net --propagation private --
        )
    endif ()

    add_test(NAME ${target_name}
        COMMAND
            ${AS_ROOT} ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE}
    )

    set_tests_properties(${target_name} PROPERTIES
        LABELS "${GROUP}"
        ENVIRONMENT "PATH=${CMAKE_BINARY_DIR}/output/sbin:${CMAKE_CURRENT_SOURCE_DIR}:$ENV{PATH}"
    )
endfunction()

function(bf_add_e2e_c_test SOURCE)
    set(source_wo_ext ${SOURCE})
    cmake_path(REMOVE_EXTENSION source_wo_ext)
    string(REPLACE "/" "." target_suffix "${source_wo_ext}")
    set(target_name "e2e.${target_suffix}")

    add_executable(${target_name} EXCLUDE_FROM_ALL ${SOURCE})

    target_link_libraries(${target_name}
        PRIVATE
            bf_global_flags_cxx
            libbpfilter
            harness
            harness_cxx
            cmocka
    )

    add_dependencies(e2e_bin ${target_name})

    add_test(NAME ${target_name}
        COMMAND ${CMAKE_SOURCE_DIR}/tools/asroot $<TARGET_FILE:${target_name}>
    )

    set_tests_properties(${target_name}
        PROPERTIES
            LABELS "e2e"
            ENVIRONMENT "PATH=${CMAKE_BINARY_DIR}/output/sbin:$ENV{PATH}"
    )
endfunction()

add_custom_target(e2e_bin
    DEPENDS setuserns libbpfilter bfcli harness harness_cxx
    COMMENT "Building end-to-end test binaries"
)

add_custom_target(e2e
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L e2e
    DEPENDS e2e_bin
    COMMENT "Running end-to-end tests"
)

bf_add_e2e_shell_test(e2e cli/chain_attach.sh ROOT)
bf_add_e2e_shell_test(e2e cli/chain_get_no_set_content.sh ROOT)
bf_add_e2e_shell_test(e2e cli/chain_load.sh ROOT)
bf_add_e2e_shell_test(e2e cli/chain_set.sh ROOT)
bf_add_e2e_shell_test(e2e cli/chain_update.sh ROOT)
bf_add_e2e_shell_test(e2e cli/chain_update_set.sh ROOT)
bf_add_e2e_shell_test(e2e cli/help.sh)
bf_add_e2e_shell_test(e2e cli/hookopts.sh)
bf_add_e2e_shell_test(e2e cli/nf_inet_dual_stack.sh ROOT)
bf_add_e2e_shell_test(e2e cli/options_error.sh)
bf_add_e2e_shell_test(e2e cli/ruleset.sh ROOT)

bf_add_e2e_shell_test(e2e namespace/host_to_netns.sh ROOT)
bf_add_e2e_shell_test(e2e namespace/netns_to_host.sh ROOT)

bf_add_e2e_shell_test(e2e persistence/pin_updated_chain.sh ROOT)
bf_add_e2e_shell_test(e2e persistence/restore_attached.sh ROOT)
bf_add_e2e_shell_test(e2e persistence/restore_non_attached.sh ROOT)

bf_add_e2e_shell_test(e2e parsing/icmp_code.sh)
bf_add_e2e_shell_test(e2e parsing/icmp_type.sh)
bf_add_e2e_shell_test(e2e parsing/icmpv6_code.sh)
bf_add_e2e_shell_test(e2e parsing/icmpv6_type.sh)
bf_add_e2e_shell_test(e2e parsing/ip4_daddr.sh)
bf_add_e2e_shell_test(e2e parsing/ip4_dnet.sh)
bf_add_e2e_shell_test(e2e parsing/ip4_dscp.sh)
bf_add_e2e_shell_test(e2e parsing/ip4_proto.sh)
bf_add_e2e_shell_test(e2e parsing/ip4_saddr.sh)
bf_add_e2e_shell_test(e2e parsing/ip4_snet.sh)
bf_add_e2e_shell_test(e2e parsing/ip6_daddr.sh)
bf_add_e2e_shell_test(e2e parsing/ip6_dnet.sh)
bf_add_e2e_shell_test(e2e parsing/ip6_dscp.sh)
bf_add_e2e_shell_test(e2e parsing/ip6_nexthdr.sh)
bf_add_e2e_shell_test(e2e parsing/ip6_saddr.sh)
bf_add_e2e_shell_test(e2e parsing/ip6_snet.sh)
bf_add_e2e_shell_test(e2e parsing/meta_dport.sh)
bf_add_e2e_shell_test(e2e parsing/meta_flow_hash.sh)
bf_add_e2e_shell_test(e2e parsing/meta_flow_probability.sh)
bf_add_e2e_shell_test(e2e parsing/meta_iface.sh)
bf_add_e2e_shell_test(e2e parsing/meta_l3_proto.sh)
bf_add_e2e_shell_test(e2e parsing/meta_l4_proto.sh)
bf_add_e2e_shell_test(e2e parsing/meta_mark.sh)
bf_add_e2e_shell_test(e2e parsing/meta_pid.sh)
bf_add_e2e_shell_test(e2e parsing/meta_probability.sh)
bf_add_e2e_shell_test(e2e parsing/meta_sport.sh)
bf_add_e2e_shell_test(e2e parsing/set.sh ROOT)
bf_add_e2e_shell_test(e2e parsing/set_empty_index.sh ROOT)
bf_add_e2e_shell_test(e2e parsing/set_min_size.sh)
bf_add_e2e_shell_test(e2e parsing/named_set.sh)
bf_add_e2e_shell_test(e2e parsing/tcp_flags.sh)
bf_add_e2e_shell_test(e2e parsing/tcp_dport.sh)
bf_add_e2e_shell_test(e2e parsing/tcp_sport.sh)
bf_add_e2e_shell_test(e2e parsing/udp_dport.sh)
bf_add_e2e_shell_test(e2e parsing/udp_sport.sh)

bf_add_e2e_shell_test(e2e rules/action_order.sh ROOT)
bf_add_e2e_shell_test(e2e rules/gre.sh ROOT)
bf_add_e2e_shell_test(e2e rules/icmp_tc.sh ROOT)
bf_add_e2e_shell_test(e2e rules/icmp_xdp.sh ROOT)
bf_add_e2e_shell_test(e2e rules/log.sh ROOT)
bf_add_e2e_shell_test(e2e rules/mark.sh ROOT)
bf_add_e2e_shell_test(e2e rules/next_tc.sh ROOT)
bf_add_e2e_shell_test(e2e rules/redirect.sh ROOT)
bf_add_e2e_shell_test(e2e rules/set_grouping.sh ROOT)
bf_add_e2e_shell_test(e2e rules/set_min_size.sh ROOT)
bf_add_e2e_shell_test(e2e rules/set_port_range.sh ROOT)

bf_add_e2e_shell_test(e2e hooks/cgroup_skb_dual_stack.sh ROOT)
bf_add_e2e_shell_test(e2e hooks/cgroup_sock_addr_connect4.sh ROOT)
bf_add_e2e_shell_test(e2e hooks/cgroup_sock_addr_connect6.sh ROOT)
bf_add_e2e_shell_test(e2e hooks/cgroup_sock_addr_dual_stack.sh ROOT)
bf_add_e2e_shell_test(e2e hooks/cgroup_sock_addr_sendmsg4.sh ROOT)
bf_add_e2e_shell_test(e2e hooks/cgroup_sock_addr_sendmsg6.sh ROOT)

bf_add_e2e_shell_test(e2e rulesets/rulesets.sh ROOT)

bf_add_e2e_c_test(verdicts/next.cpp)
bf_add_e2e_c_test(actions/log.cpp)
bf_add_e2e_c_test(actions/log_5_tuple.cpp)
bf_add_e2e_c_test(rules/derived_state.cpp)

bf_add_e2e_c_test(matchers/icmp_code.cpp)
bf_add_e2e_c_test(matchers/icmp_type.cpp)
bf_add_e2e_c_test(matchers/icmpv6_code.cpp)
bf_add_e2e_c_test(matchers/icmpv6_type.cpp)
bf_add_e2e_c_test(matchers/ip4_daddr.cpp)
bf_add_e2e_c_test(matchers/ip4_dnet.cpp)
bf_add_e2e_c_test(matchers/ip4_dscp.cpp)
bf_add_e2e_c_test(matchers/ip4_proto.cpp)
bf_add_e2e_c_test(matchers/ip4_saddr.cpp)
bf_add_e2e_c_test(matchers/ip4_snet.cpp)
bf_add_e2e_c_test(matchers/ip6_daddr.cpp)
bf_add_e2e_c_test(matchers/ip6_dnet.cpp)
bf_add_e2e_c_test(matchers/ip6_dscp.cpp)
bf_add_e2e_c_test(matchers/ip6_nexthdr.cpp)
bf_add_e2e_c_test(matchers/ip6_saddr.cpp)
bf_add_e2e_c_test(matchers/ip6_snet.cpp)
bf_add_e2e_c_test(matchers/meta_dport.cpp)
bf_add_e2e_c_test(matchers/meta_flow_hash.cpp)
bf_add_e2e_c_test(matchers/meta_flow_probability.cpp)
bf_add_e2e_c_test(matchers/meta_iface.cpp)
bf_add_e2e_c_test(matchers/meta_l3_proto.cpp)
bf_add_e2e_c_test(matchers/meta_l4_proto.cpp)
bf_add_e2e_c_test(matchers/meta_mark.cpp)
bf_add_e2e_c_test(matchers/meta_probability.cpp)
bf_add_e2e_c_test(matchers/meta_sport.cpp)
bf_add_e2e_c_test(matchers/tcp_dport.cpp)
bf_add_e2e_c_test(matchers/tcp_flags.cpp)
bf_add_e2e_c_test(matchers/tcp_sport.cpp)
bf_add_e2e_c_test(matchers/udp_dport.cpp)
bf_add_e2e_c_test(matchers/udp_sport.cpp)

bf_tests_build(e2e e2e_bin)
