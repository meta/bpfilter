#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

# Parser-only coverage for bare log lookahead and log header tokens.
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log DROP chain c2 BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp counter DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log
DROP rule ip4.proto icmp counter ACCEPT"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log
link,internet
DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link # hdrs
DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log # bare
DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log
# bare
DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp log NEXT"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp log REDIRECT 1 in"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp log mark 0x1 DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto tcp log 5-tuple DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto tcp log 5-tuple every 1s DROP"
# log every <frequency>: integer and float values, with and without headers
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log every 1s DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log every 500ms DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log every 1.5s DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log every 0.5ms DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,internet every 1s DROP"
${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log internet every 100ms DROP"
(! ${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log every 0s DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log every 1year DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,ip DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,,internet DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log @DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto tcp log 5-tuple,link DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto tcp log link,5-tuple DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_XDP ACCEPT rule ip4.proto tcp log 5_tuple DROP")
(! ${BFCLI} ruleset set --dry-run --from-str "chain c1 BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=/sys/fs/cgroup} ACCEPT rule meta.l4_proto tcp log 5-tuple DROP")

make_sandbox

${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log counter DROP"
(! ${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log ip counter DROP")
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link counter DROP"
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,internet counter DROP"
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link,transport counter DROP"
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log internet,link counter DROP"

# --verbose bpf adds a check after the log ELF stub call
${FROM_NS} ${BFCLI} --verbose bpf chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log link counter DROP"
${FROM_NS} ${BFCLI} --verbose bpf chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto tcp log 5-tuple every 1s counter DROP"

# log every <frequency> in a chain with more than one rule
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto tcp counter ACCEPT rule ip4.proto icmp log every 1s counter DROP"
