#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

# Failures
(! ${FROM_NS} ${BFCLI} chain update --from-str "")
(! ${FROM_NS} ${BFCLI} chain update --name invalid_name --from-str "chain chain_load_xdp_0 BF_HOOK_XDP ACCEPT")
(! ${FROM_NS} ${BFCLI} chain update --name chain_load_xdp_1 --from-str "chain chain_load_xdp_1 BF_HOOK_XDP ACCEPT")

# Chain exists and is not attached
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_2 BF_HOOK_XDP ACCEPT"
${FROM_NS} ${BFCLI} chain update --from-str "chain chain_load_xdp_2 BF_HOOK_XDP DROP"
${FROM_NS} ${BFCLI} chain flush --name chain_load_xdp_2

# Chain exists and is attached
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_3 BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} ${BFCLI} chain update --from-str "chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp log transport counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} ${BFCLI} chain update --name chain_load_xdp_3 --from-str "chain chain_load_xdp_3 BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} ${BFCLI} chain flush --name chain_load_xdp_3

# A failed update leaves the attached chain unchanged
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_update_rollback BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
# A bf_ctx_tmp directory makes persisting the context fail
${FROM_NS} mkdir ${WORKDIR}/bpf/bpfilter/chain_update_rollback/bf_ctx_tmp
(! ${FROM_NS} ${BFCLI} chain update --from-str "chain chain_update_rollback BF_HOOK_XDP ACCEPT")
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
chain_output=$(${FROM_NS} ${BFCLI} chain get --name chain_update_rollback)
echo "$chain_output" | grep -q 'ip4.proto'
${FROM_NS} rmdir ${WORKDIR}/bpf/bpfilter/chain_update_rollback/bf_ctx_tmp
${FROM_NS} ${BFCLI} chain update --from-str "chain chain_update_rollback BF_HOOK_XDP ACCEPT"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} ${BFCLI} chain flush --name chain_update_rollback

# Same for a Netfilter chain, whose links are recreated on update
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_update_rollback_nf BF_HOOK_NF_LOCAL_IN{priorities=101-102} ACCEPT rule ip4.proto icmp DROP"
${FROM_NS} mkdir ${WORKDIR}/bpf/bpfilter/chain_update_rollback_nf/bf_ctx_tmp
(! ${FROM_NS} ${BFCLI} chain update --from-str "chain chain_update_rollback_nf BF_HOOK_NF_LOCAL_IN ACCEPT")
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
chain_output=$(${FROM_NS} ${BFCLI} chain get --name chain_update_rollback_nf)
echo "$chain_output" | grep -q 'ip4.proto'
test "$(${FROM_NS} find ${WORKDIR}/bpf/bpfilter/chain_update_rollback_nf/ -name 'bf_link*' | wc -l)" = "2"
${FROM_NS} rmdir ${WORKDIR}/bpf/bpfilter/chain_update_rollback_nf/bf_ctx_tmp
${FROM_NS} ${BFCLI} chain update --from-str "chain chain_update_rollback_nf BF_HOOK_NF_LOCAL_IN ACCEPT"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} ${BFCLI} chain flush --name chain_update_rollback_nf

# The chain's hook can't change, whether the chain is attached or not
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_update_hook_xdp BF_HOOK_XDP ACCEPT"
(! ${FROM_NS} ${BFCLI} chain update --from-str "chain chain_update_hook_xdp BF_HOOK_TC_INGRESS ACCEPT")
chain_output=$(${FROM_NS} ${BFCLI} chain get --name chain_update_hook_xdp)
echo "$chain_output" | grep -q 'chain chain_update_hook_xdp BF_HOOK_XDP ACCEPT'
${FROM_NS} ${BFCLI} chain flush --name chain_update_hook_xdp

${FROM_NS} ${BFCLI} chain set --from-str "chain chain_update_hook_nf BF_HOOK_NF_LOCAL_IN{priorities=101-102} ACCEPT"
(! ${FROM_NS} ${BFCLI} chain update --from-str "chain chain_update_hook_nf BF_HOOK_NF_LOCAL_OUT ACCEPT")
chain_output=$(${FROM_NS} ${BFCLI} chain get --name chain_update_hook_nf)
echo "$chain_output" | grep -q 'chain chain_update_hook_nf BF_HOOK_NF_LOCAL_IN{priorities=101-102} ACCEPT'
${FROM_NS} ${BFCLI} chain flush --name chain_update_hook_nf

# Counters are reset after chain update
${FROM_NS} ${BFCLI} chain set --from-str "chain chain_load_xdp_4 BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    rule ip4.proto icmp counter DROP
"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
counter=$(${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/chain_load_xdp_4/bf_cmap | jq '.[0].values | map(.value.count) | add')
test "$counter" = "1"
${FROM_NS} ${BFCLI} chain update --from-str "chain chain_load_xdp_4 BF_HOOK_XDP ACCEPT
    rule ip4.proto icmp counter DROP
"
counter=$(${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/chain_load_xdp_4/bf_cmap | jq '.[0].values | map(.value.count) | add')
test "$counter" = "0"
${FROM_NS} ${BFCLI} chain flush --name chain_load_xdp_4
