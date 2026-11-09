#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

# A rule referencing multiple grouped sets stays disabled until every set is
# non-empty, and follows each emptiness transition after a single update.
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_ips0 (ip4.saddr) in {}
    set blocked_ips1 (ip4.saddr) in {}
    rule
        ip4.proto icmp
        (ip4.saddr) in blocked_ips0
        (ip4.saddr) in blocked_ips1
        counter
        DROP
"

ping -c 1 -W 0.1 ${NS_IP_ADDR}
test "$(get_counter test_xdp 0)" = "0"

${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_ips0 \
    --add ${HOST_IP_ADDR}
ping -c 1 -W 0.1 ${NS_IP_ADDR}
test "$(get_counter test_xdp 0)" = "0"

${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_ips1 \
    --add ${HOST_IP_ADDR}
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
test "$(get_counter test_xdp 0)" = "1"

${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_ips1 \
    --remove ${HOST_IP_ADDR}
ping -c 1 -W 0.1 ${NS_IP_ADDR}
test "$(get_counter test_xdp 0)" = "1"

${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_ips1 \
    --add ${HOST_IP_ADDR}
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
test "$(get_counter test_xdp 0)" = "2"

# A rule matching addresses "not in" an empty set matches every packet, and
# follows the set's emptiness transitions.
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set allowed (ip4.saddr) in {}
    rule
        ip4.proto icmp
        (ip4.saddr) not in allowed
        counter
        DROP
"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
test "$(get_counter test_xdp 0)" = "1"

${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name allowed \
    --add ${HOST_IP_ADDR}
ping -c 1 -W 0.1 ${NS_IP_ADDR}

${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name allowed \
    --remove ${HOST_IP_ADDR}
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
test "$(get_counter test_xdp 0)" = "2"

# Adding new elements
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_ips (ip4.saddr) in {
        10.0.0.1;
        10.0.0.2
    }
    rule
        (ip4.saddr) in blocked_ips
        counter
        DROP
"

${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --add 10.0.0.3 --add 10.0.0.4

chain_output=$(${FROM_NS} ${BFCLI} chain get --name test_xdp)
echo "$chain_output"
echo "$chain_output" | grep -q '10.0.0.1'
echo "$chain_output" | grep -q '10.0.0.2'
echo "$chain_output" | grep -q '10.0.0.3'
echo "$chain_output" | grep -q '10.0.0.4'

# Removing elements
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_ips (ip4.saddr) in {
        10.0.0.1;
        10.0.0.2;
        10.0.0.3;
        10.0.0.4
    }
    rule
        (ip4.saddr) in blocked_ips
        counter
        DROP
"

${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --remove 10.0.0.3 --remove 10.0.0.4

chain_output=$(${FROM_NS} ${BFCLI} chain get --name test_xdp)
echo "$chain_output"
echo "$chain_output" | grep -q '10.0.0.1'
echo "$chain_output" | grep -q '10.0.0.2'
(! echo "$chain_output" | grep -q '10.0.0.3')
(! echo "$chain_output" | grep -q '10.0.0.4')

# Adding and removing in one operation
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_ips (ip4.saddr) in {
        10.0.0.1;
        10.0.0.2
    }
    rule
        (ip4.saddr) in blocked_ips
        counter
        DROP
"

${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --add 10.0.0.3 --add 10.0.0.4 \
    --remove 10.0.0.1 --remove 10.0.0.4

chain_output=$(${FROM_NS} ${BFCLI} chain get --name test_xdp)
echo "$chain_output"
(! echo "$chain_output" | grep -q '10.0.0.1')
echo "$chain_output" | grep -q '10.0.0.2'
echo "$chain_output" | grep -q '10.0.0.3'
(! echo "$chain_output" | grep -q '10.0.0.4')

# Trying to update non-existent set should fail
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_ips (ip4.saddr) in {
        10.0.0.1;
        10.0.0.2
    }
    rule
        (ip4.saddr) in blocked_ips
        counter
        DROP
"

(! ${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name nonexistent_set \
    --add 10.0.0.3 2>&1)

chain_output=$(${FROM_NS} ${BFCLI} chain get --name test_xdp)
echo "$chain_output"
echo "$chain_output" | grep -q '10.0.0.1'
echo "$chain_output" | grep -q '10.0.0.2'

# Trying to update with mismatched key format should fail
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_ips (ip4.saddr) in {
        10.0.0.1;
        10.0.0.2
    }
    rule
        (ip4.saddr) in blocked_ips
        counter
        DROP
"

(! ${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --add 10.0.0.1,tcp 2>&1)

chain_output=$(${FROM_NS} ${BFCLI} chain get --name test_xdp)
echo "$chain_output"
echo "$chain_output" | grep -q '10.0.0.1'
echo "$chain_output" | grep -q '10.0.0.2'

# Trying to update with nothing to add or remove should fail
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_ips (ip4.saddr) in {
        10.0.0.1;
        10.0.0.2
    }
    rule
        (ip4.saddr) in blocked_ips
        counter
        DROP
"

(! ${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_ips 2>&1)

# Trying to add duplicate elements is no-op
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_ips (ip4.saddr) in {
        10.0.0.1
    }
    rule
        (ip4.saddr) in blocked_ips
        counter
        DROP
"

${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --add 10.0.0.1

chain_output=$(${FROM_NS} ${BFCLI} chain get --name test_xdp)
echo "$chain_output"
count=$(echo "$chain_output" | grep -o '10.0.0.1' | wc -l)
if [ "$count" -ne 1 ]; then
    echo "Expected 1 occurrence of 10.0.0.1, got $count"
    exit 1
fi

# Works with compound keys
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_addrs (ip4.saddr, tcp.sport) in {
        10.0.0.1, 10001;
        10.0.0.2, 10002
    }
    rule
        (ip4.saddr, tcp.sport) in blocked_addrs
        counter
        DROP
"

${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_addrs \
    --add 10.0.0.3,10003 --add '10.0.0.4, 10004'

chain_output=$(${FROM_NS} ${BFCLI} chain get --name test_xdp)
echo "$chain_output"
echo "$chain_output" | grep -q '10.0.0.1, 10001'
echo "$chain_output" | grep -q '10.0.0.2, 10002'
echo "$chain_output" | grep -q '10.0.0.3, 10003'
echo "$chain_output" | grep -q '10.0.0.4, 10004'

# Unattached chain can be updated
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP ACCEPT
    set test_set (ip4.saddr) in { 10.0.0.1 }
    rule (ip4.saddr) in test_set ACCEPT
"

${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name test_set \
    --add 10.0.0.2

chain_output=$(${FROM_NS} ${BFCLI} chain get --name test_xdp)
echo "$chain_output"
echo "$chain_output" | grep -q '10.0.0.1'
echo "$chain_output" | grep -q '10.0.0.2'

# A failed update-set leaves the attached chain and its counters unchanged
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_ips (ip4.saddr) in {
        ${HOST_IP_ADDR}
    }
    rule
        ip4.proto icmp
        (ip4.saddr) in blocked_ips
        counter
        DROP
"

(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
# A bf_ctx_tmp directory makes persisting the context fail
${FROM_NS} mkdir ${WORKDIR}/bpf/bpfilter/test_xdp/bf_ctx_tmp
(! ${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --remove ${HOST_IP_ADDR})

(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
test "$(get_counter test_xdp 0)" = "2"
chain_output=$(${FROM_NS} ${BFCLI} chain get --name test_xdp)
echo "$chain_output" | grep -q "${HOST_IP_ADDR}"

${FROM_NS} rmdir ${WORKDIR}/bpf/bpfilter/test_xdp/bf_ctx_tmp
${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --remove ${HOST_IP_ADDR}
ping -c 1 -W 0.1 ${NS_IP_ADDR}

# Counters are preserved after update-set for both set and non-set rules
${FROM_NS} ${BFCLI} chain set --from-str "chain test_xdp BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set blocked_ips (ip4.saddr) in {
        10.0.0.1
    }
    rule
        ip4.proto icmp
        (ip4.saddr) in blocked_ips
        counter
        DROP
    rule
        ip4.proto icmp
        counter
        DROP
"

(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --add ${HOST_IP_ADDR}

(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
${FROM_NS} ${BFCLI} chain update-set \
    --name test_xdp \
    --set-name blocked_ips \
    --add 10.0.0.2

counter=$(${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/test_xdp/bf_cmap | jq '.[0].values | map(.value.count) | add')
test "$counter" = "1"
counter=$(${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/test_xdp/bf_cmap | jq '.[1].values | map(.value.count) | add')
test "$counter" = "1"
${FROM_NS} ${BFCLI} chain flush --name test_xdp
