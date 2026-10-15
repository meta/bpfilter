#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
# Confirm connectivity and populate neighbor entries before testing DROP.
ping -c 1 -W 0.1 ${NS_IP_ADDR}

# Set-map, logging and counter fixups remain valid when the suffix is omitted.
${FROM_NS} ${BFCLI} chain set --from-str \
    "chain c BF_HOOK_XDP{ifindex=${NS_IFINDEX}} NEXT \
     set s (ip4.daddr) in {} \
     rule meta.l3_proto not ipv4 NEXT \
     rule (ip4.daddr) in s counter DROP \
     rule (tcp.dport) not in {} (ip4.saddr) in { ${HOST_IP_ADDR} } NEXT \
     rule counter CONTINUE \
     rule counter log DROP \
     rule counter CONTINUE"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
test "$(get_counter c 3)" -gt 0
test "$(get_counter c 4)" -gt 0
test "$(get_counter c 5)" = "0"
# Counter 6 belongs to the chain policy, after the six rules.
test "$(get_counter c 6)" = "0"

# Adding a condition to DROP restores the original suffix and policy.
${FROM_NS} ${BFCLI} chain update --from-str \
    "chain c BF_HOOK_XDP{ifindex=${NS_IFINDEX}} NEXT \
     set s (ip4.daddr) in {} \
     rule meta.l3_proto not ipv4 NEXT \
     rule (ip4.daddr) in s counter DROP \
     rule (tcp.dport) not in {} (ip4.saddr) in { ${HOST_IP_ADDR} } NEXT \
     rule counter CONTINUE \
     rule ip4.proto tcp counter log DROP \
     rule counter CONTINUE"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
test "$(get_counter c 5)" -gt 0
test "$(get_counter c 6)" -gt 0

# Comparison no-ops also terminate without emitting the suffix or policy.
for matcher in '(meta.sport) not in {}' 'meta.probability eq 100%'; do
    ${FROM_NS} ${BFCLI} chain set --from-str \
        "chain c BF_HOOK_XDP{ifindex=${NS_IFINDEX}} NEXT \
         rule meta.l3_proto not ipv4 NEXT \
         rule $matcher counter DROP \
         rule NEXT"
    (! ping -c 1 -W 0.1 ${NS_IP_ADDR})
done

${FROM_NS} ${BFCLI} ruleset flush
