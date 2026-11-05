#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

mkdir -p ${CGROUP_PATH}

# Rule 0 drops and counts every IPv6 packet, rule 1 every IPv4 packet sent to
# 127.0.0.1.
${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SKB_EGRESS{cgpath=${CGROUP_PATH}} ACCEPT rule meta.l3_proto eq ipv6 counter DROP rule ip4.daddr eq 127.0.0.1 counter DROP"

# Control: an IPv4 socket sends an IPv4 packet to 127.0.0.1. Rule 1 drops it,
# so sendto() fails with EPERM.
(! udp_send AF_INET 127.0.0.1)
test "$(get_counter c 1)" = "1"

# An IPv6 socket sending to ::ffff:127.0.0.1 also sends an IPv4 packet to
# 127.0.0.1: rule 0 must not match it, and rule 1 must drop it.
(! udp_send AF_INET6 ::ffff:127.0.0.1)
test "$(get_counter c 0)" = "0"
test "$(get_counter c 1)" = "2"

# An IPv6 socket sending to ::1 sends an IPv6 packet, so rule 0 drops it.
(! udp_send AF_INET6 ::1)
test "$(get_counter c 0)" = "1"

${FROM_NS} ${BFCLI} chain flush --name c

# An IPv6 socket bound to [::]:9990 receives the IPv4 packets sent to
# 127.0.0.1:9990. The ingress rule must drop them, so recv() times out.
${FROM_NS} ${BFCLI} chain set --from-str "chain i BF_HOOK_CGROUP_SKB_INGRESS{cgpath=${CGROUP_PATH}} ACCEPT rule ip4.saddr eq 127.0.0.1 counter DROP"
${FROM_NS} python3 -c "
import os, socket
with open('${CGROUP_PATH}/cgroup.procs', 'w') as f:
    f.write(str(os.getpid()))
r = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
r.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
r.bind(('::', 9990))
r.settimeout(0.5)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'x' * 64, ('127.0.0.1', 9990))
try:
    r.recv(64)
    raise SystemExit('the IPv4 packet was not dropped on ingress')
except socket.timeout:
    pass
"
test "$(get_counter i 0)" = "1"
