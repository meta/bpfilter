#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

mkdir -p ${CGROUP_PATH}

# Join the test cgroup, then connect a new UDP socket of family $1 to
# 127.0.0.1:9990 with a sockaddr_in. Python only passes a sockaddr_in for
# AF_INET sockets, so call connect() through ctypes.
udp_connect() {
    ${FROM_NS} python3 -c "
import ctypes, os, socket, struct
with open('${CGROUP_PATH}/cgroup.procs', 'w') as f:
    f.write(str(os.getpid()))
s = socket.socket(socket.$1, socket.SOCK_DGRAM)
if s.family == socket.AF_INET6:
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
sin = struct.pack('=H', socket.AF_INET) + struct.pack('!H4s8x', 9990, socket.inet_aton('127.0.0.1'))
if ctypes.CDLL(None, use_errno=True).connect(s.fileno(), sin, len(sin)):
    raise OSError(ctypes.get_errno(), 'connect')
"
}

# Rule 0 drops and counts every IPv6 call, rule 1 every IPv4 call to 127.0.0.1.
${FROM_NS} ${BFCLI} chain set --from-str "chain sendmsg BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.l3_proto eq ipv6 counter DROP rule ip4.daddr eq 127.0.0.1 counter DROP"
${FROM_NS} ${BFCLI} chain set --from-str "chain connect BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.l3_proto eq ipv6 counter DROP rule ip4.daddr eq 127.0.0.1 counter DROP"

# Control: an IPv4 socket sends to 127.0.0.1. Rule 1 drops it, so sendto()
# fails with EPERM.
(! udp_send AF_INET 127.0.0.1)
test "$(get_counter sendmsg 1)" = "1"

# An IPv6 socket sending to ::ffff:127.0.0.1 also sends to 127.0.0.1 over
# IPv4: rule 0 must not match it, and rule 1 must drop it.
(! udp_send AF_INET6 ::ffff:127.0.0.1)
test "$(get_counter sendmsg 0)" = "0"
test "$(get_counter sendmsg 1)" = "2"

# Control: an IPv4 socket connects to 127.0.0.1. Rule 1 drops it, so connect()
# fails with EPERM.
(! udp_connect AF_INET)
test "$(get_counter connect 1)" = "1"

# An IPv6 socket connecting with a sockaddr_in also goes through the CONNECT4
# hook: rule 0 must not match it, and rule 1 must drop it.
(! udp_connect AF_INET6)
test "$(get_counter connect 0)" = "0"
test "$(get_counter connect 1)" = "2"
