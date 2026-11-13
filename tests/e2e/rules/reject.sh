#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

HOST_BPFFS="${WORKDIR}/host_bpf"
HOST_BFCLI="bfcli --bpffs-path ${HOST_BPFFS}"

LISTENER_PID=

# The host-side bpffs and the listener are not part of the sandbox, remove
# them explicitly.
cleanup() {
    [ -n "${LISTENER_PID}" ] && kill ${LISTENER_PID} 2>/dev/null || true
    umount ${HOST_BPFFS} 2>/dev/null || true
    destroy_sandbox
}

make_sandbox

# REJECT is a rule-only verdict, and only XDP supports it
(! ${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_XDP{ifindex=${NS_IFINDEX}} REJECT")
(! ${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp REJECT")
(! ${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_NF_LOCAL_IN{family=inet4,priorities=100-200} ACCEPT rule ip4.proto icmp REJECT")
(! ${FROM_NS} ${BFCLI} chain set --from-str "chain c BF_HOOK_CGROUP_SKB_INGRESS{cgpath=/sys/fs/cgroup} ACCEPT rule ip4.proto icmp REJECT")

# Listen on the UDP and TCP port used below: without REJECT, the namespace
# would neither refuse the connection nor send an ICMP error.
${FROM_NS} python3 -c "
import socket, time
sockets = []
for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET6, kind)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.bind(('::', 9990))
    if kind == socket.SOCK_STREAM:
        s.listen()
    sockets.append(s)
open('${WORKDIR}/listening', 'w').close()
time.sleep(60)
" &
LISTENER_PID=$!
while [ ! -e ${WORKDIR}/listening ]; do sleep 0.1; done

# A veth only sends XDP_TX frames to its peer if the peer has NAPI enabled,
# which attaching an XDP program to the peer does.
mkdir ${HOST_BPFFS}
mount -t bpf bpf ${HOST_BPFFS}
${HOST_BFCLI} chain set --from-str "chain napi BF_HOOK_XDP{ifindex=${HOST_IFINDEX}} ACCEPT"

${FROM_NS} ${BFCLI} chain set --from-str "chain reject BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    rule ip4.proto icmp counter REJECT
    rule ip4.proto udp counter REJECT
    rule ip4.proto tcp counter REJECT"

# The original packets never reach the namespace: the replies come from REJECT
ping -c 1 -W 1 ${NS_IP_ADDR} | grep "Destination Port Unreachable"
test "$(get_counter reject 0)" = "1"

python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
s.connect(('${NS_IP_ADDR}', 9990))
s.send(b'x' * 64)
try:
    s.recv(1)
except ConnectionRefusedError:
    pass
else:
    raise SystemExit('no ICMP error received')
"
test "$(get_counter reject 1)" = "1"

python3 -c "
import socket
try:
    socket.create_connection(('${NS_IP_ADDR}', 9990), timeout=1)
except ConnectionRefusedError:
    pass
else:
    raise SystemExit('connection not refused')
"
test "$(get_counter reject 2)" = "1"

${FROM_NS} ${BFCLI} ruleset flush
${HOST_BFCLI} ruleset flush
