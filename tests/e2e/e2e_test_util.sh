#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

set -eux

FROM_NS=

# Reserve a unique suffix for every invocation, including repeated runs of the
# same test. Eight characters keep the veth names within Linux's 15-byte limit.
WORKDIR=$(mktemp -d /tmp/bpfilter.e2e.XXXXXXXX)
_SHORT_ID=${WORKDIR##*.}
_TEST_HASH=$(printf '%s' "$_SHORT_ID" | cksum | awk '{print $1}')
_OCTET2=$(( (_TEST_HASH >> 8) & 0xFF ))
_OCTET3=$(( _TEST_HASH & 0xFF ))

NETNS_NAME="bftest_${_SHORT_ID}"
CGROUP_PATH="/sys/fs/cgroup/bftest_${_SHORT_ID}"
VETH_HOST="veth_h_${_SHORT_ID}"
VETH_NS="veth_n_${_SHORT_ID}"
HOST_IP="10.${_OCTET2}.${_OCTET3}.1/24"
NS_IP="10.${_OCTET2}.${_OCTET3}.2/24"
HOST_IP_ADDR="10.${_OCTET2}.${_OCTET3}.1"
NS_IP_ADDR="10.${_OCTET2}.${_OCTET3}.2"
HOST_IFINDEX=
NS_IFINDEX=

# Tested binaries
BFCLI=bfcli
RULESETS_DIR=.

################################################################################
#
# Setup
#
################################################################################

make_sandbox() {
    echo "Create the sandbox"

    # Disable selinux if available, not all distros enforce setlinux
    if command -v setenforce &> /dev/null; then
        setenforce 0 || true
    fi

    # Create the namespaces mount points
    mkdir ${WORKDIR}/{ns,bpf}
    mount --bind ${WORKDIR}/ns ${WORKDIR}/ns
    mount --make-private ${WORKDIR}/ns

    touch ${WORKDIR}/ns/{user,mnt}

    # Create the netns to be used by unshare
    ip netns add ${NETNS_NAME}

        unshare \
            --mount=${WORKDIR}/ns/mnt \
            --net=/var/run/netns/${NETNS_NAME} \
            --keep-caps \
        /bin/bash -c "
                set -e
                mount -t tmpfs tmpfs /run
            mount -t bpf bpf ${WORKDIR}/bpf
    "

    BFCLI="bfcli --bpffs-path ${WORKDIR}/bpf"

    FROM_NS="nsenter --mount=${WORKDIR}/ns/mnt --net=/var/run/netns/${NETNS_NAME}"

    # Create the veth
    ip link set lo up
    ip link add ${VETH_HOST} type veth peer name ${VETH_NS}
    ip link set ${VETH_NS} netns ${NETNS_NAME}

    # Set IP addresses
    ip addr add ${HOST_IP} dev ${VETH_HOST}
    ip netns exec ${NETNS_NAME} ip addr add ${NS_IP} dev ${VETH_NS}

    # Bring everything up
    ip link set ${VETH_HOST} up
    ip netns exec ${NETNS_NAME} ip link set ${VETH_NS} up
    ip netns exec ${NETNS_NAME} ip link set lo up

    # Log environment details
    HOST_IFINDEX=$(ip -o link show ${VETH_HOST} | awk '{print $1}' | cut -d: -f1)
    NS_IFINDEX=$(ip netns exec ${NETNS_NAME} ip -o link show ${VETH_NS} | awk '{print $1}' | cut -d: -f1)

    echo "End-to-end test configuration:"
    echo "  Workdir: ${WORKDIR}"
    echo "  Network interfaces:"
    echo "    ${HOST_IFINDEX}: ${VETH_HOST} @ ${HOST_IP_ADDR}"
    echo "    ${NS_IFINDEX}: ${VETH_NS} @ ${NS_IP_ADDR}"
    echo "  Tested binaries"
    echo "    bfcli: ${BFCLI}"
    echo "    rulesets-dir: ${RULESETS_DIR}"
}

destroy_sandbox() {
    echo "Cleanup the sandbox"

    # Remove the veth pair even if setup failed before moving the peer.
    ip link delete "${VETH_HOST}" 2>/dev/null || true

    # netns should be unmounted AND deleted
    umount /var/run/netns/${NETNS_NAME} || true
    ip netns delete ${NETNS_NAME} || true

        umount ${WORKDIR}/bpf || true
        umount ${WORKDIR}/ns/mnt || true
    umount ${WORKDIR}/ns || true

    ip link del ${VETH_HOST} 2>/dev/null || true
    rmdir ${CGROUP_PATH} 2>/dev/null || true
    rm -rf ${WORKDIR} || true
}

cleanup() {
    destroy_sandbox
}

# Set trap to ensure cleanup happens
trap 'ret=$?; cleanup; exit ${ret}' EXIT
trap 'cleanup 1; exit 1' INT TERM


################################################################################
#
# Testing
#
################################################################################

# Print the packet counter of rule INDEX in chain NAME, read from the chain's
# pinned counters map.
#
# Usage: get_counter NAME INDEX
get_counter() {
    ${FROM_NS} bpftool map dump pinned ${WORKDIR}/bpf/bpfilter/$1/bf_cmap | jq ".[$2].values | map(.value.count) | add"
}

# Join the test cgroup, then send one UDP packet to address $2 from a new
# socket of family $1. An AF_INET6 socket has IPV6_V6ONLY turned off, so it
# sends IPv4 packets to ::ffff:a.b.c.d addresses. The 64-byte payload makes the
# packet longer than an IPv6 header, so a program that wrongly reads it as IPv6
# still reaches the rule instead of accepting it early as too short.
udp_send() {
    ${FROM_NS} python3 -c "
import os, socket
with open('${CGROUP_PATH}/cgroup.procs', 'w') as f:
    f.write(str(os.getpid()))
s = socket.socket(socket.$1, socket.SOCK_DGRAM)
if s.family == socket.AF_INET6:
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.sendto(b'x' * 64, ('$2', 9990))
s.close()
"
}
