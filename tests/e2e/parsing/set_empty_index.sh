#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

# Regression test for set index mismatch when empty sets precede non-empty sets.
#
# Sets are indexed by position in chain->sets. The matcher payload stores this
# index, which is used by BF_FIXUP_TYPE_SET_MAP_FD to resolve the map fd from
# handle->sets. If _bf_codegen_load_sets_maps skips empty sets without
# preserving their index slot, subsequent non-empty sets end up at wrong
# positions in handle->sets, causing fixup resolution to fail or resolve the
# wrong map.

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox

# empty_first: chain->sets[0], empty (skipped during map creation)
# active_second: chain->sets[1], non-empty
# The rule's matcher stores set_index=1 for active_second.
# If handle->sets doesn't preserve index correspondence, the fixup for
# set_index=1 will be out of bounds (handle->sets only has 1 entry at
# index 0).
${FROM_NS} ${BFCLI} chain set --from-str "chain test BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
    set empty_first (ip4.saddr) in {}
    set active_second (ip4.saddr) in { ${HOST_IP_ADDR} }
    rule (ip4.saddr) in active_second counter DROP"

# Verify filtering: HOST_IP_ADDR should match active_second and be dropped.
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
