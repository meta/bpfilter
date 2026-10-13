/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include "test.hpp"

#include <filesystem>

extern "C" {
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>

#include <arpa/inet.h>

#include <bpfilter/bpf.h>
#include <bpfilter/bpfilter.h>
#include <bpfilter/flavor.h>
}

int bft_e2e_setup(void **state)
{
    char path[] = "/sys/fs/bpf/bftest_XXXXXX";
    int r;

    // A non-NULL cmocka group state overrides each test's initial_state.
    // bf_ctx_setup owns a copy of the path, so leave the group state unchanged.
    (void)state;

    if (!mkdtemp(path))
        return bf_err_r(-errno, "failed to create test BPF directory");

    r = bf_ctx_setup(false, path, 0);
    if (r)
        rmdir(path);

    return r;
}

int bft_e2e_teardown(void **state)
{
    const char *bpffs_path = bf_ctx_get_bpffs_path();
    std::error_code error;
    int r;

    (void)state;

    if (!bpffs_path)
        return 0;

    std::string path(bpffs_path);

    r = bf_ruleset_flush();
    bf_ctx_teardown();
    std::filesystem::remove_all(path, error);
    if (error && !r)
        r = bf_err_r(-error.value(), "failed to remove test BPF directory");

    return r;
}

/* Mimic the kernel's struct nf_hook_state layout for BPF_PROG_TEST_RUN
 * context. Only hook and pf are read by the kernel; all pointer fields
 * must be zero. */
struct nf_hook_state_ctx
{
    uint8_t hook;
    uint8_t pf;
    void *in;
    void *out;
    void *sk;
    void *net;
    int (*okfn)(void *, void *, void *);
};

static_assert(sizeof(nf_hook_state_ctx) == 48);

/**
 * @brief Run `pkt` once through the program `fd` attached to `hook`.
 *
 * See bft_assert_prog_run() for the per-hook input conventions.
 *
 * @return The program's return value (verdict), or a negative errno value.
 */
static int _bft_prog_run_once(int fd, enum bf_hook hook, const bft::Packet &pkt)
{
    if (bf_hook_to_flavor(hook) == BF_FLAVOR_NF) {
        struct nf_hook_state_ctx ctx = {};
        uint16_t ethertype;

        assert_true(pkt.len > ETH_HLEN);

        memcpy(&ethertype, pkt.data.data() + offsetof(struct ethhdr, h_proto),
               sizeof(ethertype));
        ethertype = ntohs(ethertype);

        ctx.hook = static_cast<uint8_t>(bf_hook_to_nf_hook(hook));
        ctx.pf = ethertype == 0x0800 ? NFPROTO_IPV4 : NFPROTO_IPV6;

        if (hook == BF_HOOK_NF_LOCAL_OUT) {
            return bf_bpf_prog_run(fd, pkt.data.data() + ETH_HLEN,
                                   pkt.len - ETH_HLEN, &ctx, sizeof(ctx));
        }

        return bf_bpf_prog_run(fd, pkt.data.data(), pkt.len, &ctx, sizeof(ctx));
    }

    return bf_bpf_prog_run(fd, pkt.data.data(), pkt.len, nullptr, 0);
}

void bft_assert_prog_run(const char *chain_name, enum bf_hook hook,
                         const bft::Packet &pkt, int expected)
{
    _cleanup_close_ int fd = -1;

    fd = bf_chain_prog_fd(chain_name);
    assert_true(fd >= 0);

    assert_int_equal(expected, _bft_prog_run_once(fd, hook, pkt));
}

size_t bft_prog_run_count(const char *chain_name, enum bf_hook hook,
                          const bft::Packet &pkt, size_t runs, int verdict)
{
    _cleanup_close_ int fd = -1;
    size_t count = 0;

    fd = bf_chain_prog_fd(chain_name);
    assert_true(fd >= 0);

    for (size_t i = 0; i < runs; ++i) {
        int r = _bft_prog_run_once(fd, hook, pkt);

        // Every run must end in one of the two verdicts the chain can produce.
        assert_true(r == bft_hook_accept(hook) || r == bft_hook_drop(hook));
        if (r == verdict)
            ++count;
    }

    return count;
}

int bft_capture_log(void *ctx, void *data, size_t size)
{
    auto *capture = static_cast<struct bft_log_capture *>(ctx);
    struct bf_log log = {};

    assert_int_equal(sizeof(log), size);
    std::memcpy(&log, data, sizeof(log));
    capture->entries.push_back(log);

    return 0;
}

void bft_assert_log_address(const uint8_t *actual, int family,
                            const char *expected)
{
    std::array<uint8_t, sizeof(struct in6_addr)> addr = {};
    size_t len = family == AF_INET ? sizeof(struct in_addr) : sizeof(addr);

    assert_int_equal(1, inet_pton(family, expected, addr.data()));
    assert_memory_equal(addr.data(), actual, len);
}

uint32_t bft_map_id(int fd)
{
    struct bpf_map_info info = {};

    assert_ok(bf_bpf_map_get_info(fd, &info));

    return info.id;
}

namespace
{
// TCX_PASS/TCX_DROP/TCX_NEXT are enum values in linux/bpf.h, but may conflict
// with the C++ compilation depending on kernel headers version. Use literals.
constexpr int kTcxPass = 0;
constexpr int kTcxDrop = 2;
constexpr int kTcxNext = -1;

static int _bft_verdict(enum bf_hook hook, enum bf_verdict verdict)
{
    switch (bf_hook_to_flavor(hook)) {
    case BF_FLAVOR_XDP:
        return verdict == BF_VERDICT_ACCEPT ? XDP_PASS : XDP_DROP;
    case BF_FLAVOR_TC:
        return verdict == BF_VERDICT_ACCEPT ? kTcxPass : kTcxDrop;
    case BF_FLAVOR_NF:
        return verdict == BF_VERDICT_ACCEPT ? NF_ACCEPT : NF_DROP;
    case BF_FLAVOR_CGROUP_SKB: // fallthrough
    case BF_FLAVOR_CGROUP_SOCK_ADDR:
        return verdict == BF_VERDICT_ACCEPT ? 1 : 0;
    default:
        return -ENOTSUP;
    }
}
} // namespace

int bft_hook_accept(enum bf_hook hook)
{
    return _bft_verdict(hook, BF_VERDICT_ACCEPT);
}

int bft_hook_drop(enum bf_hook hook)
{
    return _bft_verdict(hook, BF_VERDICT_DROP);
}

int bft_hook_next(enum bf_hook hook)
{
    switch (bf_hook_to_flavor(hook)) {
    case BF_FLAVOR_TC:
        return kTcxNext;
    case BF_FLAVOR_XDP:
        return XDP_PASS;
    case BF_FLAVOR_NF:
        return NF_ACCEPT;
    case BF_FLAVOR_CGROUP_SKB: // fallthrough
    case BF_FLAVOR_CGROUP_SOCK_ADDR:
        return 1;
    default:
        return -ENOTSUP;
    }
}

int bft_matcher_test_setup(void **state)
{
    (void)state;

    int r = bf_ruleset_flush();
    if (r != 0)
        return bf_err_r(r, "failed to flush ruleset in test setup");

    return 0;
}

int bft_matcher_test_teardown(void **state)
{
    (void)state;

    int r = bf_ruleset_flush();
    if (r != 0)
        return bf_err_r(r, "failed to flush ruleset in test teardown");

    return 0;
}
