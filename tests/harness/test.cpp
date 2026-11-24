/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include "test.hpp"

#include <array>
#include <cinttypes>
#include <filesystem>
#include <map>

#include "Chain.hpp"
#include "FileDescriptor.hpp"

extern "C" {
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>

#include <arpa/inet.h>

#include <bpfilter/bpf.h>
#include <bpfilter/bpfilter.h>
#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/counter.h>
#include <bpfilter/flavor.h>
#include <bpfilter/rule.h>
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

namespace
{

/**
 * @brief Get the name of a counter, for failure messages.
 */
std::string _bft_counter_name(const bft::CounterId &id)
{
    // Same order as bft::CounterType
    static constexpr std::array names = {"policy", "error", "parser drop"};

    if (const auto *index = std::get_if<int>(&id))
        return "rule " + std::to_string(*index);

    return names.at(static_cast<size_t>(std::get<bft::CounterType>(id)));
}

/**
 * @brief Get the name of the verdict that `hook` returns as `value`, for
 * failure messages. If `value` is not a verdict, return it as a number.
 */
std::string _bft_verdict_name(enum bf_hook hook, int value)
{
    // Check NEXT last: most hooks return the same value for ACCEPT and NEXT
    if (value == bft_hook_accept(hook))
        return "ACCEPT";
    if (value == bft_hook_drop(hook))
        return "DROP";
    if (value == bft_hook_next(hook))
        return "NEXT";

    return std::to_string(value);
}

/**
 * @brief Get the value that a program on `hook` returns for `verdict`.
 */
int _bft_hook_verdict(enum bf_hook hook, enum bf_verdict verdict)
{
    switch (verdict) {
    case BF_VERDICT_ACCEPT:
        return bft_hook_accept(hook);
    case BF_VERDICT_DROP:
        return bft_hook_drop(hook);
    case BF_VERDICT_NEXT:
        return bft_hook_next(hook);
    default:
        fail_msg("no return value for verdict %s", bf_verdict_to_str(verdict));
    }
}

using CounterMap = std::map<bft::CounterId, struct bf_counter>;

/**
 * @brief Get the counters of the chain `name`.
 */
CounterMap _bft_get_counters(const std::string &name)
{
    _free_bf_chain_ struct bf_chain *chain = nullptr;
    _free_bf_hookopts_ struct bf_hookopts *hookopts = nullptr;

    assert_ok(bf_chain_get(name.c_str(), &chain, &hookopts));

    CounterMap counters = {
        {bft::CounterType::Policy, chain->policy_counters},
        {bft::CounterType::Error, chain->error_counters},
        {bft::CounterType::ParserDrop, chain->parser_drop_counters},
    };

    bf_list_foreach (&chain->rules, node) {
        const auto *rule =
            static_cast<const struct bf_rule *>(bf_list_node_get_data(node));

        if (rule->has_counters)
            counters.emplace(static_cast<int>(rule->index), rule->counters);
    }

    return counters;
}

/**
 * @brief Check the value of a counter after packet `index` on `hook`. Print a
 * mismatch.
 *
 * @return 1 on a mismatch, 0 otherwise.
 */
size_t _bft_check_counter(enum bf_hook hook, size_t index,
                          const bft::CounterId &id,
                          const struct bf_counter &value, uint64_t npkt,
                          uint64_t nbytes)
{
    if (value.count == npkt && value.size == nbytes)
        return 0;

    print_error("packet %zu on %s: %s counter: expected %" PRIu64
                " packets and %" PRIu64 " bytes, got %" PRIu64
                " packets and %" PRIu64 " bytes\n",
                index, bf_hook_to_str(hook), _bft_counter_name(id).c_str(),
                npkt, nbytes, value.count, value.size);

    return 1;
}

/**
 * @brief Check the counter values after packet `index`, of `pkt_len` bytes,
 * on `hook`. Print each mismatch.
 *
 * @return Number of mismatches.
 */
size_t _bft_check_counters(enum bf_hook hook, size_t index, CounterMap values,
                           const bft::Counters &expected, size_t pkt_len)
{
    size_t failures = 0;

    for (const auto &[id, npkt, nbytes]: expected) {
        const auto it = values.find(id);
        if (it == values.end()) {
            print_error("packet %zu on %s: chain has no %s counter\n", index,
                        bf_hook_to_str(hook), _bft_counter_name(id).c_str());
            ++failures;
            continue;
        }
        failures += _bft_check_counter(hook, index, id, it->second, npkt,
                                       nbytes.value_or(npkt * pkt_len));
    }

    if (!expected.exact)
        return failures;

    for (const auto &counter: expected)
        values.erase(counter.id);
    for (const auto &[id, counter]: values)
        failures += _bft_check_counter(hook, index, id, counter, 0, 0);

    return failures;
}

/**
 * @brief Run each packet of `packets` through a new copy of `chain`, and check
 * the verdict and the counter values. Print each mismatch.
 *
 * @return Number of mismatches.
 */
size_t _bft_check_prog_run(const bf::Chain &chain,
                           const std::vector<bft::PacketRun> &packets)
{
    const std::string name = chain.name();
    const enum bf_hook hook = chain.hook();
    size_t failures = 0;

    for (size_t i = 0; i < packets.size(); ++i) {
        const auto &[pkt, verdict, counters] = packets[i];

        BFT_CHAIN_SET(chain);

        const bft::FileDescriptor fd {bf_chain_prog_fd(name.c_str())};
        assert_fd(fd.get());

        const int r = _bft_prog_run_once(fd.get(), hook, pkt);
        if (r != _bft_hook_verdict(hook, verdict)) {
            print_error("packet %zu on %s: verdict: expected %s, got %s\n", i,
                        bf_hook_to_str(hook), bf_verdict_to_str(verdict),
                        _bft_verdict_name(hook, r).c_str());
            ++failures;
        }

        failures += _bft_check_counters(hook, i, _bft_get_counters(name),
                                        counters, pkt.len);

        assert_ok(bf_chain_flush(name.c_str()));
    }

    return failures;
}

} // namespace

void bft::assert_prog_run(const bf::Chain &chain,
                          const std::vector<bft::PacketRun> &packets)
{
    const size_t failures = _bft_check_prog_run(chain, packets);

    if (failures)
        fail_msg("%zu mismatches, see above", failures);
}

void bft::assert_prog_run(const std::vector<enum bf_hook> &hooks,
                          bf::Chain chain,
                          const std::vector<bft::PacketRun> &packets)
{
    size_t failures = 0;

    for (const auto hook: hooks) {
        chain.set_hook(hook);
        failures += _bft_check_prog_run(chain, packets);
    }

    if (failures)
        fail_msg("%zu mismatches, see above", failures);
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
