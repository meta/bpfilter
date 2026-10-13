/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <algorithm>
#include <climits>
#include <cstring>
#include <iostream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "Packet.hpp"
#include "bpfilter/flavor.h"

extern "C" {
// clang-format off
#include <stdarg.h> // NOLINT: required by cmocka.h
#include <stddef.h> // NOLINT: required by cmocka.h
#include <stdint.h> // NOLINT: required by cmocka.h
#include <setjmp.h> // NOLINT: required by cmocka.h
#include <cmocka.h> // NOLINT: required by cmocka.h
// clang-format on

#include <linux/if_ether.h>

#include <arpa/inet.h>

#include <bpfilter/bpf.h>
#include <bpfilter/bpfilter.h>
#include <bpfilter/ctx.h>
#include <bpfilter/hook.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>
#include <bpfilter/runtime.h>
#include <bpfilter/verdict.h>

#include "test.h"
}

/** @brief Per-test setup: flush the ruleset so each test starts clean. */
int bft_matcher_test_setup(void **state);

/** @brief Per-test teardown: flush the ruleset to clean up after the test. */
int bft_matcher_test_teardown(void **state);

/** @brief Set up an end-to-end test group with a unique BPF directory. */
int bft_e2e_setup(void **state);

/** @brief Flush the test group's ruleset and remove its BPF directory. */
int bft_e2e_teardown(void **state);

/**
 * @brief Build a chain from a `bf::Chain` expression, install it, and assert
 * success.
 *
 * Usage: `BFT_CHAIN_SET(bf::Chain("name", hook, policy) << rule1 << rule2);`
 */
#define BFT_CHAIN_SET(chain_expr)                                              \
    do {                                                                       \
        auto _bft_chain = (chain_expr).get();                                  \
        assert_int_equal(0, bf_chain_set(_bft_chain.get(), nullptr));          \
    } while (0)

/**
 * @brief Run a packet through a chain's BPF program and assert the return
 * value.
 *
 * BPF_PROG_TEST_RUN requires different inputs depending on the hook type:
 * - XDP/TC: raw L2 packet data, no context.
 * - cgroup_skb: raw L2 packet data, no context.
 * - NF (LOCAL_OUT): L3 packet data (no Ethernet header) + nf_hook_state
 *   context with pf and hook fields. The kernel sets skb->protocol from pf.
 * - NF (all others): L2 packet data (with Ethernet header) + nf_hook_state
 *   context. The kernel calls eth_type_trans() to consume the Ethernet header
 *   and validates that the ethertype matches pf.
 */
void bft_assert_prog_run(const char *chain_name, enum bf_hook hook,
                         const bft::Packet &pkt, int expected);

/**
 * @brief Run a packet through a chain's BPF program `runs` times and count
 * the runs that returned `verdict`.
 *
 * Same input conventions as bft_assert_prog_run(). Intended for matchers
 * whose result is random per run (e.g. meta.probability), where a single
 * verdict is not meaningful but the match rate over many runs is.
 *
 * @return Number of runs (out of `runs`) that returned `verdict`.
 */
size_t bft_prog_run_count(const char *chain_name, enum bf_hook hook,
                          const bft::Packet &pkt, size_t runs, int verdict);

struct bft_log_capture
{
    std::vector<struct bf_log> entries;
};

int bft_capture_log(void *ctx, void *data, size_t size);

void bft_assert_log_address(const uint8_t *actual, int family,
                            const char *expected);

/** @brief Get the ID of the BPF map referred to by `fd`. */
uint32_t bft_map_id(int fd);

/**
 * @brief Encode a port number as a 2-byte big-endian payload.
 *
 * Produces the wire encoding expected by TCP/UDP/meta sport and dport
 * matchers.
 */
static inline std::vector<uint8_t> bft_port_be(uint16_t port)
{
    uint16_t net = htobe16(port);
    auto *ptr = reinterpret_cast<uint8_t *>(&net);
    return {ptr[0], ptr[1]};
}

/**
 * @brief Encode a port range [min, max] as a 4-byte host-order payload.
 *
 * Both bounds are consecutive uint16_t values in host byte order, as
 * expected by BF_MATCHER_RANGE for port matchers.
 */
static inline std::vector<uint8_t> bft_port_range(uint16_t min, uint16_t max)
{
    std::vector<uint8_t> payload(sizeof(min) * 2);
    std::memcpy(payload.data(), &min, sizeof(min));
    std::memcpy(payload.data() + sizeof(min), &max, sizeof(max));
    return payload;
}

/**
 * @brief Encode a uint16_t as a 2-byte host-order payload.
 */
static inline std::vector<uint8_t> bft_u16_payload(uint16_t val)
{
    std::vector<uint8_t> payload(sizeof(val));
    std::memcpy(payload.data(), &val, sizeof(val));
    return payload;
}

/**
 * @brief Encode a uint32_t as a 4-byte host-order payload.
 */
static inline std::vector<uint8_t> bft_u32_payload(uint32_t val)
{
    std::vector<uint8_t> payload(sizeof(val));
    std::memcpy(payload.data(), &val, sizeof(val));
    return payload;
}

/**
 * @brief Encode a uint32_t range [min, max] as an 8-byte host-order payload.
 *
 * Both bounds are consecutive uint32_t values in host byte order, as
 * expected by BF_MATCHER_RANGE for 32-bit matchers.
 */
static inline std::vector<uint8_t> bft_u32_range(uint32_t min, uint32_t max)
{
    std::vector<uint8_t> payload(sizeof(min) * 2);
    std::memcpy(payload.data(), &min, sizeof(min));
    std::memcpy(payload.data() + sizeof(min), &max, sizeof(max));
    return payload;
}

/**
 * @brief Encode a float as a 4-byte payload.
 */
static inline std::vector<uint8_t> bft_float_payload(float val)
{
    std::vector<uint8_t> payload(sizeof(val));
    std::memcpy(payload.data(), &val, sizeof(val));
    return payload;
}

/**
 * @brief Convert an IPv6 address string to a 16-byte payload.
 */
static inline std::vector<uint8_t> bft_ipv6_addr(const char *str)
{
    struct in6_addr in6;

    if (inet_pton(AF_INET6, str, &in6) != 1)
        throw std::invalid_argument(str);
    auto *ptr = reinterpret_cast<uint8_t *>(&in6);
    return {ptr, ptr + sizeof(in6)};
}

/**
 * @brief Build a bf_ip4_lpm_key payload for IPv4 subnet matchers.
 *
 * @param prefixlen Prefix length (0–32).
 * @param oct0,oct1,oct2,oct3 Network address octets in presentation order.
 */
static inline std::vector<uint8_t> bft_ip4_lpm_key(uint32_t prefixlen,
                                                   uint8_t oct0, uint8_t oct1,
                                                   uint8_t oct2, uint8_t oct3)
{
    struct bf_ip4_lpm_key key = {};
    key.prefixlen = prefixlen;
    std::array<uint8_t, 4> addr = {oct0, oct1, oct2, oct3};
    std::memcpy(&key.data, addr.data(), addr.size());
    auto *ptr = reinterpret_cast<uint8_t *>(&key);
    return {ptr, ptr + sizeof(key)};
}

/**
 * @brief Build a bf_ip6_lpm_key payload for IPv6 subnet matchers.
 *
 * @param prefixlen Prefix length (0–128).
 * @param net Network address as a colon-hex string.
 */
static inline std::vector<uint8_t> bft_ip6_lpm_key(uint32_t prefixlen,
                                                   const char *net)
{
    struct bf_ip6_lpm_key key = {};
    key.prefixlen = prefixlen;
    inet_pton(AF_INET6, net, key.data);
    auto *ptr = reinterpret_cast<uint8_t *>(&key);
    return {ptr, ptr + sizeof(key)};
}

class MatcherTest
{
private:
    std::string _name;
    enum bf_matcher_type _type;
    enum bf_hook _hook;
    enum bf_matcher_op _op;
    void (*_callback)(void **state);

    void genName()
    {
        _name = std::string(bf_matcher_type_to_str(_type)) + "." +
                bf_matcher_op_to_str(_op) + "[" + bf_hook_to_str(_hook) + "]";
    }

public:
    MatcherTest(enum bf_matcher_type type, enum bf_matcher_op op,
                void (*callback)(void **state),
                enum bf_hook hook = _BF_HOOK_MAX):
        _type {type},
        _hook {hook},
        _op {op},
        _callback {callback}
    {
        genName();
    }

    virtual ~MatcherTest() = default;

    [[nodiscard]] enum bf_hook hook() const
    {
        return _hook;
    }

    [[nodiscard]] enum bf_matcher_op op() const
    {
        return _op;
    }

    [[nodiscard]] void (*callback() const)(void **state)
    {
        return _callback;
    }

    [[nodiscard]] int verdictAccept() const
    {
        return bft_hook_accept(_hook);
    }

    [[nodiscard]] int verdictDrop() const
    {
        return bft_hook_drop(_hook);
    }

    [[nodiscard]] const std::string &name() const
    {
        return _name;
    }

    void setHook(enum bf_hook hook)
    {
        _hook = hook;
        genName();
    }

    void print() const
    {
        std::cout << _name << "\n";
    }
};

class MatcherTestsSuite
{
private:
    enum bf_matcher_type _type;
    const struct bf_matcher_meta *_meta;
    std::set<std::pair<enum bf_hook, enum bf_matcher_op>> _check;
    std::vector<MatcherTest> _tests;

public:
    MatcherTestsSuite(enum bf_matcher_type type):
        _type {type},
        _meta {bf_matcher_get_meta(type)}
    {
        assert_non_null(_meta);

        for (auto hook = static_cast<bf_hook>(0); hook < _BF_HOOK_MAX;
             hook = static_cast<bf_hook>(hook + 1)) {
            if ((_meta->unsupported_hooks & BF_FLAG(hook)) != 0U)
                continue;

            // CGROUP_SOCK_ADDR programs don't support BPF_PROG_TEST_RUN
            if (bf_hook_to_flavor(hook) == BF_FLAVOR_CGROUP_SOCK_ADDR)
                continue;

            for (auto op = static_cast<enum bf_matcher_op>(0);
                 op < _BF_MATCHER_OP_MAX;
                 op = static_cast<bf_matcher_op>(op + 1)) {
                if (_meta->ops[op].parse == nullptr)
                    continue;

                _check.insert({hook, op});
            }
        }
    }

    MatcherTestsSuite &operator<<(MatcherTest &&test)
    {
        std::vector<std::pair<enum bf_hook, enum bf_matcher_op>> new_tests;

        // bf_hook_to_flavor() doesn't allow invalid hooks.
        if (test.hook() != _BF_HOOK_MAX &&
            bf_hook_to_flavor(test.hook()) == BF_FLAVOR_CGROUP_SOCK_ADDR) {
            bf_warn(
                "BF_FLAVOR_CGROUP_SOCK_ADDR hooks are not supported by MatcherTestsSuite, ignoring");
            return *this;
        }

        std::ranges::copy_if(_check, std::back_inserter(new_tests),
                             [&test](const auto &pair) {
                                 return pair.second == test.op() &&
                                        (test.hook() == _BF_HOOK_MAX ||
                                         test.hook() == pair.first);
                             });

        for (const auto &pair: new_tests) {
            auto actual_test = test;

            actual_test.setHook(pair.first);

            _tests.push_back(std::move(actual_test));
            _check.erase(pair);
        }

        return *this;
    }

    /**
     * @brief cmocka test verifying all supported (hook, op) pairs have a
     * registered test. Receives a pointer to the residual @c _check set as
     * state; fails if the set is non-empty, listing each uncovered pair.
     */
    static void _coverage_check(void **state)
    {
        using CheckSet = std::set<std::pair<enum bf_hook, enum bf_matcher_op>>;
        const auto *check = static_cast<const CheckSet *>(*state);

        for (const auto &[hook, op]: *check) {
            print_error("missing e2e.matchers test: %s for '%s'\n",
                        bf_hook_to_str(hook), bf_matcher_op_to_str(op));
        }

        assert_true(check->empty());
    }

    int run()
    {
        std::vector<CMUnitTest> tests;
        tests.reserve(_tests.size() + 1);

        tests.push_back(
            CMUnitTest {.name = "coverage",
                        .test_func = _coverage_check,
                        .setup_func = nullptr,
                        .teardown_func = nullptr,
                        .initial_state = static_cast<void *>(&_check)});

        for (auto &test: _tests) {
            tests.push_back(
                CMUnitTest {.name = test.name().c_str(),
                            .test_func = test.callback(),
                            .setup_func = bft_matcher_test_setup,
                            .teardown_func = bft_matcher_test_teardown,
                            .initial_state = static_cast<void *>(&test)});
        }

        return _cmocka_run_group_tests(bf_matcher_type_to_str(_type),
                                       tests.data(), tests.size(),
                                       bft_e2e_setup, bft_e2e_teardown);
    }
};
