/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/if_ether.h>

#include <utility>

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "test.hpp"

extern "C" {
#include <bpfilter/bpfilter.h>
}

static bft::Packet tagged_ethernet(size_t count)
{
    auto pkt = bft::Packet {} / bft::Ethernet {};

    for (size_t i = 0; i < count; ++i)
        pkt = std::move(pkt) / bft::VLAN {.ether_type = i % 2 ?
                                                            bft::VLAN::k8021AD :
                                                            bft::VLAN::k8021Q};

    return pkt;
}

static void vlan_depth(void **state)
{
    const auto tcp = bft::Ethernet {} / bft::IPv4 {} / bft::TCP {.dport = 80};
    const auto udp = bft::Ethernet {} / bft::IPv6 {} / bft::UDP {.dport = 53};
    const auto single = tagged_ethernet(1) / bft::IPv4 {} / bft::TCP {};
    const auto tcp_max = tagged_ethernet(16) / bft::IPv4 {} / bft::TCP {};
    const auto udp_max = tagged_ethernet(16) / bft::IPv6 {} / bft::UDP {};
    const auto over_limit = tagged_ethernet(17) / bft::IPv4 {} / bft::TCP {};
    auto truncated = single;
    truncated.len = ETH_HLEN + 3;

    (void)state;

    for (auto hook: {BF_HOOK_XDP, BF_HOOK_TC_INGRESS}) {
        _free_bf_chain_ struct bf_chain *chain = nullptr;
        _free_bf_hookopts_ struct bf_hookopts *hookopts = nullptr;
        constexpr auto name = "vlan_depth";
        const int drop = bft_hook_drop(hook);

        assert_ok(bf_ruleset_flush());
        BFT_CHAIN_SET(bf::Chain(name, hook, BF_VERDICT_ACCEPT)
                      << bf::Rule(BF_VERDICT_DROP,
                                  {bf::Matcher(BF_MATCHER_TCP_DPORT,
                                               BF_MATCHER_EQ, bft_port_be(80))},
                                  bf_counter())
                      << bf::Rule(BF_VERDICT_DROP,
                                  {bf::Matcher(BF_MATCHER_UDP_DPORT,
                                               BF_MATCHER_EQ, bft_port_be(53))},
                                  bf_counter()));

        bft_assert_prog_run(name, hook, tcp, drop);
        bft_assert_prog_run(name, hook, udp, drop);
        bft_assert_prog_run(name, hook, single, drop);
        bft_assert_prog_run(name, hook, tcp_max, drop);
        bft_assert_prog_run(name, hook, udp_max, drop);
        bft_assert_prog_run(name, hook, over_limit, drop);
        bft_assert_prog_run(name, hook, truncated, drop);

        bft_assert_counter_eq(name, 0, 3, -1);
        bft_assert_counter_eq(name, 1, 2, -1);
        assert_ok(bf_chain_get(name, &chain, &hookopts));
        assert_int_equal(chain->parser_drop_counters.count, 2);
        assert_int_equal(chain->parser_drop_counters.size,
                         over_limit.len + truncated.len);
    }
}

int main()
{
    const CMUnitTest tests[] = {cmocka_unit_test(vlan_depth)};

    return cmocka_run_group_tests(tests, bft_e2e_setup, bft_e2e_teardown);
}
