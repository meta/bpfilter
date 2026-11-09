/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include <cstring>
#include <vector>

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "test.hpp"

extern "C" {
#include <linux/if_ether.h>

#include <arpa/inet.h>
#include <bpf/libbpf.h>

#include <bpfilter/bpfilter.h>
#include <bpfilter/runtime.h>
}

namespace
{

constexpr uint8_t kTupleLog = BF_FLAG(BF_LOG_OPT_5_TUPLE);

static void assertTuple(const struct bf_log &log, uint16_t l3Proto,
                        uint8_t l4Proto, const char *saddr, const char *daddr,
                        uint16_t sport, uint16_t dport)
{
    int family = l3Proto == ETH_P_IP ? AF_INET : AF_INET6;

    assert_int_equal(BF_LOG_TYPE_PACKET_5_TUPLE, log.log_type);
    assert_int_equal(l3Proto, log.l3_proto);
    assert_int_equal(l4Proto, log.l4_proto);
    assert_int_equal(0, log.rule_id);
    assert_int_equal(BF_VERDICT_DROP, log.verdict);
    bft_assert_log_address(log.pkt_5_tuple.saddr, family, saddr);
    bft_assert_log_address(log.pkt_5_tuple.daddr, family, daddr);
    assert_int_equal(sport, log.pkt_5_tuple.sport);
    assert_int_equal(dport, log.pkt_5_tuple.dport);
}

static void tupleLogging(void **state)
{
    _cleanup_close_ int fd = -1;
    struct bft_log_capture capture;
    struct ring_buffer *rb;

    (void)state;

    BFT_CHAIN_SET(bf::Chain("test_tuple_log", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, bf_counter(), kTupleLog,
                              {bf::Matcher::alwaysMatch()}));

    fd = bf_chain_logs_fd("test_tuple_log");
    assert_true(fd >= 0);
    rb = ring_buffer__new(fd, bft_capture_log, &capture, nullptr);
    assert_non_null(rb);

    bft_assert_prog_run(
        "test_tuple_log", BF_HOOK_XDP,
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.10", .daddr = "198.51.100.20"} /
            bft::TCP {.sport = 12345, .dport = 443},
        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assertTuple(capture.entries.back(), ETH_P_IP, IPPROTO_TCP, "192.0.2.10",
                "198.51.100.20", 12345, 443);

    bft_assert_prog_run(
        "test_tuple_log", BF_HOOK_XDP,
        bft::Ethernet() /
            bft::IPv4 {.saddr = "203.0.113.1", .daddr = "203.0.113.2"} /
            bft::UDP {.sport = 5353, .dport = 53},
        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assertTuple(capture.entries.back(), ETH_P_IP, IPPROTO_UDP, "203.0.113.1",
                "203.0.113.2", 5353, 53);

    bft_assert_prog_run(
        "test_tuple_log", BF_HOOK_XDP,
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8::10", .daddr = "2001:db8::20"} /
            bft::TCP {.sport = 22, .dport = 60000},
        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assertTuple(capture.entries.back(), ETH_P_IPV6, IPPROTO_TCP, "2001:db8::10",
                "2001:db8::20", 22, 60000);

    bft_assert_prog_run(
        "test_tuple_log", BF_HOOK_XDP,
        bft::Ethernet() /
            bft::IPv6 {.saddr = "2001:db8:1::1", .daddr = "2001:db8:1::2"} /
            bft::UDP {.sport = 10000, .dport = 20000},
        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assertTuple(capture.entries.back(), ETH_P_IPV6, IPPROTO_UDP,
                "2001:db8:1::1", "2001:db8:1::2", 10000, 20000);

    /* Unsupported transport protocols still receive the rule verdict and are
     * counted, but do not emit a log entry. */
    bft_assert_prog_run("test_tuple_log", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} / bft::ICMPv4 {},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(0, ring_buffer__consume(rb));
    assert_int_equal(4, capture.entries.size());

    bft::Packet arp;
    arp.len = bft::Ethernet().write(arp.data.data(), ETH_P_ARP);
    bft_assert_prog_run("test_tuple_log", BF_HOOK_XDP, arp,
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(0, ring_buffer__consume(rb));
    assert_int_equal(4, capture.entries.size());
    bft_assert_counter_eq("test_tuple_log", 0, 6, -1);

    ring_buffer__free(rb);
}

static void rawLoggingUnchanged(void **state)
{
    struct bft_log_capture capture;
    struct ring_buffer *rb;

    (void)state;

    for (auto hook: {BF_HOOK_XDP, BF_HOOK_TC_INGRESS, BF_HOOK_NF_LOCAL_IN,
                     BF_HOOK_CGROUP_SKB_INGRESS}) {
        _cleanup_close_ int fd = -1;

        BFT_CHAIN_SET(bf::Chain("test_raw_log", hook, BF_VERDICT_ACCEPT)
                      << bf::Rule(BF_VERDICT_DROP, std::nullopt,
                                  BF_LOG_OPT_DEFAULT,
                                  {bf::Matcher::alwaysMatch()}));

        fd = bf_chain_logs_fd("test_raw_log");
        assert_true(fd >= 0);
        rb = ring_buffer__new(fd, bft_capture_log, &capture, nullptr);
        assert_non_null(rb);

        for (const auto &pkt: {
                 bft::Ethernet() / bft::IPv4 {} / bft::TCP {},
                 bft::Ethernet() / bft::IPv6 {} / bft::UDP {},
             }) {
            bool ipv4 = pkt.data[ETH_HLEN] >> 4 == 4;
            size_t l3Size = ipv4 ? bft::IPv4::size() : bft::IPv6::size();
            size_t l4Size = ipv4 ? bft::TCP::size() : bft::UDP::size();
            bool hasL2 = hook == BF_HOOK_XDP || hook == BF_HOOK_TC_INGRESS;

            bft_assert_prog_run("test_raw_log", hook, pkt, bft_hook_drop(hook));
            assert_int_equal(1, ring_buffer__consume(rb));
            const auto &log = capture.entries.back();
            assert_int_equal(BF_LOG_TYPE_PACKET, log.log_type);
            assert_int_equal(BF_LOG_PACKET_HEADERS, log.pkt.req_headers);
            assert_int_equal(BF_LOG_PACKET_HEADERS &
                                 ~(hasL2 ? 0 : BF_FLAG(BF_LOG_OPT_LINK)),
                             log.pkt.headers);
            if (hasL2)
                assert_memory_equal(pkt.data.data(), log.pkt.l2hdr, ETH_HLEN);
            assert_memory_equal(pkt.data.data() + ETH_HLEN, log.pkt.l3hdr,
                                l3Size);
            assert_memory_equal(pkt.data.data() + ETH_HLEN + l3Size,
                                log.pkt.l4hdr, l4Size);
        }

        ring_buffer__free(rb);
    }
}

static void tupleLogRateEligibility(void **state)
{
    _cleanup_close_ int fd = -1;
    struct bft_log_capture capture;
    struct ring_buffer *rb;
    // 10^9 seconds, far beyond the host's uptime.
    bf::Rule rule(BF_VERDICT_DROP, bf_counter(), kTupleLog,
                  {bf::Matcher::alwaysMatch()}, 1'000'000'000'000'000'000ULL);

    (void)state;

    BFT_CHAIN_SET(
        bf::Chain("test_tuple_log_rate", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
        << rule);

    fd = bf_chain_logs_fd("test_tuple_log_rate");
    assert_true(fd >= 0);
    rb = ring_buffer__new(fd, bft_capture_log, &capture, nullptr);
    assert_non_null(rb);

    bft_assert_prog_run("test_tuple_log_rate", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} / bft::ICMPv4 {},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(0, ring_buffer__consume(rb));

    /* The ignored ICMP packet must not consume the rate-limit interval. */
    bft_assert_prog_run("test_tuple_log_rate", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} / bft::TCP {},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));

    bft_assert_prog_run("test_tuple_log_rate", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} / bft::TCP {},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(0, ring_buffer__consume(rb));
    assert_int_equal(1, capture.entries.size());
    bft_assert_counter_eq("test_tuple_log_rate", 0, 3, -1);

    ring_buffer__free(rb);
}

} // namespace

int main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(tupleLogging, bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
        cmocka_unit_test_setup_teardown(tupleLogRateEligibility,
                                        bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
        cmocka_unit_test_setup_teardown(rawLoggingUnchanged,
                                        bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
    };

    return cmocka_run_group_tests(tests, bft_e2e_setup, bft_e2e_teardown);
}
