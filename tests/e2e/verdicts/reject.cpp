/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <cstring>
#include <initializer_list>
#include <vector>

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "test.hpp"

extern "C" {
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <bpfilter/bpf.h>
#include <bpfilter/bpfilter.h>
#include <bpfilter/helper.h>
}

namespace
{

constexpr uint8_t kBroadcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/* All hooks except XDP, which is the only one supporting REJECT. */
constexpr enum bf_hook kUnsupportedHooks[] = {
    BF_HOOK_TC_INGRESS,
    BF_HOOK_TC_EGRESS,
    BF_HOOK_NF_PRE_ROUTING,
    BF_HOOK_NF_LOCAL_IN,
    BF_HOOK_NF_FORWARD,
    BF_HOOK_NF_LOCAL_OUT,
    BF_HOOK_NF_POST_ROUTING,
    BF_HOOK_CGROUP_SKB_INGRESS,
    BF_HOOK_CGROUP_SKB_EGRESS,
    BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4,
    BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6,
    BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4,
    BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6,
};

/**
 * Add @p len bytes to the one's complement sum @p sum .
 */
uint32_t sum16(const uint8_t *data, size_t len, uint32_t sum = 0)
{
    for (size_t i = 0; i + 1 < len; i += 2)
        sum += static_cast<uint32_t>(data[i] << 8 | data[i + 1]);
    if (len % 2)
        sum += static_cast<uint32_t>(data[len - 1] << 8);

    return sum;
}

/**
 * Fold the one's complement sum of @p len bytes: 0 if their checksum is valid.
 */
uint16_t csum(const uint8_t *data, size_t len, uint32_t sum = 0)
{
    sum = sum16(data, len, sum);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return static_cast<uint16_t>(~sum);
}

void set_ip4_csum(bft::Packet &pkt)
{
    auto *iph = reinterpret_cast<struct iphdr *>(&pkt.data[ETH_HLEN]);
    uint16_t sum;

    iph->check = 0;
    sum = htons(csum(&pkt.data[ETH_HLEN], iph->ihl * 4));
    std::memcpy(&iph->check, &sum, sizeof(sum));
}

/**
 * Rule rejecting every packet. A rule without matchers would make the chain
 * policy unreachable, which the verifier refuses.
 */
bf::Rule reject_rule()
{
    return {BF_VERDICT_REJECT, std::nullopt, {}, {bf::Matcher::alwaysMatch()}};
}

/**
 * Run @p pkt through the XDP program of chain @p name, check the program
 * returned @p expected, and return the packet as the program left it.
 */
std::vector<uint8_t> run_xdp(const char *name, const bft::Packet &pkt,
                             int expected)
{
    std::vector<uint8_t> out(512);
    _cleanup_close_ int fd = bf_chain_prog_fd(name);
    union bpf_attr attr = {};

    assert_true(fd >= 0);

    attr.test.prog_fd = fd;
    attr.test.data_in = (unsigned long long)pkt.data.data();
    attr.test.data_size_in = pkt.len;
    attr.test.data_out = (unsigned long long)out.data();
    attr.test.data_size_out = out.size();
    attr.test.repeat = 1;

    assert_int_equal(0, bf_bpf(BF_BPF_PROG_TEST_RUN, &attr));
    assert_int_equal(expected, attr.test.retval);

    out.resize(attr.test.data_size_out);

    return out;
}

/**
 * Check @p reply is the ICMP port unreachable error for the IPv4 packet @p pkt.
 */
void assert_icmp_reply(const bft::Packet &pkt,
                       const std::vector<uint8_t> &reply)
{
    const auto *orig =
        reinterpret_cast<const struct iphdr *>(&pkt.data[ETH_HLEN]);
    const size_t quote_len = orig->ihl * 4 + 8;
    const auto *eth = reinterpret_cast<const struct ethhdr *>(reply.data());
    const auto *iph = reinterpret_cast<const struct iphdr *>(&reply[ETH_HLEN]);
    const auto *icmph = reinterpret_cast<const struct icmphdr *>(
        &reply[ETH_HLEN + sizeof(*iph)]);
    const uint8_t *quote = &reply[ETH_HLEN + sizeof(*iph) + sizeof(*icmph)];

    assert_int_equal(reply.size(),
                     ETH_HLEN + sizeof(*iph) + sizeof(*icmph) + quote_len);

    assert_memory_equal(eth->h_dest, &pkt.data[ETH_ALEN], ETH_ALEN);
    assert_memory_equal(eth->h_source, &pkt.data[0], ETH_ALEN);
    assert_int_equal(eth->h_proto, htons(ETH_P_IP));

    assert_int_equal(iph->version, 4);
    assert_int_equal(iph->ihl, 5);
    assert_int_equal(ntohs(iph->tot_len), reply.size() - ETH_HLEN);
    assert_int_equal(iph->frag_off, htons(0x4000));
    assert_int_equal(iph->ttl, 64);
    assert_int_equal(iph->protocol, IPPROTO_ICMP);
    assert_int_equal(iph->saddr, orig->daddr);
    assert_int_equal(iph->daddr, orig->saddr);
    assert_int_equal(csum(&reply[ETH_HLEN], sizeof(*iph)), 0);

    assert_int_equal(icmph->type, ICMP_DEST_UNREACH);
    assert_int_equal(icmph->code, ICMP_PORT_UNREACH);
    assert_int_equal(icmph->un.gateway, 0);
    assert_int_equal(csum(reinterpret_cast<const uint8_t *>(icmph),
                          sizeof(*icmph) + quote_len),
                     0);
    assert_memory_equal(quote, &pkt.data[ETH_HLEN], quote_len);
}

// Quote of an IPv6 packet without extension headers
constexpr size_t kIPv6Quote = sizeof(struct ipv6hdr) + 8;

/**
 * Check @p reply is the ICMPv6 port unreachable error for the IPv6 packet
 * @p pkt , quoting its first @p quote_len bytes.
 */
void assert_icmp6_reply(const bft::Packet &pkt,
                        const std::vector<uint8_t> &reply,
                        size_t quote_len = kIPv6Quote)
{
    const auto *orig =
        reinterpret_cast<const struct ipv6hdr *>(&pkt.data[ETH_HLEN]);
    const auto *eth = reinterpret_cast<const struct ethhdr *>(reply.data());
    const auto *ip6h =
        reinterpret_cast<const struct ipv6hdr *>(&reply[ETH_HLEN]);
    const auto *icmp6h = reinterpret_cast<const struct icmp6hdr *>(
        &reply[ETH_HLEN + sizeof(*ip6h)]);
    const uint8_t *quote = &reply[ETH_HLEN + sizeof(*ip6h) + sizeof(*icmp6h)];
    const uint32_t icmp6_len = sizeof(*icmp6h) + quote_len;
    const uint8_t pseudo_tail[] = {0, 0, 0, static_cast<uint8_t>(icmp6_len),
                                   0, 0, 0, IPPROTO_ICMPV6};
    uint32_t sum;

    assert_int_equal(reply.size(), ETH_HLEN + sizeof(*ip6h) + icmp6_len);

    assert_memory_equal(eth->h_dest, &pkt.data[ETH_ALEN], ETH_ALEN);
    assert_memory_equal(eth->h_source, &pkt.data[0], ETH_ALEN);
    assert_int_equal(eth->h_proto, htons(ETH_P_IPV6));

    // Version 6, traffic class and flow label 0
    assert_memory_equal(ip6h, "\x60\x00\x00\x00", 4);
    assert_int_equal(ntohs(ip6h->payload_len), icmp6_len);
    assert_int_equal(ip6h->nexthdr, IPPROTO_ICMPV6);
    assert_int_equal(ip6h->hop_limit, 64);
    assert_memory_equal(&ip6h->saddr, &orig->daddr, sizeof(orig->daddr));
    assert_memory_equal(&ip6h->daddr, &orig->saddr, sizeof(orig->saddr));

    assert_int_equal(icmp6h->icmp6_type, ICMPV6_DEST_UNREACH);
    assert_int_equal(icmp6h->icmp6_code, ICMPV6_PORT_UNREACH);
    assert_int_equal(icmp6h->icmp6_dataun.un_data32[0], 0);
    sum = sum16(reinterpret_cast<const uint8_t *>(&ip6h->saddr),
                sizeof(ip6h->saddr) + sizeof(ip6h->daddr));
    sum = sum16(pseudo_tail, sizeof(pseudo_tail), sum);
    assert_int_equal(
        csum(reinterpret_cast<const uint8_t *>(icmp6h), icmp6_len, sum), 0);
    assert_memory_equal(quote, &pkt.data[ETH_HLEN], quote_len);
}

} // namespace

/**
 * REJECT is only supported by XDP: the other hooks fail to generate the
 * program.
 */
static void unsupported_hooks(void **state)
{
    (void)state;

    for (auto hook: kUnsupportedHooks) {
        auto chain =
            (bf::Chain("reject", hook, BF_VERDICT_ACCEPT) << reject_rule())
                .get();

        assert_int_equal(-ENOTSUP, bf_chain_set(chain.get(), nullptr));
    }
}

/**
 * IPv4 packets are replaced with an ICMP port unreachable error quoting their
 * IP header and the 8 next bytes, sent back with `XDP_TX`.
 */
static void ip4_reply(void **state)
{
    bft::Packet pkt;

    (void)state;

    BFT_CHAIN_SET(bf::Chain("reject", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
                  << reject_rule());

    pkt = bft::Ethernet() / bft::IPv4 {} / bft::UDP {};
    assert_icmp_reply(pkt, run_xdp("reject", pkt, XDP_TX));

    pkt = bft::Ethernet() / bft::IPv4 {} / bft::TCP {.syn = true};
    assert_icmp_reply(pkt, run_xdp("reject", pkt, XDP_TX));

    // ICMP requests are answered, as with the kernel's icmp_send()
    pkt = bft::Ethernet() / bft::IPv4 {} / bft::ICMPv4 {};
    assert_icmp_reply(pkt, run_xdp("reject", pkt, XDP_TX));

    // IP options are quoted too
    pkt = bft::Ethernet() / bft::IPv4 {} / bft::UDP {};
    std::memmove(&pkt.data[ETH_HLEN + sizeof(struct iphdr) + 4],
                 &pkt.data[ETH_HLEN + sizeof(struct iphdr)],
                 pkt.len - ETH_HLEN - sizeof(struct iphdr));
    std::memset(&pkt.data[ETH_HLEN + sizeof(struct iphdr)], 1, 4); // NOPs
    pkt.len += 4;
    pkt.data[ETH_HLEN] = 0x46;
    pkt.data[ETH_HLEN + 3] += 4;
    set_ip4_csum(pkt);
    assert_icmp_reply(pkt, run_xdp("reject", pkt, XDP_TX));

    // The reply is cut after the quote, even if the packet is longer
    pkt = bft::Ethernet() / bft::IPv4 {} / bft::UDP {};
    pkt.len += 32;
    pkt.data[ETH_HLEN + 3] += 32;
    set_ip4_csum(pkt);
    assert_icmp_reply(pkt, run_xdp("reject", pkt, XDP_TX));

    // Rules matching IPv4 only never reach the reply of other protocols
    BFT_CHAIN_SET(
        bf::Chain("reject_ip4", BF_HOOK_XDP, BF_VERDICT_ACCEPT) << bf::Rule(
            BF_VERDICT_REJECT, std::nullopt, {},
            {bf::Matcher(BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ, {IPPROTO_UDP})}));
    pkt = bft::Ethernet() / bft::IPv4 {} / bft::UDP {};
    assert_icmp_reply(pkt, run_xdp("reject_ip4", pkt, XDP_TX));
}

/**
 * Packets the kernel wouldn't send an ICMP error for are dropped without a
 * reply.
 */
static void ip4_no_reply(void **state)
{
    bft::Packet pkt;

    (void)state;

    BFT_CHAIN_SET(bf::Chain("reject", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
                  << reject_rule());

    // Link-layer broadcast and multicast
    pkt = bft::Ethernet() / bft::IPv4 {} / bft::UDP {};
    std::memcpy(&pkt.data[0], kBroadcast, ETH_ALEN);
    run_xdp("reject", pkt, XDP_DROP);
    pkt.data[0] = 0x01;
    run_xdp("reject", pkt, XDP_DROP);

    // Broadcast, multicast, and unspecified addresses
    for (const char *addr: {"255.255.255.255", "224.0.0.1", "0.0.0.0"}) {
        pkt = bft::Ethernet() / bft::IPv4 {.daddr = addr} / bft::UDP {};
        run_xdp("reject", pkt, XDP_DROP);
        pkt = bft::Ethernet() / bft::IPv4 {.saddr = addr} / bft::UDP {};
        run_xdp("reject", pkt, XDP_DROP);
    }

    // Fragments other than the first one
    pkt = bft::Ethernet() / bft::IPv4 {} / bft::UDP {};
    pkt.data[ETH_HLEN + 7] = 1;
    set_ip4_csum(pkt);
    run_xdp("reject", pkt, XDP_DROP);

    // ICMP errors, or unknown ICMP types
    for (uint8_t type:
         {ICMP_DEST_UNREACH, ICMP_TIME_EXCEEDED, ICMP_PARAMETERPROB, 42}) {
        pkt = bft::Ethernet() / bft::IPv4 {} / bft::ICMPv4 {.type = type};
        run_xdp("reject", pkt, XDP_DROP);
    }

    // Invalid header checksum
    pkt = bft::Ethernet() / bft::IPv4 {} / bft::UDP {};
    pkt.data[ETH_HLEN + 10] ^= 0xff;
    run_xdp("reject", pkt, XDP_DROP);

    // Total length larger than the packet
    pkt = bft::Ethernet() / bft::IPv4 {} / bft::UDP {};
    pkt.len -= 1;
    run_xdp("reject", pkt, XDP_DROP);

    // Less than 8 bytes after the IP header
    pkt = bft::Ethernet() / bft::IPv4 {} / bft::UDP {};
    pkt.len -= 1;
    pkt.data[ETH_HLEN + 3] -= 1;
    set_ip4_csum(pkt);
    run_xdp("reject", pkt, XDP_DROP);

    // Not IP
    pkt = bft::Ethernet() / bft::IPv4 {} / bft::UDP {};
    pkt.data[12] = 0x08;
    pkt.data[13] = 0x06;
    run_xdp("reject", pkt, XDP_DROP);
}

/**
 * IPv6 packets are replaced with an ICMPv6 port unreachable error quoting
 * their IPv6 header, extension headers, and the first 8 bytes of their
 * transport header, sent back with `XDP_TX`.
 */
static void ip6_reply(void **state)
{
    bft::Packet pkt;

    (void)state;

    BFT_CHAIN_SET(bf::Chain("reject", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
                  << reject_rule());

    pkt = bft::Ethernet() / bft::IPv6 {} / bft::UDP {};
    assert_icmp6_reply(pkt, run_xdp("reject", pkt, XDP_TX));

    pkt = bft::Ethernet() / bft::IPv6 {} / bft::TCP {.syn = true};
    assert_icmp6_reply(pkt, run_xdp("reject", pkt, XDP_TX));

    pkt = bft::Ethernet() / bft::IPv6 {} / bft::ICMPv6 {};
    assert_icmp6_reply(pkt, run_xdp("reject", pkt, XDP_TX));

    // Extension headers are quoted, up to the transport header
    pkt =
        bft::Ethernet() / bft::IPv6 {} / bft::IPv6HopByHop {} / bft::ICMPv6 {};
    assert_icmp6_reply(pkt, run_xdp("reject", pkt, XDP_TX), kIPv6Quote + 8);

    // Routing, destination options, and authentication headers of 8 bytes
    for (uint8_t nexthdr: std::initializer_list<uint8_t> {
             IPPROTO_ROUTING, IPPROTO_DSTOPTS, IPPROTO_AH}) {
        pkt =
            bft::Ethernet() / bft::IPv6 {} / bft::IPv6HopByHop {} / bft::UDP {};
        pkt.data[ETH_HLEN + offsetof(struct ipv6hdr, nexthdr)] = nexthdr;
        assert_icmp6_reply(pkt, run_xdp("reject", pkt, XDP_TX), kIPv6Quote + 8);
    }

    pkt = bft::Ethernet() / bft::IPv6 {} / bft::IPv6HopByHop {} /
          bft::IPv6HopByHop {} / bft::IPv6HopByHop {} / bft::IPv6HopByHop {} /
          bft::IPv6HopByHop {} / bft::IPv6HopByHop {} / bft::UDP {};
    assert_icmp6_reply(pkt, run_xdp("reject", pkt, XDP_TX), kIPv6Quote + 48);

    // First fragment
    pkt = bft::Ethernet() / bft::IPv6 {} / bft::IPv6Fragment {} / bft::UDP {};
    assert_icmp6_reply(pkt, run_xdp("reject", pkt, XDP_TX), kIPv6Quote + 8);

    // The reply is cut after the quote, even if the packet is longer
    pkt = bft::Ethernet() / bft::IPv6 {} / bft::UDP {};
    pkt.len += 32;
    pkt.data[ETH_HLEN + 5] += 32;
    assert_icmp6_reply(pkt, run_xdp("reject", pkt, XDP_TX));

    // Rules matching IPv6 only never reach the reply of other protocols
    BFT_CHAIN_SET(bf::Chain("reject_ip6", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_REJECT, std::nullopt, {},
                              {bf::Matcher(BF_MATCHER_IP6_NEXTHDR,
                                           BF_MATCHER_EQ, {IPPROTO_UDP})}));
    pkt = bft::Ethernet() / bft::IPv6 {} / bft::UDP {};
    assert_icmp6_reply(pkt, run_xdp("reject_ip6", pkt, XDP_TX));
}

/**
 * IPv6 packets the kernel wouldn't send an ICMPv6 error for are dropped
 * without a reply.
 */
static void ip6_no_reply(void **state)
{
    bft::Packet pkt;

    (void)state;

    BFT_CHAIN_SET(bf::Chain("reject", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
                  << reject_rule());

    // Link-layer broadcast
    pkt = bft::Ethernet() / bft::IPv6 {} / bft::UDP {};
    std::memcpy(&pkt.data[0], kBroadcast, ETH_ALEN);
    run_xdp("reject", pkt, XDP_DROP);

    // Multicast and unspecified addresses
    for (const char *addr: {"ff02::1", "::"}) {
        pkt = bft::Ethernet() / bft::IPv6 {.daddr = addr} / bft::UDP {};
        run_xdp("reject", pkt, XDP_DROP);
        pkt = bft::Ethernet() / bft::IPv6 {.saddr = addr} / bft::UDP {};
        run_xdp("reject", pkt, XDP_DROP);
    }

    // Fragments other than the first one
    pkt = bft::Ethernet() / bft::IPv6 {} / bft::IPv6Fragment {} / bft::UDP {};
    pkt.data[ETH_HLEN + sizeof(struct ipv6hdr) + 3] = 0x08;
    run_xdp("reject", pkt, XDP_DROP);

    // ICMPv6 errors, even after extension headers
    for (uint8_t type:
         {ICMPV6_DEST_UNREACH, ICMPV6_PKT_TOOBIG, ICMPV6_TIME_EXCEED}) {
        pkt = bft::Ethernet() / bft::IPv6 {} / bft::ICMPv6 {.type = type};
        run_xdp("reject", pkt, XDP_DROP);
        pkt = bft::Ethernet() / bft::IPv6 {} / bft::IPv6HopByHop {} /
              bft::ICMPv6 {.type = type};
        run_xdp("reject", pkt, XDP_DROP);
    }

    // More than 6 extension headers
    pkt = bft::Ethernet() / bft::IPv6 {} / bft::IPv6HopByHop {} /
          bft::IPv6HopByHop {} / bft::IPv6HopByHop {} / bft::IPv6HopByHop {} /
          bft::IPv6HopByHop {} / bft::IPv6HopByHop {} / bft::IPv6HopByHop {} /
          bft::UDP {};
    run_xdp("reject", pkt, XDP_DROP);

    // Less than 8 bytes after the extension headers
    pkt = bft::Ethernet() / bft::IPv6 {} / bft::IPv6HopByHop {} / bft::UDP {};
    pkt.len -= 1;
    pkt.data[ETH_HLEN + 5] -= 1;
    run_xdp("reject", pkt, XDP_DROP);

    // Payload length larger than the packet
    pkt = bft::Ethernet() / bft::IPv6 {} / bft::UDP {};
    pkt.len -= 1;
    run_xdp("reject", pkt, XDP_DROP);

    // Less than 8 bytes after the IPv6 header
    pkt = bft::Ethernet() / bft::IPv6 {} / bft::UDP {};
    pkt.len -= 1;
    pkt.data[ETH_HLEN + 5] -= 1;
    run_xdp("reject", pkt, XDP_DROP);
}

int main()
{
    const std::vector<CMUnitTest> tests = {
        cmocka_unit_test_setup_teardown(unsupported_hooks,
                                        bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
        cmocka_unit_test_setup_teardown(ip4_reply, bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
        cmocka_unit_test_setup_teardown(ip4_no_reply, bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
        cmocka_unit_test_setup_teardown(ip6_reply, bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
        cmocka_unit_test_setup_teardown(ip6_no_reply, bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
    };

    return _cmocka_run_group_tests("REJECT verdict", tests.data(), tests.size(),
                                   bft_e2e_setup, bft_e2e_teardown);
}
