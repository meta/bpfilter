/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include "Packet.hpp"

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <arpa/inet.h>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace bft
{

namespace
{

// Header length in 32-bit words when no options are present.
constexpr uint8_t kIPv4IHL = 5;
constexpr uint8_t kTCPDataOffset = 5;
constexpr uint8_t kTrafficClassLowMask = 0x0f;
// Size of the IPv6 extension headers built by the packet builder.
constexpr size_t kIPv6ExtHdrLen = 8;

uint16_t checksum(const void *data, size_t len)
{
    const auto *buf = static_cast<const uint16_t *>(data);
    uint32_t sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *reinterpret_cast<const uint8_t *>(buf);

    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;

    return static_cast<uint16_t>(~sum);
}

} // namespace

IPv4Addr::IPv4Addr(uint32_t addr):
    addr(addr)
{}

IPv4Addr::IPv4Addr(const char *str)
{
    struct in_addr in;
    if (inet_pton(AF_INET, str, &in) != 1)
        throw std::invalid_argument(str);
    addr = ntohl(in.s_addr);
}

IPv6Addr::IPv6Addr(const char *str)
{
    struct in6_addr in6;
    if (inet_pton(AF_INET6, str, &in6) != 1)
        throw std::invalid_argument(str);
    std::memcpy(addr.data(), &in6, addr.size());
}

size_t VLAN::size()
{
    return 2 * sizeof(uint16_t);
}

size_t VLAN::write(uint8_t *buf, uint16_t proto) const
{
    const uint16_t tag[] = {htons(tci), htons(proto)};

    std::memcpy(buf, tag, sizeof(tag));
    return sizeof(tag);
}

size_t Ethernet::size()
{
    return sizeof(struct ethhdr);
}

size_t Ethernet::write(uint8_t *buf, uint16_t proto) const
{
    struct ethhdr hdr = {};
    std::memcpy(hdr.h_dest, dst.data(), dst.size());
    std::memcpy(hdr.h_source, src.data(), src.size());
    hdr.h_proto = htons(proto);
    std::memcpy(buf, &hdr, sizeof(hdr));
    return sizeof(hdr);
}

size_t IPv4::size()
{
    return sizeof(struct iphdr);
}

size_t IPv4::write(uint8_t *buf, uint8_t proto, size_t payload) const
{
    struct iphdr hdr = {};
    hdr.ihl = kIPv4IHL;
    hdr.version = 4;
    hdr.tos = tos;
    hdr.tot_len = htons(sizeof(hdr) + payload);
    hdr.id = htons(id);
    hdr.ttl = ttl;
    hdr.protocol = proto;
    hdr.saddr = htonl(saddr.addr);
    hdr.daddr = htonl(daddr.addr);
    hdr.check = 0;
    hdr.check = checksum(&hdr, sizeof(hdr));
    std::memcpy(buf, &hdr, sizeof(hdr));
    return sizeof(hdr);
}

size_t IPv6::size()
{
    return sizeof(struct ipv6hdr);
}

size_t IPv6::write(uint8_t *buf, uint8_t proto, size_t payload) const
{
    struct ipv6hdr hdr = {};
    hdr.version = 6;
    hdr.priority = traffic_class >> 4;
    hdr.flow_lbl[0] =
        static_cast<uint8_t>((traffic_class & kTrafficClassLowMask) << 4);
    hdr.payload_len = htons(payload);
    hdr.nexthdr = proto;
    hdr.hop_limit = hop_limit;
    std::memcpy(&hdr.saddr, saddr.addr.data(), saddr.addr.size());
    std::memcpy(&hdr.daddr, daddr.addr.data(), daddr.addr.size());
    std::memcpy(buf, &hdr, sizeof(hdr));
    return sizeof(hdr);
}

size_t IPv6HopByHop::size()
{
    return kIPv6ExtHdrLen;
}

size_t IPv6HopByHop::write(uint8_t *buf, uint8_t proto) const
{
    // Hdr Ext Len 0 (8 bytes), then a PadN option with 4 bytes of padding
    const std::array<uint8_t, kIPv6ExtHdrLen> hdr = {proto, 0, IPV6_TLV_PADN,
                                                     4};

    std::memcpy(buf, hdr.data(), hdr.size());
    return hdr.size();
}

size_t IPv6Fragment::size()
{
    return kIPv6ExtHdrLen;
}

size_t IPv6Fragment::write(uint8_t *buf, uint8_t proto) const
{
    const std::array<uint8_t, kIPv6ExtHdrLen> hdr = {proto, reserved};

    std::memcpy(buf, hdr.data(), hdr.size());
    return hdr.size();
}

size_t TCP::size()
{
    return sizeof(struct tcphdr);
}

size_t TCP::write(uint8_t *buf) const
{
    struct tcphdr hdr = {};
    hdr.source = htons(sport);
    hdr.dest = htons(dport);
    hdr.seq = htonl(seq);
    hdr.ack_seq = htonl(ack_seq);
    hdr.doff = kTCPDataOffset;
    hdr.fin = fin;
    hdr.syn = syn;
    hdr.rst = rst;
    hdr.psh = psh;
    hdr.ack = ack;
    hdr.urg = urg;
    hdr.window = htons(window);
    hdr.check = 0;
    std::memcpy(buf, &hdr, sizeof(hdr));
    return sizeof(hdr);
}

size_t UDP::size()
{
    return sizeof(struct udphdr);
}

size_t UDP::write(uint8_t *buf) const
{
    struct udphdr hdr = {};
    hdr.source = htons(sport);
    hdr.dest = htons(dport);
    hdr.len = htons(sizeof(hdr));
    hdr.check = 0;
    std::memcpy(buf, &hdr, sizeof(hdr));
    return sizeof(hdr);
}

size_t ICMPv4::size()
{
    return sizeof(struct icmphdr);
}

size_t ICMPv4::write(uint8_t *buf) const
{
    struct icmphdr hdr = {};
    hdr.type = type;
    hdr.code = code;
    hdr.checksum = 0;
    hdr.checksum = checksum(&hdr, sizeof(hdr));
    std::memcpy(buf, &hdr, sizeof(hdr));
    return sizeof(hdr);
}

size_t ICMPv6::size()
{
    return sizeof(struct icmp6hdr);
}

size_t ICMPv6::write(uint8_t *buf) const
{
    struct icmp6hdr hdr = {};
    hdr.icmp6_type = type;
    hdr.icmp6_code = code;
    hdr.icmp6_cksum = 0;
    std::memcpy(buf, &hdr, sizeof(hdr));
    return sizeof(hdr);
}

Packet operator/(detail::Header first, detail::Header second)
{
    Packet pkt;

    pkt._headers.push_back(std::move(first));
    return std::move(pkt) / std::move(second);
}

Packet operator/(Packet pkt, detail::Header header)
{
    const auto size = [](const auto &hdr) { return hdr.size(); };
    uint16_t next_ether_type = 0;
    std::optional<uint8_t> next_ip_proto;
    size_t total = 0;
    size_t payload = 0;

    pkt._headers.push_back(std::move(header));
    for (const auto &hdr: pkt._headers)
        total += std::visit(size, hdr);

    if (total > pkt.data.size())
        throw std::runtime_error("packet buffer overflow");

    // Write from the innermost header out so the next protocol and payload size
    // are known when writing each header.
    for (auto it = pkt._headers.rbegin(); it != pkt._headers.rend(); ++it) {
        const size_t header_size = std::visit(size, *it);
        auto *buf = pkt.data.data() + total - payload - header_size;

        std::visit(
            [&](const auto &hdr) {
                using Header = std::remove_cvref_t<decltype(hdr)>;

                if constexpr (requires {
                                  hdr.write(buf, uint8_t {}, payload);
                              }) {
                    constexpr uint8_t terminal =
                        std::is_same_v<Header, IPv4> ? 0 : IPPROTO_NONE;
                    (void)hdr.write(buf, next_ip_proto.value_or(terminal),
                                    payload);
                } else if constexpr (requires { hdr.ether_type; }) {
                    (void)hdr.write(buf, next_ether_type);
                } else if constexpr (requires { hdr.write(buf, uint8_t {}); }) {
                    (void)hdr.write(buf, next_ip_proto.value_or(IPPROTO_NONE));
                } else {
                    (void)hdr.write(buf);
                }

                if constexpr (requires { hdr.ether_type; })
                    next_ether_type = hdr.ether_type;
                else
                    next_ether_type = 0;

                if constexpr (requires { hdr.ip_proto; })
                    next_ip_proto = hdr.ip_proto;
                else
                    next_ip_proto.reset();
            },
            *it);
        payload += header_size;
    }

    pkt.len = total;
    return pkt;
}

} // namespace bft
