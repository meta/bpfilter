/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace bft
{

constexpr size_t kEthernetAddrLen = 6;

/**
 * @brief Raw packet buffer.
 *
 * Holds a serialized packet built by composing protocol layers with the `/`
 * operator (e.g. `Ethernet{} / IPv4{} / TCP{}`).
 */
struct Packet
{
    std::array<uint8_t, 256> data = {};
    size_t len = 0;
};

/**
 * @brief Ethernet header.
 *
 * Default addresses use the locally-administered unicast prefix (`02:...`).
 */
struct Ethernet
{
    std::array<uint8_t, kEthernetAddrLen> dst = {0x02, 0, 0, 0, 0, 0x01};
    std::array<uint8_t, kEthernetAddrLen> src = {0x02, 0, 0, 0, 0, 0x02};

    [[nodiscard]] static size_t size();
    [[nodiscard]] size_t write(uint8_t *buf, uint16_t proto) const;
};

/**
 * @brief IPv4 address, constructible from a 32-bit integer or dotted string.
 */
struct IPv4Addr
{
    uint32_t addr;

    IPv4Addr(uint32_t addr);
    IPv4Addr(const char *str);
};

/**
 * @brief IPv4 header.
 *
 * Default addresses use TEST-NET-1 (`192.0.2.0/24`, RFC 5737).
 */
struct IPv4
{
    static constexpr auto kDefaultSrc = "192.0.2.1";
    static constexpr auto kDefaultDst = "192.0.2.2";
    static constexpr uint8_t kDefaultTTL = 64;
    static constexpr uint16_t kDefaultId = 1;

    IPv4Addr saddr = kDefaultSrc;
    IPv4Addr daddr = kDefaultDst;
    uint8_t ttl = kDefaultTTL;
    uint16_t id = kDefaultId;
    uint8_t tos = 0;

    static constexpr uint16_t ether_type = 0x0800;

    [[nodiscard]] static size_t size();
    [[nodiscard]] size_t write(uint8_t *buf, uint8_t proto,
                               size_t payload) const;
};

/**
 * @brief IPv6 address, constructible from a colon-hex string.
 */
struct IPv6Addr
{
    std::array<uint8_t, 16> addr = {};

    IPv6Addr(const char *str);
};

/**
 * @brief IPv6 header.
 *
 * Default addresses use the documentation prefix (`2001:db8::/32`, RFC 3849).
 */
struct IPv6
{
    static constexpr auto kDefaultSrc = "2001:db8::1";
    static constexpr auto kDefaultDst = "2001:db8::2";
    static constexpr uint8_t kDefaultHopLimit = 64;

    IPv6Addr saddr = kDefaultSrc;
    IPv6Addr daddr = kDefaultDst;
    uint8_t hop_limit = kDefaultHopLimit;
    uint8_t traffic_class = 0;

    static constexpr uint16_t ether_type = 0x86dd;

    [[nodiscard]] static size_t size();
    [[nodiscard]] size_t write(uint8_t *buf, uint8_t proto,
                               size_t payload) const;
};

/**
 * @brief IPv6 Hop-by-Hop Options header, padded to 8 bytes.
 */
struct IPv6HopByHop
{
    static constexpr uint8_t ip_proto = 0; // IPPROTO_HOPOPTS

    [[nodiscard]] static size_t size();
    [[nodiscard]] size_t write(uint8_t *buf, uint8_t proto) const;
};

/**
 * @brief IPv6 Destination Options header, same layout as Hop-by-Hop.
 */
struct IPv6DstOpts: IPv6HopByHop
{
    static constexpr uint8_t ip_proto = 60; // IPPROTO_DSTOPTS
};

/**
 * @brief IPv6 Fragment header for a single fragment (offset 0, M flag unset).
 */
struct IPv6Fragment
{
    uint8_t reserved = 0;

    static constexpr uint8_t ip_proto = 44; // IPPROTO_FRAGMENT

    [[nodiscard]] static size_t size();
    [[nodiscard]] size_t write(uint8_t *buf, uint8_t proto) const;
};

/**
 * @brief TCP header.
 */
struct TCP
{
    static constexpr uint16_t kDefaultSport = 12345;
    static constexpr uint16_t kDefaultDport = 80;
    static constexpr uint16_t kDefaultWindow = 65535;

    uint16_t sport = kDefaultSport;
    uint16_t dport = kDefaultDport;
    uint32_t seq = 0;
    uint32_t ack_seq = 0;
    uint16_t window = kDefaultWindow;
    bool fin = false;
    bool syn = false;
    bool rst = false;
    bool psh = false;
    bool ack = false;
    bool urg = false;

    static constexpr uint8_t ip_proto = 6; // IPPROTO_TCP

    [[nodiscard]] static size_t size();
    [[nodiscard]] size_t write(uint8_t *buf) const;
};

/**
 * @brief UDP header.
 */
struct UDP
{
    static constexpr uint16_t kDefaultSport = 12345;
    static constexpr uint16_t kDefaultDport = 53;

    uint16_t sport = kDefaultSport;
    uint16_t dport = kDefaultDport;

    static constexpr uint8_t ip_proto = 17; // IPPROTO_UDP

    [[nodiscard]] static size_t size();
    [[nodiscard]] size_t write(uint8_t *buf) const;
};

/**
 * @brief ICMPv4 header.
 *
 * Defaults to Echo Request (type 8, code 0).
 */
struct ICMPv4
{
    static constexpr uint8_t kDefaultType = 8; // ICMP_ECHO
    static constexpr uint8_t kDefaultCode = 0;

    uint8_t type = kDefaultType;
    uint8_t code = kDefaultCode;

    static constexpr uint8_t ip_proto = 1; // IPPROTO_ICMP

    [[nodiscard]] static size_t size();
    [[nodiscard]] size_t write(uint8_t *buf) const;
};

/**
 * @brief ICMPv6 header.
 *
 * Defaults to Echo Request (type 128, code 0).
 */
struct ICMPv6
{
    static constexpr uint8_t kDefaultType = 128; // ICMPV6_ECHO_REQUEST
    static constexpr uint8_t kDefaultCode = 0;

    uint8_t type = kDefaultType;
    uint8_t code = kDefaultCode;

    static constexpr uint8_t ip_proto = 58; // IPPROTO_ICMPV6

    [[nodiscard]] static size_t size();
    [[nodiscard]] size_t write(uint8_t *buf) const;
};

/**
 * @brief IPv6 extension header: written with the protocol of the next layer.
 */
template<typename T>
concept IPv6ExtHdr =
    requires(const T &layer, uint8_t *buf) { layer.write(buf, T::ip_proto); };

namespace detail
{

/**
 * @brief Intermediate state for the `Ethernet{} / L3{}` partial stack.
 *
 * Not meant to be used directly — produced by `operator/` and consumed
 * by a second `operator/` that appends the L4 layer and produces a `Packet`.
 */
template<typename L3>
struct Partial
{
    Ethernet l2;
    L3 l3;
};

/**
 * @brief Network layer followed by an IPv6 extension header.
 *
 * Produced by `operator/`. It is used as a network layer, so extension headers
 * can be chained before the transport layer.
 */
template<typename L3, IPv6ExtHdr Ext>
struct WithExtHdr
{
    L3 l3;
    Ext ext;

    static constexpr uint16_t ether_type = L3::ether_type;

    [[nodiscard]] static size_t size()
    {
        return L3::size() + Ext::size();
    }

    [[nodiscard]] size_t write(uint8_t *buf, uint8_t proto,
                               size_t payload) const
    {
        const size_t off = l3.write(buf, Ext::ip_proto, Ext::size() + payload);

        return off + ext.write(buf + off, proto);
    }
};

} // namespace detail

/**
 * @brief Compose an Ethernet layer with a network layer (e.g. `IPv4`, `IPv6`).
 *
 * @return An intermediate `detail::Partial` that must be combined with a
 *         transport layer via a second `/` to produce a `Packet`.
 */
template<typename L3>
detail::Partial<L3> operator/(Ethernet layer2, L3 layer3)
{
    return {layer2, layer3};
}

/**
 * @brief Append an IPv6 extension header to a partial stack.
 *
 * Usage: `auto pkt = Ethernet{} / IPv6{} / IPv6HopByHop{} / TCP{};`
 */
template<typename L3, IPv6ExtHdr Ext>
detail::Partial<detail::WithExtHdr<L3, Ext>>
operator/(detail::Partial<L3> stack, Ext ext)
{
    return {stack.l2, {stack.l3, ext}};
}

/**
 * @brief Append a transport layer to a partial stack and serialize a `Packet`.
 *
 * Usage: `auto pkt = Ethernet{} / IPv4{} / TCP{.dport = 443};`
 */
template<typename L3, typename L4>
Packet operator/(detail::Partial<L3> stack, L4 layer4)
{
    Packet pkt;
    size_t off = 0;

    if (off + stack.l2.size() > pkt.data.size())
        throw std::runtime_error("packet buffer overflow");
    off += stack.l2.write(pkt.data.data() + off, L3::ether_type);

    if (off + stack.l3.size() > pkt.data.size())
        throw std::runtime_error("packet buffer overflow");
    off += stack.l3.write(pkt.data.data() + off, L4::ip_proto, layer4.size());

    if (off + layer4.size() > pkt.data.size())
        throw std::runtime_error("packet buffer overflow");
    off += layer4.write(pkt.data.data() + off);

    pkt.len = off;
    return pkt;
}

} // namespace bft
