/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <variant>
#include <vector>

namespace bft
{

constexpr size_t kEthernetAddrLen = 6;

/**
 * @brief VLAN tag with an EtherType and tag control information in host order.
 */
struct VLAN
{
    static constexpr uint16_t k8021Q = 0x8100;
    static constexpr uint16_t k8021AD = 0x88a8;

    uint16_t ether_type = k8021Q;
    uint16_t tci = 0;

    [[nodiscard]] static size_t size();
    [[nodiscard]] size_t write(uint8_t *buf, uint16_t proto) const;
};

/**
 * @brief Ethernet header.
 *
 * Default addresses use the locally-administered unicast prefix (`02:...`).
 */
struct Ethernet
{
    static constexpr uint16_t kTransparentBridging = 0x6558; // ETH_P_TEB

    std::array<uint8_t, kEthernetAddrLen> dst = {0x02, 0, 0, 0, 0, 0x01};
    std::array<uint8_t, kEthernetAddrLen> src = {0x02, 0, 0, 0, 0, 0x02};

    /// EtherType advertised to the preceding header, if present.
    uint16_t ether_type = kTransparentBridging;

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
    static constexpr uint8_t ip_proto = 4; // IPPROTO_IPIP

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
    static constexpr uint8_t ip_proto = 41; // IPPROTO_IPV6

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

namespace detail
{

using Header = std::variant<Ethernet, VLAN, IPv4, IPv6, IPv6HopByHop,
                            IPv6Fragment, TCP, UDP, ICMPv4, ICMPv6>;

} // namespace detail

/**
 * @brief Serialized packet that can be extended with the `/` operator.
 *
 * Each composition writes the headers in the supplied order and updates
 * lengths and next-protocol fields. Composing again regenerates the bytes
 * from the saved headers.
 */
struct Packet
{
    std::array<uint8_t, 256> data = {};
    size_t len = 0;

private:
    std::vector<detail::Header> _headers;

    friend Packet operator/(detail::Header first, detail::Header second);
    friend Packet operator/(Packet pkt, detail::Header header);
};

Packet operator/(detail::Header first, detail::Header second);
Packet operator/(Packet pkt, detail::Header header);

} // namespace bft
