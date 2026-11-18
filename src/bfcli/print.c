/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "print.h"

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>

#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/counter.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>
#include <bpfilter/rule.h>
#include <bpfilter/runtime.h>
#include <bpfilter/set.h>
#include <bpfilter/verdict.h>

#include "bpfilter/core/hashset.h"

struct bfc_chain_opts;

#define INET6_ADDRSTRLEN 46

#define BF_TIME_S 1000000000
#define BF_TIME_MS 1000000
#define BF_TIME_US 1000

#define BF_DUMP_HEXDUMP_LEN 8
#define BF_DUMP_TOKEN_LEN 5

#define BF_CHECK_TCP_FLAG(tcphdr, field, flag_enum, flags_str, pos,            \
                          flag_count)                                          \
    if ((tcphdr)->field) {                                                     \
        const char *flag_name = bf_tcp_flag_to_str(flag_enum);                 \
        if (flag_name) {                                                       \
            (pos) += snprintf((flags_str) + (pos), sizeof(flags_str) - (pos),  \
                              "%s%s", (flag_count) > 0 ? "," : "", flag_name); \
            (flag_count)++;                                                    \
        }                                                                      \
    }

extern const char *inet_ntop(int, const void *, char *, socklen_t);

/**
 * Dump a block of memory in hexadecimal format.
 *
 * @param data Pointer to the data to be dumped. Must be non-NULL.
 * @param len Length of the data in bytes.
 */
static void bf_dump_hex_local(const void *data, size_t len)
{
    const void *end = data + len;
    // 5 characters per byte (0x%02x) + 1 for the null terminator.
    char buf[(BF_DUMP_HEXDUMP_LEN * BF_DUMP_TOKEN_LEN) + 1];

    assert(data);

    while (data < end) {
        char *line = buf;
        for (size_t i = 0; i < BF_DUMP_HEXDUMP_LEN && data < end; ++i, ++data)
            line += sprintf(line, "0x%02x ", *(unsigned char *)data);

        (void)fprintf(stdout, "%s", buf);
    }
}

void bfc_chain_dump(struct bf_chain *chain, struct bf_hookopts *hookopts,
                    bool no_set_content)
{
    bool need_comma = false;
    bool is_pkt_hook;

    assert(chain);

    is_pkt_hook = bf_hook_to_flavor(chain->hook) != BF_FLAVOR_CGROUP_SOCK_ADDR;

    (void)fprintf(stdout, "chain %s %s", chain->name,
                  bf_hook_to_str(chain->hook));
    if (hookopts) {
        (void)fprintf(stdout, "{");

        if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_IFINDEX)) {
            (void)fprintf(stdout, "%sifindex=%d", need_comma ? "," : "",
                          hookopts->ifindex);
            need_comma = true;
        }

        if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_CGPATH)) {
            (void)fprintf(stdout, "%scgpath=%s", need_comma ? "," : "",
                          hookopts->cgpath);
            need_comma = true;
        }

        if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_FAMILY)) {
            (void)fprintf(stdout, "%sfamily=%s", need_comma ? "," : "",
                          hookopts->family == PF_INET ? "inet4" : "inet6");
            need_comma = true;
        }

        if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_PRIORITIES)) {
            (void)fprintf(stdout, "%spriorities=%d-%d", need_comma ? "," : "",
                          hookopts->priorities[0], hookopts->priorities[1]);
            need_comma = true;
        }

        (void)fprintf(stdout, "}");
    }

    (void)fprintf(stdout, " %s\n", bf_verdict_to_str(chain->policy));

    if (is_pkt_hook) {
        (void)fprintf(stdout, "    counters policy %lu packets %lu bytes; ",
                      chain->policy_counters.count,
                      chain->policy_counters.size);
    } else {
        (void)fprintf(stdout, "    counters policy %lu calls; ",
                      chain->policy_counters.count);
    }

    if (is_pkt_hook) {
        (void)fprintf(stdout, "error %lu packets %lu bytes; ",
                      chain->error_counters.count, chain->error_counters.size);
        (void)fprintf(stdout, "parser-drop %lu packets %lu bytes\n",
                      chain->parser_drop_counters.count,
                      chain->parser_drop_counters.size);
    } else {
        (void)fprintf(stdout, "error %lu calls\n", chain->error_counters.count);
    }

    // Loop over named sets
    bf_hashset_foreach (&chain->sets, set_node) {
        struct bf_set *set = set_node->data;

        if (bf_set_is_anonymous(set))
            continue;

        (void)fprintf(stdout, "    set %s (", set->name);
        for (size_t i = 0; i < set->n_comps; ++i) {
            (void)fprintf(stdout, "%s", bf_matcher_type_to_str(set->key[i]));

            if (i != set->n_comps - 1)
                (void)fprintf(stdout, ", ");
        }
        (void)fprintf(stdout, ")");

        if (set->min_size)
            (void)fprintf(stdout, " min-size=%zu", set->min_size);

        if (no_set_content) {
            (void)fprintf(stdout,
                          " in { /* %zu elements, content elided */ }\n",
                          bf_hashset_size(&set->elems));
            continue;
        }

        (void)fprintf(stdout, " in {\n");

        bf_hashset_foreach (&set->elems, node) {
            uint32_t payload_idx = 0;

            (void)fprintf(stdout, "        ");
            for (size_t i = 0; i < set->n_comps; ++i) {
                const struct bf_matcher_meta *meta =
                    bf_matcher_get_meta(set->key[i]);

                meta->ops[BF_MATCHER_IN].print(node->data + payload_idx);
                payload_idx += meta->ops[BF_MATCHER_IN].ref_payload_size;

                if (i != set->n_comps - 1)
                    (void)fprintf(stdout, ", ");
            }
            (void)fprintf(stdout, "\n");
        }

        (void)fprintf(stdout, "    }\n");
    }

    // Loop over rules
    bf_list_foreach (&chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        (void)fprintf(stdout, "    rule\n");
        bf_list_foreach (&rule->matchers, matcher_node) {
            struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
            const struct bf_matcher_ops *ops = bf_matcher_get_ops(
                bf_matcher_get_type(matcher), bf_matcher_get_op(matcher));

            const bool negate = bf_matcher_get_negate(matcher);
            const char *in_str = negate ? "not in" : "in";

            if (bf_matcher_get_type(matcher) == BF_MATCHER_SET) {
                const struct bf_set *set =
                    bf_chain_get_set_for_matcher(chain, matcher);

                (void)fprintf(stdout, "        (");
                for (size_t i = 0; i < set->n_comps; ++i) {
                    (void)fprintf(stdout, "%s",
                                  bf_matcher_type_to_str(set->key[i]));

                    if (i != set->n_comps - 1)
                        (void)fprintf(stdout, ", ");
                }

                if (!bf_set_is_anonymous(set)) {
                    (void)fprintf(stdout, ") %s %s", in_str, set->name);
                } else if (no_set_content) {
                    (void)fprintf(stdout,
                                  ") in { /* %zu elements, content elided */ }",
                                  bf_hashset_size(&set->elems));
                } else {
                    (void)fprintf(stdout, ") %s {\n", in_str);

                    bf_hashset_foreach (&set->elems, node) {
                        uint32_t payload_idx = 0;

                        (void)fprintf(stdout, "            ");
                        for (size_t i = 0; i < set->n_comps; ++i) {
                            const struct bf_matcher_meta *meta =
                                bf_matcher_get_meta(set->key[i]);

                            meta->ops[BF_MATCHER_IN].print(node->data +
                                                           payload_idx);
                            payload_idx +=
                                meta->ops[BF_MATCHER_IN].ref_payload_size;

                            if (i != set->n_comps - 1)
                                (void)fprintf(stdout, ", ");
                        }
                        (void)fprintf(stdout, "\n");
                    }

                    (void)fprintf(stdout, "        }");
                }
            } else {
                (void)fprintf(
                    stdout, "        %s",
                    bf_matcher_type_to_str(bf_matcher_get_type(matcher)));
                (void)fprintf(stdout, "%s %s ", negate ? " not" : "",
                              bf_matcher_op_to_str(bf_matcher_get_op(matcher)));

                if (ops) {
                    ops->print(bf_matcher_payload(matcher));
                } else {
                    bf_dump_hex_local(bf_matcher_payload(matcher),
                                      bf_matcher_payload_len(matcher));
                }
            }

            (void)fprintf(stdout, "\n");
        }

        if (rule->log) {
            if (rule->log == BF_LOG_OPT_DEFAULT) {
                (void)fprintf(stdout, "        log");
            } else {
                uint8_t log = rule->log;

                (void)fprintf(stdout, "        log ");

                for (enum bf_log_opt hdr = 0; hdr < _BF_LOG_OPT_MAX; ++hdr) {
                    if (!(log & BF_FLAG(hdr)))
                        continue;

                    log &= ~BF_FLAG(hdr);
                    (void)fprintf(stdout, "%s%s", bf_log_opt_to_str(hdr),
                                  log ? "," : "");
                }
            }

            if (rule->log_rate_ns) {
                uint64_t r = rule->log_rate_ns;

                if (r % BF_TIME_S == 0) {
                    (void)fprintf(stdout, " every %llus",
                                  (unsigned long long)(r / BF_TIME_S));
                } else if (r % BF_TIME_MS == 0) {
                    (void)fprintf(stdout, " every %llums",
                                  (unsigned long long)(r / BF_TIME_MS));
                } else if (r % BF_TIME_US == 0) {
                    (void)fprintf(stdout, " every %lluus",
                                  (unsigned long long)(r / BF_TIME_US));
                } else {
                    (void)fprintf(stdout, " every %lluns",
                                  (unsigned long long)r);
                }
            }

            (void)fprintf(stdout, "\n");
        }

        if (bf_rule_mark_is_set(rule))
            (void)fprintf(stdout, "        mark 0x%x\n",
                          bf_rule_mark_get(rule));

        if (rule->has_counters) {
            if (is_pkt_hook) {
                (void)fprintf(stdout,
                              "        counters %lu packets %lu bytes\n",
                              rule->counters.count, rule->counters.size);
            } else {
                (void)fprintf(stdout, "        counters %lu calls\n",
                              rule->counters.count);
            }
        }

        if (rule->verdict == BF_VERDICT_REDIRECT) {
            (void)fprintf(stdout, "        REDIRECT %u %s\n",
                          rule->redirect_ifindex,
                          bf_redirect_dir_to_str(rule->redirect_dir));
        } else {
            (void)fprintf(stdout, "        %s\n",
                          bf_verdict_to_str(rule->verdict));
        }
    }
}

int bfc_ruleset_dump(bf_list *chains, bf_list *hookopts, bool no_set_content)
{
    struct bf_list_node *chain_node;
    struct bf_list_node *hookopts_node;

    assert(chains);
    assert(hookopts);

    if (bf_list_size(chains) != bf_list_size(hookopts))
        return -EINVAL;

    chain_node = bf_list_get_head(chains);
    hookopts_node = bf_list_get_head(hookopts);

    while (chain_node) {
        bfc_chain_dump(bf_list_node_get_data(chain_node),
                       bf_list_node_get_data(hookopts_node), no_set_content);

        chain_node = bf_list_node_next(chain_node);
        hookopts_node = bf_list_node_next(hookopts_node);
    }

    return 0;
}

static const char *_bf_tcp_flags_to_str(const struct tcphdr *tcphdr)
{
    static char flags_str[128];
    int pos = 0;
    int flag_count = 0;

    flags_str[0] = '\0';

    BF_CHECK_TCP_FLAG(tcphdr, fin, BF_TCP_FIN, flags_str, pos, flag_count);
    BF_CHECK_TCP_FLAG(tcphdr, syn, BF_TCP_SYN, flags_str, pos, flag_count);
    BF_CHECK_TCP_FLAG(tcphdr, rst, BF_TCP_RST, flags_str, pos, flag_count);
    BF_CHECK_TCP_FLAG(tcphdr, psh, BF_TCP_PSH, flags_str, pos, flag_count);
    BF_CHECK_TCP_FLAG(tcphdr, ack, BF_TCP_ACK, flags_str, pos, flag_count);
    BF_CHECK_TCP_FLAG(tcphdr, urg, BF_TCP_URG, flags_str, pos, flag_count);
    BF_CHECK_TCP_FLAG(tcphdr, ece, BF_TCP_ECE, flags_str, pos, flag_count);
    BF_CHECK_TCP_FLAG(tcphdr, cwr, BF_TCP_CWR, flags_str, pos, flag_count);

    return flag_count > 0 ? flags_str : NULL;
}

static int _bf_chain_log_header(const struct bf_log *log)
{
    struct timespec realtime;
    struct timespec monotonic;
    struct timespec time;
    int64_t elapsed_ns;
    char time_str[64];

    assert(log);

    if (clock_gettime(CLOCK_REALTIME, &realtime) ||
        clock_gettime(CLOCK_MONOTONIC, &monotonic))
        return bf_err_r(-errno, "failed to read clocks for log timestamp");

    // Reconstruct wall time as realtime_now - (monotonic_now - event_time).
    elapsed_ns = ((int64_t)monotonic.tv_sec * BF_TIME_S) + monotonic.tv_nsec -
                 (int64_t)log->ts;
    time.tv_sec = realtime.tv_sec - (time_t)(elapsed_ns / BF_TIME_S);
    time.tv_nsec = realtime.tv_nsec - (long)(elapsed_ns % BF_TIME_S);
    if (time.tv_nsec < 0) {
        --time.tv_sec;
        time.tv_nsec += BF_TIME_S;
    } else if (time.tv_nsec >= BF_TIME_S) {
        ++time.tv_sec;
        time.tv_nsec -= BF_TIME_S;
    }

    (void)strftime(time_str, sizeof(time_str), "%H:%M:%S",
                   localtime(&time.tv_sec));

    (void)fprintf(stdout, "\n%s[%s.%06ld]%s Rule #%u",
                  bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_NORMAL),
                  time_str, time.tv_nsec / BF_TIME_US,
                  bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                  log->rule_id);

    if (log->log_type == BF_LOG_TYPE_PACKET) {
        (void)fprintf(stdout, " matched %s%llu bytes%s with",
                      bf_logger_get_color(BF_COLOR_DEFAULT, BF_STYLE_BOLD),
                      log->pkt.pkt_size,
                      bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));
    }

    (void)fprintf(stdout, " verdict %s\n",
                  bf_verdict_to_str((enum bf_verdict)log->verdict));

    return 0;
}

static void _bf_chain_log_l2(const struct bf_log *log)
{
    struct ethhdr *ethhdr = (void *)log->pkt.l2hdr;
    const char *ethertype;

    if (!(log->pkt.headers & (1 << BF_LOG_OPT_LINK))) {
        (void)fprintf(stdout, "  Ethernet  : <unknown header>\n");
        return;
    }

    ethertype = bf_ethertype_to_str(be16toh(ethhdr->h_proto));

    // NOLINTBEGIN
    (void)fprintf(
        stdout,
        "  Ethernet  : %s%02x:%02x:%02x:%02x:%02x:%02x%s → %s%02x:%02x:%02x:%02x:%02x:%02x%s",
        bf_logger_get_color(BF_COLOR_YELLOW, BF_STYLE_BOLD),
        ethhdr->h_source[0], ethhdr->h_source[1], ethhdr->h_source[2],
        ethhdr->h_source[3], ethhdr->h_source[4], ethhdr->h_source[5],
        bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
        bf_logger_get_color(BF_COLOR_YELLOW, BF_STYLE_BOLD), ethhdr->h_dest[0],
        ethhdr->h_dest[1], ethhdr->h_dest[2], ethhdr->h_dest[3],
        ethhdr->h_dest[4], ethhdr->h_dest[5],
        bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));
    // NOLINTEND

    if (ethertype)
        (void)fprintf(stdout, " (%s)\n", ethertype);
    else
        (void)fprintf(stdout, " (0x%04x)\n", be16toh(ethhdr->h_proto));
}

static void _bf_chain_log_l3(const struct bf_log *log)
{
    struct iphdr *iphdr;
    struct ipv6hdr *ipv6hdr;
    char src_addr[INET6_ADDRSTRLEN];
    char dst_addr[INET6_ADDRSTRLEN];
    const char *protocol;

    if (!(log->pkt.headers & (1 << BF_LOG_OPT_INTERNET))) {
        (void)fprintf(stdout, "  Internet  : <unknown header>\n");
        return;
    }

    switch (log->l3_proto) {
    case ETH_P_IP:
        iphdr = (struct iphdr *)&log->pkt.l3hdr[0];

        inet_ntop(AF_INET, &iphdr->saddr, src_addr, sizeof(src_addr));
        inet_ntop(AF_INET, &iphdr->daddr, dst_addr, sizeof(dst_addr));
        protocol = bf_ipproto_to_str(iphdr->protocol);

        (void)fprintf(
            stdout, "  IPv4      : %s%-15s%s → %s%-15s%s",
            bf_logger_get_color(BF_COLOR_CYAN, BF_STYLE_BOLD), src_addr,
            bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
            bf_logger_get_color(BF_COLOR_CYAN, BF_STYLE_BOLD), dst_addr,
            bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));

        if (protocol) {
            (void)fprintf(
                stdout, " [%s%s%s, TTL=%u]\n",
                bf_logger_get_color(BF_COLOR_LIGHT_MAGENTA, BF_STYLE_BOLD),
                protocol, bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                iphdr->ttl);
        } else {
            (void)fprintf(stdout, " [proto=%u, TTL=%u]\n", iphdr->protocol,
                          iphdr->ttl);
        }
        break;

    case ETH_P_IPV6:
        ipv6hdr = (struct ipv6hdr *)log->pkt.l3hdr;

        inet_ntop(AF_INET6, &ipv6hdr->saddr, src_addr, sizeof(src_addr));
        inet_ntop(AF_INET6, &ipv6hdr->daddr, dst_addr, sizeof(dst_addr));
        protocol = bf_ipproto_to_str(ipv6hdr->nexthdr);

        (void)fprintf(
            stdout, "  IPv6      : %s%s%s → %s%s%s",
            bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_BOLD), src_addr,
            bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
            bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_BOLD), dst_addr,
            bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));

        if (protocol) {
            (void)fprintf(
                stdout, " [%s%s%s, Hop=%u]\n",
                bf_logger_get_color(BF_COLOR_LIGHT_MAGENTA, BF_STYLE_BOLD),
                protocol, bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                ipv6hdr->hop_limit);
        } else {
            (void)fprintf(stdout, " [nexthdr=%u, Hop=%u]\n", ipv6hdr->nexthdr,
                          ipv6hdr->hop_limit);
        }
        break;

    default:
        (void)fprintf(stdout, "  Internet  : <unknown protocol 0x%04x>\n",
                      log->l3_proto);
    }
}

static void _bf_chain_log_l4(const struct bf_log *log)
{
    struct icmphdr *icmphdr;
    struct icmp6hdr *icmp6hdr;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;
    const char *tcp_flags_str;

    if (!(log->pkt.headers & (1 << BF_LOG_OPT_TRANSPORT))) {
        (void)fprintf(stdout, "  Transport : <unknown header>\n");
        return;
    }

    switch (log->l4_proto) {
    case IPPROTO_TCP:
        tcphdr = (struct tcphdr *)log->pkt.l4hdr;
        tcp_flags_str = _bf_tcp_flags_to_str(tcphdr);

        (void)fprintf(stdout, "  TCP       : %s%-5u%s → %s%-5u%s",
                      bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_BOLD),
                      be16toh(tcphdr->source),
                      bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                      bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_BOLD),
                      be16toh(tcphdr->dest),
                      bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));

        if (tcp_flags_str) {
            (void)fprintf(
                stdout, " [%s%s%s]",
                bf_logger_get_color(BF_COLOR_LIGHT_GREEN, BF_STYLE_BOLD),
                tcp_flags_str,
                bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));
        }

        (void)fprintf(stdout, "\n              seq=%-10u ack=%-10u win=%-5u\n",
                      be32toh(tcphdr->seq), be32toh(tcphdr->ack_seq),
                      be16toh(tcphdr->window));
        break;

    case IPPROTO_UDP:
        udphdr = (struct udphdr *)log->pkt.l4hdr;

        (void)fprintf(stdout, "  UDP       : %s%-5u%s → %s%-5u%s [len=%u]\n",
                      bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_BOLD),
                      be16toh(udphdr->source),
                      bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                      bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_BOLD),
                      be16toh(udphdr->dest),
                      bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                      be16toh(udphdr->len));
        break;

    case IPPROTO_ICMP:
        icmphdr = (struct icmphdr *)log->pkt.l4hdr;

        (void)fprintf(stdout, "  ICMP      : type=%-3u code=%-3u",
                      icmphdr->type, icmphdr->code);

        if (icmphdr->type == ICMP_ECHO || icmphdr->type == ICMP_ECHOREPLY) {
            (void)fprintf(stdout, " [id=%u seq=%u]\n",
                          be16toh(icmphdr->un.echo.id),
                          be16toh(icmphdr->un.echo.sequence));
        } else {
            (void)fprintf(stdout, "\n");
        }
        break;

    case IPPROTO_ICMPV6:
        icmp6hdr = (struct icmp6hdr *)log->pkt.l4hdr;

        (void)fprintf(stdout, "  ICMPv6    : type=%-3u code=%-3u",
                      icmp6hdr->icmp6_type, icmp6hdr->icmp6_code);

        if (icmp6hdr->icmp6_type == ICMPV6_ECHO_REQUEST ||
            icmp6hdr->icmp6_type == ICMPV6_ECHO_REPLY) {
            (void)fprintf(stdout, " [id=%u seq=%u]\n",
                          be16toh(icmp6hdr->icmp6_identifier),
                          be16toh(icmp6hdr->icmp6_sequence));
        } else {
            (void)fprintf(stdout, "\n");
        }
        break;

    default:
        (void)fprintf(stdout, "  Transport : <unknown protocol %u>\n",
                      log->l4_proto);
    }
}

static void _bf_chain_log_sock_addr(const struct bf_log *log)
{
    char src_addr[INET6_ADDRSTRLEN];
    char dst_addr[INET6_ADDRSTRLEN];
    const char *protocol;
    const char *label = NULL;
    const char *color = NULL;
    const char *l4_label;
    int family = 0;

    assert(log);

    protocol = bf_ipproto_to_str(log->l4_proto);

    if (log->l3_proto == ETH_P_IP) {
        family = AF_INET;
        label = "IPv4";
        color = bf_logger_get_color(BF_COLOR_CYAN, BF_STYLE_BOLD);
    } else if (log->l3_proto == ETH_P_IPV6) {
        family = AF_INET6;
        label = "IPv6";
        color = bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_BOLD);
    }

    if (label) {
        bool has_saddr =
            log->sock_addr.captured_fields & BF_LOG_SOCK_ADDR_SADDR;

        inet_ntop(family, log->sock_addr.daddr, dst_addr, sizeof(dst_addr));

        if (has_saddr) {
            inet_ntop(family, log->sock_addr.saddr, src_addr, sizeof(src_addr));
            (void)fprintf(
                stdout, "  %-10s: %s%s%s → %s%s%s", label, color, src_addr,
                bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET), color,
                dst_addr, bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));
        } else {
            (void)fprintf(stdout, "  %-10s: → %s%s%s", label, color, dst_addr,
                          bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));
        }

        if (protocol) {
            (void)fprintf(
                stdout, " [%s%s%s]\n",
                bf_logger_get_color(BF_COLOR_LIGHT_MAGENTA, BF_STYLE_BOLD),
                protocol, bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));
        } else {
            (void)fprintf(stdout, " [proto=%u]\n", log->l4_proto);
        }
    } else {
        (void)fprintf(stdout, "  Internet  : <unknown protocol 0x%04x>\n",
                      log->l3_proto);
    }

    switch (log->l4_proto) {
    case IPPROTO_TCP:
        l4_label = "TCP";
        break;
    case IPPROTO_UDP:
        l4_label = "UDP";
        break;
    default:
        l4_label = "Transport";
        break;
    }

    (void)fprintf(stdout, "  %-10s: → %s%-5u%s\n", l4_label,
                  bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_BOLD),
                  log->sock_addr.dport,
                  bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));

    (void)fprintf(stdout, "  PID       : %s%u%s\n",
                  bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_BOLD),
                  log->sock_addr.pid,
                  bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));

    /* A process in the initial PID namespace has a single PID, already
     * printed above, and ns_pid is 0. */
    if (log->sock_addr.ns_pid) {
        (void)fprintf(stdout, "  NS PID    : %s%u%s\n",
                      bf_logger_get_color(BF_COLOR_LIGHT_YELLOW, BF_STYLE_BOLD),
                      log->sock_addr.ns_pid,
                      bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));
    }

    (void)fprintf(stdout, "  Process   : %s%.*s%s\n",
                  bf_logger_get_color(BF_COLOR_LIGHT_GREEN, BF_STYLE_BOLD),
                  BF_COMM_LEN, log->sock_addr.comm,
                  bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));
}

static void _bf_chain_log_5_tuple(const struct bf_log *log)
{
    char src_addr[INET6_ADDRSTRLEN];
    char dst_addr[INET6_ADDRSTRLEN];
    const char *protocol;
    int family;

    assert(log);

    if (log->l3_proto == ETH_P_IP) {
        family = AF_INET;
    } else if (log->l3_proto == ETH_P_IPV6) {
        family = AF_INET6;
    } else {
        (void)fprintf(stdout, "  5-tuple   : <unknown protocol 0x%04x>\n",
                      log->l3_proto);
        return;
    }

    inet_ntop(family, log->pkt_5_tuple.saddr, src_addr, sizeof(src_addr));
    inet_ntop(family, log->pkt_5_tuple.daddr, dst_addr, sizeof(dst_addr));
    protocol = bf_ipproto_to_str(log->l4_proto);
    /* Tuple logging only emits TCP or UDP records, both of which are known to
     * bf_ipproto_to_str(). */

    (void)fprintf(stdout, "  5-tuple   : %s%s%s ",
                  bf_logger_get_color(BF_COLOR_LIGHT_MAGENTA, BF_STYLE_BOLD),
                  protocol ?: "unknown",
                  bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));

    if (family == AF_INET6) {
        (void)fprintf(stdout, "%s[%s]:%u%s → %s[%s]:%u%s\n",
                      bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_BOLD),
                      src_addr, log->pkt_5_tuple.sport,
                      bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                      bf_logger_get_color(BF_COLOR_LIGHT_CYAN, BF_STYLE_BOLD),
                      dst_addr, log->pkt_5_tuple.dport,
                      bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));
    } else {
        (void)fprintf(stdout, "%s%s:%u%s → %s%s:%u%s\n",
                      bf_logger_get_color(BF_COLOR_CYAN, BF_STYLE_BOLD),
                      src_addr, log->pkt_5_tuple.sport,
                      bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET),
                      bf_logger_get_color(BF_COLOR_CYAN, BF_STYLE_BOLD),
                      dst_addr, log->pkt_5_tuple.dport,
                      bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET));
    }
}

int bfc_print_log(const struct bf_log *log)
{
    int r;

    assert(log);

    r = _bf_chain_log_header(log);
    if (r)
        return r;

    switch (log->log_type) {
    case BF_LOG_TYPE_PACKET:
        if (log->pkt.req_headers & (1 << BF_LOG_OPT_LINK))
            _bf_chain_log_l2(log);
        if (log->pkt.req_headers & (1 << BF_LOG_OPT_INTERNET))
            _bf_chain_log_l3(log);
        if (log->pkt.req_headers & (1 << BF_LOG_OPT_TRANSPORT))
            _bf_chain_log_l4(log);
        break;
    case BF_LOG_TYPE_SOCK_ADDR:
        _bf_chain_log_sock_addr(log);
        break;
    case BF_LOG_TYPE_PACKET_5_TUPLE:
        _bf_chain_log_5_tuple(log);
        break;
    default:
        break;
    }

    return 0;
}
