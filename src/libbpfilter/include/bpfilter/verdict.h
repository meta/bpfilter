/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

/**
 * Redirect direction for the REDIRECT verdict.
 */
enum bf_redirect_dir
{
    /** Redirect to the interface's ingress path. */
    BF_REDIRECT_INGRESS,
    /** Redirect to the interface's egress path. */
    BF_REDIRECT_EGRESS,
    _BF_REDIRECT_DIR_MAX,
};

/**
 * @brief Convert a redirect direction value into a string.
 *
 * @param dir The direction to convert, must be valid.
 * @return String representation of the direction.
 */
const char *bf_redirect_dir_to_str(enum bf_redirect_dir dir);

/**
 * @brief Convert a string into a redirect direction value.
 *
 * @param str String to convert to a direction. Can't be NULL.
 * @param dir Pointer to store the direction value. Can't be NULL.
 * @return 0 on success, or negative errno value on error.
 */
int bf_redirect_dir_from_str(const char *str, enum bf_redirect_dir *dir);

/**
 * Reply sent by the REJECT verdict.
 *
 * Each type is answered with the message matching the packet's network
 * protocol: ICMP for IPv4, ICMPv6 for IPv6.
 */
enum bf_reject_type
{
    /** Destination unreachable, port unreachable: ICMP type 3 code 3, or
     * ICMPv6 type 1 code 4. Default. */
    BF_REJECT_PORT_UNREACH,
    _BF_REJECT_TYPE_MAX,
};

/**
 * @brief Convert a reject type value into a string.
 *
 * @param type The reject type to convert, must be valid.
 * @return String representation of the reject type.
 */
const char *bf_reject_type_to_str(enum bf_reject_type type);

/**
 * @brief Convert a string into a reject type value.
 *
 * @param str String to convert to a reject type. Can't be NULL.
 * @param type Pointer to store the reject type value. Can't be NULL.
 * @return 0 on success, or negative errno value on error.
 */
int bf_reject_type_from_str(const char *str, enum bf_reject_type *type);

/**
 * Verdict to apply for a rule or chain.
 *
 * Only some verdicts are valid as chain policies (see
 * `bf_verdict_is_valid_policy`). Rules can use all verdicts.
 */
enum bf_verdict
{
    /** Accept the packet. Terminal. */
    BF_VERDICT_ACCEPT,
    /** Drop the packet. Terminal. */
    BF_VERDICT_DROP,
    /** Continue processing the next rule. Non-terminal. */
    BF_VERDICT_CONTINUE,
    /** Redirect the packet to another interface. Terminal. */
    BF_VERDICT_REDIRECT,
    /** Pass the packet to the next BPF program. Terminal.
     *
     * For TC, this maps to TCX_NEXT which defers to the next program in
     * the TCX link. For NF, XDP, and cgroup_skb, NEXT maps to the same
     * return code as ACCEPT since these hooks do not distinguish between
     * "accept" and "pass to next program." */
    BF_VERDICT_NEXT,
    /** Drop the packet and send a reply to its sender (see
     * `bf_reject_type`). Terminal. */
    BF_VERDICT_REJECT,
    _BF_VERDICT_MAX,
};

/**
 * Convert a verdict value into a string.
 *
 * @param verdict The verdict to convert, must be valid.
 * @return String representation of the verdict.
 */
const char *bf_verdict_to_str(enum bf_verdict verdict);

/**
 * Convert a string into a verdict value.
 *
 * @param str String to convert to a verdict. Can't be NULL.
 * @param verdict String representation of the verdict. Can't be NULL.
 * @return 0 on success, or negative errno value on error.
 */
int bf_verdict_from_str(const char *str, enum bf_verdict *verdict);

/**
 * Check if a verdict is valid as a chain policy.
 *
 * Only ACCEPT, DROP, and NEXT are valid chain policies. CONTINUE is
 * non-terminal and cannot be a default action. REDIRECT requires per-rule
 * parameters (interface, direction) so it cannot be a policy either. REJECT
 * is a rule-only verdict, as with iptables.
 *
 * @param verdict Verdict to check.
 * @return true if the verdict is valid as a chain policy, false otherwise.
 */
bool bf_verdict_is_valid_policy(enum bf_verdict verdict);
