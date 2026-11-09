/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

struct bf_matcher_meta;
struct bf_program;

/**
 * Emit instructions to get a dynptr for an XDP program.
 *
 * Prepare arguments and call bpf_dynptr_from_xdp(). If the return value is
 * different from 0, jump to the end of the program and accept the packet.
 *
 * The initialised dynptr is stored in the program's runtime context.
 *
 * @param program Program to emit instructions into.
 * @param md_reg Scratch register containing the pointer to the xdp_md.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_make_ctx_xdp_dynptr(struct bf_program *program, int md_reg);

/**
 * Emit instructions to get a dynptr for an XDP program.
 *
 * Prepare arguments and call bpf_dynptr_from_skb(). If the return value is
 * different from 0, jump to the end of the program and accept the packet.
 *
 * The initialised dynptr is stored in the program's runtime context.
 *
 * @param program Program to emit instructions into.
 * @param skb_reg Scratch register containing the pointer to the skb.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_make_ctx_skb_dynptr(struct bf_program *program, int skb_reg);

/**
 * Emit instructions to get a dynptr slice for the packet's L2 Ethernet
 * header.
 *
 * The Ethernet header is processed the following way:
 * - Create a BPF dynamic pointer slice for the header.
 * - If the slice creation fails, the error counter is updated and the
 *   program accepts the packet
 * - The header address returned by @c bpf_dynptr_slice is stored in
 *   `bf_runtime.l2_hdr`
 * - The L3 protocol ID (extracted from the ethertype field) is stored in @c r7
 * - The offset of the L3 header is stored in  `bf_runtime.l2_offset`
 *
 * @param program Program to emit instructions into.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_parse_l2_ethhdr(struct bf_program *program);

/**
 * Emit instructions to get a dynptr slice for the packet's L3 IPv4
 * header.
 *
 * This function behaves similarly to @ref bf_stub_parse_l2_ethhdr but for the
 * L3 header, with the following differences:
 * - The size of the slice to request depends on the L3 protocol ID stored in @c r7
 * - Once the slice has been requested, the L3 header is processed to extract
 *   the offset of the L4 header and the L4 protocol ID
 *
 * If the L3 protocol is not supported, this function returns before requesting
 * a dynamic pointer slice, and the L3 protocol ID register is set to 0.
 *
 * If the chain matches on L4 fields, IPv6 packets with more than
 * @c BF_IPV6_EH_MAX extension headers are counted as errors and dropped.
 *
 * @param program Program to emit instructions into.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_parse_l3_hdr(struct bf_program *program);

/**
 * Emit instructions to get a dynptr slice for the packet's L4 header.
 *
 * This function behaves similarly to @ref bf_stub_parse_l2_ethhdr but for the
 * L4 header, with the following differences:
 * - The size of the slice to request depends on the L4 protocol ID stored in @c r8
 * - There is no logic to process the L4 header and determine the L5 protocol
 * - If the slice creation fails (e.g. the packet is too short), the error
 *   counter is updated, the L4 protocol ID register is set to 0 and
 *   `bf_runtime.l4_hdr` to NULL, and processing continues as for an
 *   unsupported L4 protocol
 *
 * If the L4 protocol is not supported, this function returns before requesting
 * a dynamic pointer slice, and the L4 protocol ID register is set to 0.
 *
 * @param program Program to emit instructions into.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_parse_l4_hdr(struct bf_program *program);

/**
 * @brief Emit the instructions to check if the packet contains a specific
 *        protocol.
 *
 * This stub is usually emitted at the beginning of a rule, to ensure the
 * protocol this rule applies to is actually available in the packet. If not,
 * the rule is skipped.
 *
 * @param program Program to emit the instructions into. Can't be NULL.
 * @param meta Metadata for the matcher type to apply. Can't be NULL.
 * @return 0 on success, or negative error value on error.
 */
int bf_stub_rule_check_protocol(struct bf_program *program,
                                const struct bf_matcher_meta *meta);

/**
 * @brief Emit the instructions to load a header address into a register.
 *
 * @param program Program to emit the instructions into. Can't be NULL.
 * @param meta Metadata for the matcher type to apply. Defines the layer to load
 *        the header address for.
 * @param reg Register to load the header address into.
 * @return 0 on success, or negative error value on error.
 */
int bf_stub_load_header(struct bf_program *program,
                        const struct bf_matcher_meta *meta, int reg);

/**
 * @brief Copy bytes from `R6 + src_offset` to `R10 + dst_offset`.
 *
 * The access size per iteration is determined by checking alignment of both
 * source and destination offsets (both advance each iteration), picking the
 * largest width where both are aligned and remaining >= width.
 *
 * @param program Program to emit the instructions into. Can't be NULL.
 * @param src_offset Byte offset from `R6` to start reading from.
 * @param size Number of bytes to copy.
 * @param dst_offset Byte offset from `R10` (stack pointer) to write to. Use
 *        `BF_PROG_SCR_OFF()` for scratch area offsets.
 * @return 0 on success, or negative error value on error.
 */
int bf_stub_load(struct bf_program *program, size_t src_offset, size_t size,
                 int dst_offset);

/**
 * @brief Store the `size` low bytes of `reg` at `R10 + dst_offset`.
 *
 * Store-side counterpart of `bf_stub_load`, for values living in a register
 * (e.g. a helper's return value) instead of memory. The access size per
 * iteration is the largest width `dst_offset` is aligned to: the verifier
 * enforces strict alignment on stack accesses. The value is stored in host
 * byte order, `reg` is shifted right after each partial store and is
 * clobbered unless a single store is emitted.
 *
 * @param program Program to emit the instructions into. Can't be NULL.
 * @param reg Register holding the value to store.
 * @param size Number of bytes to store. At most 8.
 * @param dst_offset Byte offset from `R10` (stack pointer) to write to.
 * @return 0 on success, or negative error value on error.
 */
int bf_stub_store(struct bf_program *program, int reg, size_t size,
                  int dst_offset);

int bf_stub_stx_payload(struct bf_program *program,
                        const struct bf_matcher_meta *meta, size_t offset);
