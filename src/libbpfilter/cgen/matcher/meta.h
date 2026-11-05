/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

struct bf_matcher;
struct bf_codegen;

int bf_matcher_generate_meta(struct bf_codegen *program,
                             const struct bf_matcher *matcher);
