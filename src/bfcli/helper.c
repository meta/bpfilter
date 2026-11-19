
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "helper.h"

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#include <bpfilter/logger.h>

#include "lexer.h"
#include "parser.h"

/* To speed up parsing very large rulesets, we can increase YY_READ_BUF_SIZE.
 * Referenced by the generated lexer; cannot be static. */
// NOLINTNEXTLINE(misc-use-internal-linkage)
int yy_read_buf_size;

#define _BF_LEX_MIN_BUF_POW 14
#define _BF_LEX_MAX_BUF_POW 20

static int _bf_compute_lexer_buf_size(size_t len)
{
    int val = _BF_LEX_MIN_BUF_POW;

    if (len) {
        val = ((int)sizeof(len) * 8) - __builtin_clzl(len);
        val = bf_min(bf_max(val - 3, _BF_LEX_MIN_BUF_POW), _BF_LEX_MAX_BUF_POW);
    }

    return (int)BF_FLAG(val);
}

int bfc_parse_file(const char *file, struct bfc_ruleset *ruleset)
{
    FILE *rules;
    struct stat stt;
    int r;

    if (stat(file, &stt) == -1)
        return bf_err_r(errno, "failed to stat file %s:", file);

    yy_read_buf_size = _bf_compute_lexer_buf_size(stt.st_size);
    bf_dbg("yy_read_buf_size choosen is %d", yy_read_buf_size);

    rules = fopen(file, "r");
    if (!rules)
        return bf_err_r(errno, "failed to read rules from %s:", file);

    yyin = rules;

    r = yyparse(ruleset);
    if (r == 1)
        r = bf_err_r(-EINVAL, "failed to parse rules, invalid syntax");
    else if (r == 2)
        r = bf_err_r(-ENOMEM, "failed to parse rules, not enough memory");

    (void)fclose(rules);

    return r;
}

int bfc_parse_str(const char *str, struct bfc_ruleset *ruleset)
{
    YY_BUFFER_STATE buffer;
    unsigned long str_size;
    int r;

    str_size = strlen(str);
    yy_read_buf_size = _bf_compute_lexer_buf_size(str_size);
    bf_dbg("yy_read_buf_size choosen is %d", yy_read_buf_size);

    buffer = yy_scan_string(str);

    r = yyparse(ruleset);
    if (r == 1)
        r = bf_err_r(-EINVAL, "failed to parse rules, invalid syntax");
    else if (r == 2)
        r = bf_err_r(-ENOMEM, "failed to parse rules, not enough memory");

    yy_delete_buffer(buffer);

    return r;
}
