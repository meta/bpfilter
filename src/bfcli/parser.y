/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

%{
    #include <endian.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdbool.h>

    #include <bpfilter/core/list.h>
    #include <bpfilter/if.h>

    #include "ruleset.h"

    extern int yylex();
    extern int yyparse(struct bfc_ruleset *ruleset);
    extern FILE *yyin;

    void yyerror(struct bfc_ruleset *ruleset, const char *fmt, ...);
%}

%code requires {
    #include <linux/in.h>
    #include <linux/in6.h>
    #include <linux/if_ether.h>
    #include <limits.h>
    #include <math.h>

    #include <bpfilter/verdict.h>
    #include <bpfilter/hook.h>
    #include <bpfilter/matcher.h>
    #include <bpfilter/core/list.h>
    #include <bpfilter/rule.h>
    #include <bpfilter/chain.h>
    #include <bpfilter/runtime.h>

    #include "helper.h"

    extern int inet_pton(int af, const char *restrict src, void *restrict dst);

    #define AF_INET     2
    #define AF_INET6    10

    #define min(a,b)             \
    ({                           \
        __typeof__ (a) _a = (a); \
        __typeof__ (b) _b = (b); \
        _a < _b ? _a : _b;       \
    })

    #define bf_parse_err(fmt, ...)                                             \
    ({                                                                         \
        yyerror(ruleset, fmt, ##__VA_ARGS__);                                  \
        YYABORT;                                                               \
    })

    enum bf_rule_option_flag {
        BF_RULE_OPTION_LOG      = 1 << 0,
        BF_RULE_OPTION_COUNTER  = 1 << 1,
        BF_RULE_OPTION_MARK     = 1 << 2,
        BF_RULE_OPTION_LOG_RATE = 1 << 3,
    };

    struct bf_rule_options {
        uint8_t flags;

        uint8_t log;
        uint64_t log_rate_ns;
        bool counter;
        uint32_t mark;
    };

    static inline int _parse_log_rate(const char *s, uint64_t *ns)
    {
        double multiplier;
        double v;
        char *end;

        v = strtod(s, &end);
        if (end == s || v <= 0.0)
            return -1;

        if (strcmp(end, "ns") == 0)
            multiplier = 1.0;
        else if (strcmp(end, "us") == 0)
            multiplier = 1000.0;
        else if (strcmp(end, "ms") == 0)
            multiplier = 1000000.0;
        else if (strcmp(end, "s") == 0)
            multiplier = 1000000000.0;
        else
            return -1;

        if (!isfinite(v) || v > (double)UINT64_MAX / multiplier)
            return -1;

        *ns = (uint64_t)(v * multiplier + 0.5);
        if (*ns == 0)
            return -1;

        return 0;
    }

    struct bfc_rule_verdict {
        enum bf_verdict verdict;
        uint32_t redirect_ifindex;
        enum bf_redirect_dir redirect_dir;
    };
}

%define parse.error detailed
%parse-param {struct bfc_ruleset *ruleset}

%union {
    bool bval;
    uint8_t u8;
    uint32_t u32;
    uint64_t u64;
    char *sval;
    enum bf_verdict verdict;
    enum bf_hook hook;
    enum bf_matcher_type matcher_type;
    bf_list *list;
    struct bf_matcher *matcher;
    struct bf_rule *rule;
    struct bf_chain *chain;
    enum bf_matcher_op matcher_op;
    struct bf_hookopts *hookopts;
    struct bf_rule_options rule_options;
    struct bfc_rule_verdict rule_verdict;
}

// Tokens
%token CHAIN
%token RULE
%token SET
%token NEGATE LOG COUNTER MARK EVERY
%token REDIRECT_TOKEN
%token <sval> SET_TYPE
%token <u64> SET_MIN_SIZE
%token <sval> SET_RAW_PAYLOAD
%token <sval> STRING
%token <sval> HOOK VERDICT MATCHER_TYPE MATCHER_OP
%token <sval> RAW_HOOKOPT
%token <sval> RAW_PAYLOAD
%token <sval> REDIRECT_IFACE
%token <sval> REDIRECT_DIR

// Grammar types
%destructor { BF_FREEP(&$$); } <sval>

%type <hook> hook
%type <hookopts> hookopts
%destructor { bf_hookopts_free(&$$); } hookopts

%type <verdict> verdict
%type <rule_verdict> rule_verdict

%type <matcher_type> matcher_type

%type <matcher_op> matcher_op

%type <bval> negate

%type <void> sets
%type <void> set
%type <u64> set_min_size

%type <list> matchers
%destructor { bf_list_free(&$$); } matchers

%type <matcher> matcher
%destructor { bf_matcher_free(&$$); } matcher

%type <list> rules
%destructor { bf_list_free(&$$); } rules

%type <u8> log_headers
%type <u64> log_rate
%type <rule_options> rule_option
%type <rule_options> rule_options
%type <rule> rule
%destructor { bf_rule_free(&$$); } rule

%type <chain> chain
%destructor { bf_chain_free(&$$); } chain

%%
chains          : chain { (void)$1; }
                | chains chain { (void)$2; }
                ;

chain           : CHAIN STRING hook hookopts verdict sets rules
                {
                    _free_bf_chain_ struct bf_chain *chain = NULL;
                    _cleanup_free_ const char *name = $2;
                    _free_bf_hookopts_ struct bf_hookopts *hookopts = $4;
                    _free_bf_list_ bf_list *rules = $7;
                    int r;

                    if (!bf_verdict_is_valid_policy($5))
                        bf_parse_err("'%s' is not a valid chain policy\n", bf_verdict_to_str($5));

                    if (bf_chain_new(&chain, name, $3, $5, &ruleset->sets, rules) < 0)
                        bf_parse_err("failed to create a new bf_chain\n");

                    if (hookopts) {
                        r = bf_hookopts_validate(hookopts, chain->hook);
                        if (r)
                            bf_parse_err("invalid hook options used");
                    }

                    if (bf_list_add_tail(&ruleset->chains, chain) < 0)
                        bf_parse_err("failed to add chain into bf_list\n");
                    $$ = TAKE_PTR(chain);

                    if (bf_list_add_tail(&ruleset->hookopts, hookopts))
                        bf_parse_err("failed to insert hookopts to list of hookopts");
                    TAKE_PTR(hookopts);
                }

verdict         : VERDICT
                {
                    if (bf_verdict_from_str($1, &$$) < 0)
                        bf_parse_err("unknown verdict '%s'\n", $1);
                    free($1);
                }

rule_verdict    : verdict
                {
                    $$ = (struct bfc_rule_verdict){
                        .verdict = $1,
                        .redirect_ifindex = 0,
                        .redirect_dir = BF_REDIRECT_EGRESS,
                    };
                }
                | REDIRECT_TOKEN REDIRECT_IFACE REDIRECT_DIR
                {
                    _cleanup_free_ const char *iface = $2;
                    _cleanup_free_ const char *dir = $3;
                    uint32_t ifindex;
                    enum bf_redirect_dir redirect_dir;
                    int r;

                    r = bf_if_index_from_str(iface, &ifindex);
                    if (r)
                        bf_parse_err("interface '%s' not found", iface);

                    // Parse direction
                    if (bf_redirect_dir_from_str(dir, &redirect_dir) < 0)
                        bf_parse_err("invalid redirect direction '%s' (expected 'in' or 'out')", dir);

                    $$ = (struct bfc_rule_verdict){
                        .verdict = BF_VERDICT_REDIRECT,
                        .redirect_ifindex = ifindex,
                        .redirect_dir = redirect_dir,
                    };
                }

hook            : HOOK
                {
                    _cleanup_free_ const char *hook_str = $1;

                    if (bf_hook_from_str(hook_str, &$$) < 0)
                        bf_parse_err("unknown hook '%s'\n", hook_str);
                }

hookopts        : %empty { $$ = NULL; }
                | hookopts RAW_HOOKOPT
                {
                    _free_bf_hookopts_ struct bf_hookopts *hookopts = $1;
                    _cleanup_free_ const char *raw_opt = $2;
                    int r;

                    if (!hookopts) {
                        r = bf_hookopts_new(&hookopts);
                        if (r)
                            bf_parse_err("failed to allocate a new bf_hookopts object");
                    }

                    r = bf_hookopts_parse_opt(hookopts, raw_opt);
                    if (r)
                        bf_parse_err("failed to parse hook option");

                    $$ = TAKE_PTR(hookopts);
                }
                ;

sets            : %empty { }
                | sets set { }
                ;
set             : SET STRING SET_TYPE set_min_size matcher_op SET_RAW_PAYLOAD
                {
                    _free_bf_set_ struct bf_set *set = NULL;
                    _cleanup_free_ const char *name = $2;
                    _cleanup_free_ const char *raw_key = $3;
                    _cleanup_free_ const char *payload = $6;
                    enum bf_matcher_op op = $5;
                    int r;

                    if (op != BF_MATCHER_IN)
                        bf_parse_err("only the 'in' operator is supported for sets");

                    r = bf_set_new_from_raw(&set, name, raw_key, payload);
                    if (r)
                        bf_parse_err("failed to create new set");

                    set->min_size = $4;

                    if (bf_hashset_add(&ruleset->sets, (void **)&set) < 0)
                        bf_parse_err("failed to add set '%s' to the ruleset", name);
                }
                ;

set_min_size    : %empty { $$ = 0; }
                | SET_MIN_SIZE
                {
                    if ($1 > UINT32_MAX)
                        bf_parse_err("set min-size can't exceed %u", UINT32_MAX);

                    $$ = $1;
                }
                ;

rules           : %empty { $$ = NULL; }
                | rules rule
                {
                    if (!$1) {
                        if (bf_list_new(&$1, (bf_list_ops[]){{.free = (bf_list_ops_free)bf_rule_free, .pack = (bf_list_ops_pack)bf_rule_pack}}) < 0)
                            bf_parse_err("failed to allocate a new bf_list for bf_rule\n");
                    }

                    if (bf_list_add_tail($1, $2) < 0)
                        bf_parse_err("failed to insert rule into bf_list\n");

                    TAKE_PTR($2);
                    $$ = TAKE_PTR($1);
                }
                ;
rule            : RULE matchers rule_options rule_verdict
                {
                    _free_bf_rule_ struct bf_rule *rule = NULL;

                    if (bf_rule_new(&rule) < 0)
                        bf_parse_err("failed to create a new bf_rule\n");

                    rule->log = $3.flags & BF_RULE_OPTION_LOG ? $3.log : 0;
                    rule->log_rate_ns = $3.flags & BF_RULE_OPTION_LOG_RATE ? $3.log_rate_ns : 0;
                    rule->has_counters = $3.flags & BF_RULE_OPTION_COUNTER ? 1 : 0;

                    if ($3.flags & BF_RULE_OPTION_MARK)
                        bf_rule_mark_set(rule, $3.mark);

                    rule->verdict = $4.verdict;
                    if ($4.verdict == BF_VERDICT_REDIRECT)
                        bf_rule_set_redirect(rule, $4.redirect_ifindex, $4.redirect_dir);

                    bf_list_foreach ($2, matcher_node) {
                        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

                        if (bf_list_add_tail(&rule->matchers, matcher) < 0)
                            bf_parse_err("failed to add matcher to the rule\n");

                        bf_list_node_take_data(matcher_node);
                    }

                    bf_list_free(&$2);
                    $$ = TAKE_PTR(rule);
                }
                ;

rule_option     : LOG
                {
                    $$ = (struct bf_rule_options){
                        .log = BF_LOG_OPT_DEFAULT,
                        .flags = BF_RULE_OPTION_LOG,
                    };
                }
                | LOG log_headers
                {
                    $$ = (struct bf_rule_options){
                        .log = $2,
                        .flags = BF_RULE_OPTION_LOG,
                    };
                }
                | LOG EVERY log_rate
                {
                    $$ = (struct bf_rule_options){
                        .log = BF_LOG_OPT_DEFAULT,
                        .log_rate_ns = $3,
                        .flags = BF_RULE_OPTION_LOG | BF_RULE_OPTION_LOG_RATE,
                    };
                }
                | LOG log_headers EVERY log_rate
                {
                    $$ = (struct bf_rule_options){
                        .log = $2,
                        .log_rate_ns = $4,
                        .flags = BF_RULE_OPTION_LOG | BF_RULE_OPTION_LOG_RATE,
                    };
                }
                | COUNTER
                {
                    $$ = (struct bf_rule_options){
                        .counter = true,
                        .flags = BF_RULE_OPTION_COUNTER,
                    };
                }
                | MARK STRING
                {
                    _cleanup_free_ const char *raw_mark = $2;
                    long long mark;
                    char *endptr;

                    mark = strtoll(raw_mark, &endptr, 0);
                    if (*endptr)
                        bf_parse_err("mark value '%s' can't be parsed as a positive integer", raw_mark);
                    if (mark < 0)
                        bf_parse_err("mark should be positive, not '%s'", raw_mark);
                    if (mark > UINT32_MAX)
                        bf_parse_err("mark should be at most 0x%x", UINT32_MAX);

                    $$ = (struct bf_rule_options){
                        .mark = (uint32_t)mark,
                        .flags = BF_RULE_OPTION_MARK,
                    };
                }

log_rate        : STRING
                {
                    _cleanup_free_ const char *rate_str = $1;
                    uint64_t ns;

                    if (_parse_log_rate(rate_str, &ns) < 0)
                        bf_parse_err("invalid rate '%s': expected <N>ns/us/ms/s",
                                     rate_str);

                    $$ = ns;
                }
                ;

rule_options    : %empty { $$ = (struct bf_rule_options){}; }
                | rule_options rule_option {
                    if ($2.flags & BF_RULE_OPTION_LOG) {
                        if ($1.flags & BF_RULE_OPTION_LOG)
                            bf_parse_err("duplicate keyword \"log\" in rule");
                        $1.flags |= BF_RULE_OPTION_LOG;
                        $1.log = $2.log;
                    }

                    if ($2.flags & BF_RULE_OPTION_LOG_RATE) {
                        $1.flags |= BF_RULE_OPTION_LOG_RATE;
                        $1.log_rate_ns = $2.log_rate_ns;
                    }

                    if ($2.flags & BF_RULE_OPTION_COUNTER) {
                        if ($1.flags & BF_RULE_OPTION_COUNTER)
                            bf_parse_err("duplicate keyword \"counter\" in rule");
                        $1.flags |= BF_RULE_OPTION_COUNTER;
                        $1.counter = $2.counter;
                    }

                    if ($2.flags & BF_RULE_OPTION_MARK) {
                        if ($1.flags & BF_RULE_OPTION_MARK)
                            bf_parse_err("duplicate keyword \"mark\" in rule");
                        $1.flags |= BF_RULE_OPTION_MARK;
                        $1.mark = $2.mark;
                    }

                    $$ = $1;
                }

log_headers     : STRING
                {
                    _cleanup_free_ const char *name = $1;
                    enum bf_log_opt header;

                    if (bf_log_opt_from_str(name, &header) < 0)
                        bf_parse_err("unknown packet header '%s'", name);

                    $$ = BF_FLAG(header);
                }
                | log_headers ',' STRING
                {
                    _cleanup_free_ const char *name = $3;
                    enum bf_log_opt header;

                    if (bf_log_opt_from_str(name, &header) < 0)
                        bf_parse_err("unknown packet header '%s'", name);

                    $$ = $1 | BF_FLAG(header);
                }
                ;

matchers        : %empty
                {
                    _free_bf_list_ bf_list *list = NULL;

                    if (bf_list_new(&list, (bf_list_ops[]){{.free = (bf_list_ops_free)bf_matcher_free, .pack = (bf_list_ops_pack)bf_matcher_pack}}) < 0)
                        bf_parse_err("failed to allocate a new bf_list for bf_matcher\n");

                    $$ = TAKE_PTR(list);
                }
                | matchers matcher
                {
                    if (bf_list_add_tail($1, $2) < 0)
                        bf_parse_err("failed to insert matcher into bf_list\n");

                    TAKE_PTR($2);
                    $$ = TAKE_PTR($1);
                }
                ;
matcher         : matcher_type negate matcher_op RAW_PAYLOAD
                {
                    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
                    _cleanup_free_ const char *payload = $4;
                    int r;

                    r = bf_matcher_new_from_raw(&matcher, $1, $3, payload, $2);
                    if (r)
                        bf_parse_err("failed to create a new matcher\n");

                    $$ = TAKE_PTR(matcher);
                }
                | SET_TYPE negate matcher_op SET_RAW_PAYLOAD
                {
                     _free_bf_matcher_ struct bf_matcher *matcher = NULL;
                    _cleanup_free_ const char *raw_key = $1;
                    _cleanup_free_ const char *payload = $4;
                    enum bf_matcher_op op = $3;
                     int r;

                    if (op != BF_MATCHER_IN)
                        bf_parse_err("only the 'in' operator is supported for sets");

                    r = bf_matcher_new_for_anon_set_from_raw(&matcher, raw_key, payload, $2);
                    if (r)
                        bf_parse_err("failed to create a new matcher");

                     $$ = TAKE_PTR(matcher);
                }
                | SET_TYPE negate matcher_op STRING
                {
                    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
                    _cleanup_free_ const char *raw_key = $1;
                    _cleanup_free_ const char *name = $4;
                    struct bf_set *found_set = NULL;
                    _free_bf_set_ struct bf_set *test_key = NULL;
                    int r;

                    if ($3 != BF_MATCHER_IN)
                        bf_parse_err("only the 'in' operator is supported for sets");

                    r = bf_set_new_from_raw(&test_key, NULL, raw_key, "{}");
                    if (r)
                        bf_parse_err("failed to verify set key '%s'", raw_key);

                    found_set = bf_hashset_get(&ruleset->sets, &(struct bf_set){.name = name});

                    if (!found_set)
                        bf_parse_err("can't find set '%s'", name);

                    if (found_set->n_comps != test_key->n_comps || memcmp(found_set->key, test_key->key, found_set->n_comps * sizeof(enum bf_matcher_type)))
                        bf_parse_err("using named set '%s', but key doesn't match", name);

                    r = bf_matcher_new_for_named_set(&matcher, found_set, $2);
                    if (r)
                        bf_parse_err("failed to create a new matcher");

                     $$ = TAKE_PTR(matcher);
                }
                ;
negate          : %empty { $$ = false; }
                | NEGATE { $$ = true; }
                ;
matcher_type    : MATCHER_TYPE
                {
                    if (bf_matcher_type_from_str($1, &$$) < 0)
                        bf_parse_err("unknown matcher type '%s'\n", $1);
                    free($1);
                }
matcher_op      : %empty { $$ = BF_MATCHER_EQ; }
                | MATCHER_OP
                {
                    if (bf_matcher_op_from_str($1, &$$) < 0)
                        bf_parse_err("unknown matcher operator '%s'\n", $1);
                    free($1);
                }
                ;

%%
