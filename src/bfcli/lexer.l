/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

%{
    #include <stdio.h>
    #include <stdbool.h>
    #include <stdlib.h>

    #include <bpfilter/verdict.h>
    #include <bpfilter/hook.h>
    #include <bpfilter/matcher.h>

    #include "parser.h"

    extern int yy_read_buf_size;
%}

%option noyywrap
%option noinput
%option nounput

%s STATE_HOOK_OPTS
%s STATE_MARK_OPTS
%s STATE_LOG_EVERY
%s STATE_REDIRECT_IFACE
%s STATE_REDIRECT_DIR
%s STATE_MATCHER_SET
%s STATE_MATCHER_META_IFACE
%s STATE_MATCHER_META_L3_PROTO
%s STATE_MATCHER_META_MARK
%s STATE_MATCHER_META_FLOW_HASH
%s STATE_MATCHER_META_PID
%s STATE_MATCHER_L4_PROTO
%s STATE_MATCHER_META_PROBA
%s STATE_MATCHER_IPV4_ADDR
%s STATE_MATCHER_IP4_NET
%s STATE_MATCHER_IP4_DSCP
%s STATE_MATCHER_IP6_ADDR
%s STATE_MATCHER_IP6_NET
%s STATE_MATCHER_IP6_DSCP
%s STATE_MATCHER_PORT
%s STATE_MATCHER_ICMP_TYPE
%s STATE_MATCHER_ICMP_CODE
%s STATE_MATCHER_TCP_FLAGS
%s STATE_MATCHER_META_LIMIT

int             (-|(0x))?[0-9a-zA-Z]+
float           [0-9]+(\.[0-9]+)?
%%

[ \t\n]         ;
"#".*           ;

chain           { return CHAIN; }
rule            { return RULE; }
set             { return SET; }

    /* Keywords */
not             { return NEGATE; }
counter         { return COUNTER; }

    /* Hooks */
BF_HOOK_[A-Z0-9_]+ { BEGIN(STATE_HOOK_OPTS); yylval.sval = strdup(yytext); return HOOK; }
<STATE_HOOK_OPTS>{
    (\{|,) /* Ignore */
    \} { BEGIN(INITIAL); }
    [a-zA-Z0-9_]+=[a-zA-Z0-9_\-\.\/]+ {
        yylval.sval = strdup(yytext);
        return RAW_HOOKOPT;
    }
}
    /* Verdicts */
(ACCEPT|DROP|CONTINUE|NEXT)   { yylval.sval = strdup(yytext); return VERDICT; }
REDIRECT                 { BEGIN(STATE_REDIRECT_IFACE); return REDIRECT_TOKEN; }
<STATE_REDIRECT_IFACE>{
    {int}|[0-9a-zA-Z_-]+ {
        BEGIN(STATE_REDIRECT_DIR);
        yylval.sval = strdup(yytext);
        return REDIRECT_IFACE;
    }
}
<STATE_REDIRECT_DIR>{
    (in|out) {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return REDIRECT_DIR;
    }
}

    /* Mark */
mark            { BEGIN(STATE_MARK_OPTS); return MARK; }
<STATE_MARK_OPTS>{
    {int} {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return STRING;
    }
}

    /* Logs */
log             { return LOG; }
every           { BEGIN(STATE_LOG_EVERY); return EVERY; }
<STATE_LOG_EVERY>{
    {float}[a-z]+ {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return STRING;
    }
}

    /* Sets */
\([ \t\n\r\f\v]*([a-zA-Z0-9_]+\.[a-zA-Z0-9_]+)([ \t\n\r\f\v]*,[ \t\n\r\f\v]*([a-zA-Z0-9_]+\.[a-zA-Z0-9_]+))*[ \t\n\r\f\v]*\) {
    BEGIN(STATE_MATCHER_SET);
    yylval.sval = strdup(yytext);
    return SET_TYPE;
}
<STATE_MATCHER_SET>{
    (in) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    min-size=[0-9]+ {
        /* bpfilter only support min-size= as option for now, if we introduce
         * new option, we should implement a generic way of parsing options. */
        yylval.u64 = strtoull(yytext + sizeof("min-size=") - 1, NULL, 10);
        return SET_MIN_SIZE;
    }
    \{[^}]*\} {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return SET_RAW_PAYLOAD;
    }
}

    /* Matcher types */
meta\.iface  { BEGIN(STATE_MATCHER_META_IFACE); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_META_IFACE>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}|[0-9a-zA-Z-]+ {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

meta\.l3_proto  { BEGIN(STATE_MATCHER_META_L3_PROTO); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_META_L3_PROTO>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}|[0-9a-zA-Z-]+ {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

meta\.l4_proto  { BEGIN(STATE_MATCHER_L4_PROTO); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
ip4\.proto      { BEGIN(STATE_MATCHER_L4_PROTO); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
ip6\.nexthdr    { BEGIN(STATE_MATCHER_L4_PROTO); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_L4_PROTO>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}|[0-9a-zA-Z-]+ {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

meta\.probability  { BEGIN(STATE_MATCHER_META_PROBA); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
meta\.flow_probability { BEGIN(STATE_MATCHER_META_PROBA); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_META_PROBA>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {float}% {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

meta\.mark          { BEGIN(STATE_MATCHER_META_MARK); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_META_MARK>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int} {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

meta\.flow_hash     { BEGIN(STATE_MATCHER_META_FLOW_HASH); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_META_FLOW_HASH>{
    (eq|range) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}(-{int})? {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

meta\.pid           { BEGIN(STATE_MATCHER_META_PID); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_META_PID>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int} {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

meta\.limit  { BEGIN(STATE_MATCHER_META_LIMIT); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_META_LIMIT>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}\/[a-zA-Z] {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

ip4\.saddr       { BEGIN(STATE_MATCHER_IPV4_ADDR); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
ip4\.daddr       { BEGIN(STATE_MATCHER_IPV4_ADDR); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_IPV4_ADDR>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}\.{int}\.{int}\.{int} {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

ip4\.snet       { BEGIN(STATE_MATCHER_IP4_NET); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
ip4\.dnet       { BEGIN(STATE_MATCHER_IP4_NET); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_IP4_NET>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}\.{int}\.{int}\.{int}\/{int} {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

ip4\.dscp       { BEGIN(STATE_MATCHER_IP4_DSCP); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_IP4_DSCP>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}|[0-9a-zA-Z-]+ {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

ip6\.(s|d)addr      { BEGIN(STATE_MATCHER_IP6_ADDR); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_IP6_ADDR>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    [a-zA-Z0-9:]+ {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

ip6\.(s|d)net       { BEGIN(STATE_MATCHER_IP6_NET); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_IP6_NET>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    [a-zA-Z0-9:\/]+ {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

ip6\.dscp           { BEGIN(STATE_MATCHER_IP6_DSCP); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_IP6_DSCP>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}|[0-9a-zA-Z-]+ {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

meta\.(s|d)port { BEGIN(STATE_MATCHER_PORT); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
tcp\.(s|d)port  { BEGIN(STATE_MATCHER_PORT); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
udp\.(s|d)port  { BEGIN(STATE_MATCHER_PORT); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_PORT>{
    (eq|range) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}(-{int})? {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

icmp(v6)?\.type { BEGIN(STATE_MATCHER_ICMP_TYPE); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_ICMP_TYPE>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int}|[0-9a-zA-Z-]+ {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

icmp(v6)?\.code { BEGIN(STATE_MATCHER_ICMP_CODE); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_ICMP_CODE>{
    (eq) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    {int} {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

tcp\.flags      { BEGIN(STATE_MATCHER_TCP_FLAGS); yylval.sval = strdup(yytext); return MATCHER_TYPE; }
<STATE_MATCHER_TCP_FLAGS>{
    (eq|any|all) { yylval.sval = strdup(yytext); return MATCHER_OP; }
    ([a-zA-Z]+,?)+ {
        BEGIN(INITIAL);
        yylval.sval = strdup(yytext);
        return RAW_PAYLOAD;
    }
}

[a-zA-Z0-9_-]+  { yylval.sval = strdup(yytext); return STRING; }

.               { return *yytext; }

%%
