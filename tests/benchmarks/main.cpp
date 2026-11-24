/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <benchmark/benchmark.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <exception>
#include <format>
#include <iostream>
#include <memory>
#include <random>
#include <span>
#include <stdexcept>
#include <unistd.h>
#include <vector>

extern "C" {
#include <bpfilter/bpfilter.h>
#include <bpfilter/ctx.h>
#include <bpfilter/hook.h>
#include <bpfilter/matcher.h>
#include <bpfilter/runtime.h>
#include <bpfilter/verdict.h>
}

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "Set.hpp"
#include "benchmark.hpp"

namespace
{

using bf::Chain;
using bf::Matcher;
using bf::Rule;
using bf::Set;
namespace bm = bft::benchmark;

std::vector<uint8_t> uint32ToIp4(uint32_t val)
{
    return {static_cast<uint8_t>(val >> 24), static_cast<uint8_t>(val >> 16),
            static_cast<uint8_t>(val >> 8), static_cast<uint8_t>(val)};
}

std::vector<uint8_t> uint32ToIp6(uint32_t val)
{
    return {
        static_cast<uint8_t>(val >> 24),
        static_cast<uint8_t>(val >> 16),
        static_cast<uint8_t>(val >> 8),
        static_cast<uint8_t>(val),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    };
}

void chain_policy_c(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_DROP);

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip4_icmp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("chain policy, with counter");
}

BENCHMARK(chain_policy_c)->UseManualTime();

void xdp__prologue(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip6_tcp);
        if (stats.retval != XDP_PASS)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("XDP prologue, accept policy");
}

BENCHMARK(xdp__prologue)->UseManualTime();

void tc__prologue(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_TC_INGRESS, BF_VERDICT_ACCEPT);

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    // TC_ACT_OK = 0
    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip6_tcp);
        if (stats.retval != 0)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("TC prologue, accept policy");
}

BENCHMARK(tc__prologue)->UseManualTime();

void cgroup_skb__prologue(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_CGROUP_SKB_INGRESS, BF_VERDICT_ACCEPT);

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip6_tcp);
        if (stats.retval != ::bft::CGROUP_SKB_ACCEPT)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("CGroup skb prologue, accept policy");
}

BENCHMARK(cgroup_skb__prologue)->UseManualTime();

void netfilter__prologue(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_NF_LOCAL_IN, BF_VERDICT_ACCEPT);

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    /* Without a context, BPF_PROG_TEST_RUN runs a Netfilter program as an
     * IPv4 NF_INET_LOCAL_OUT hook: the data starts at the IPv4 header. */
    const auto pkt = std::span(::bft::pkt_local_ip4_tcp).subspan(ETH_HLEN);

    // NF_ACCEPT = 1
    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(pkt);
        if (stats.retval != 1)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("Netfilter prologue, accept policy");
}

BENCHMARK(netfilter__prologue)->UseManualTime();

void single_rule__ip4_saddr(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP,
                  std::vector<Matcher> {
                      Matcher(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                              {0x7f, 0x02, 0x0a, 0x0a}),
                  });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip4_icmp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, ip4.saddr");
}

BENCHMARK(single_rule__ip4_saddr)->UseManualTime();

void multiple_rules__ip4_saddr(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);

    uint32_t nrules = state.range(0);
    for (uint32_t i = 0; i < nrules - 1; ++i) {
        chain << Rule(
            BF_VERDICT_DROP,
            std::vector<Matcher> {
                Matcher(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ, uint32ToIp4(i)),
            });
    }

    chain << Rule(BF_VERDICT_DROP,
                  std::vector<Matcher> {
                      Matcher(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                              {0x7f, 0x02, 0x0a, 0x0a}),
                  });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip4_icmp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel(std::format("{} rules, ip4.saddr", nrules));
}

BENCHMARK(multiple_rules__ip4_saddr)
    ->Arg(8)
    ->Arg(32)
    ->Arg(128)
    ->UseManualTime();

void single_rule__ip4_saddr__x_elem_set(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);

    Set s = Set({BF_MATCHER_IP4_SADDR});

    uint32_t nrules = state.range(0);
    for (uint32_t i = 0; i < nrules - 1; ++i)
        s << uint32ToIp4(i);

    s << std::vector<uint8_t> {0x7f, 0x02, 0x0a, 0x0a};

    chain << Rule(BF_VERDICT_DROP, std::vector<Matcher> {
                                       Matcher::in(s),
                                   });

    chain << s;

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip4_icmp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    bm::set_flags(state, {.use_set = true});
    state.SetLabel(std::format("1 rule, ip4.saddr, {} elements set", nrules));
}

BENCHMARK(single_rule__ip4_saddr__x_elem_set)
    ->Arg(1 << 3)
    ->Arg(1 << 7)
    ->Arg(1 << 15)
    ->UseManualTime();

void chain_set__ip4_saddr__x_elem_set(::benchmark::State &state)
{
    const std::string chain_name = "bf_benchmark";
    Chain chain(chain_name, BF_HOOK_XDP, BF_VERDICT_ACCEPT);

    Set s = Set({BF_MATCHER_IP4_SADDR});
    uint32_t nelems = state.range(0);
    for (uint32_t i = 0; i < nelems; ++i)
        s << uint32ToIp4(i);
    chain << s;

    chain << Rule(BF_VERDICT_DROP, std::vector<Matcher> {
                                       Matcher::in(s),
                                   });

    auto chainp = chain.get();

    for (auto _: state) {
        int ret = bf_chain_set(chainp.get(), nullptr);
        if (ret < 0) {
            state.SkipWithError("failed to load chain");
            break;
        }

        state.PauseTiming();
        ret = bf_chain_flush(chain_name.c_str());
        if (ret < 0) {
            state.SkipWithError("failed to flush chain");
            break;
        }
        state.ResumeTiming();
    }

    bm::set_flags(state, {.use_set = true, .userspace_only = true});
    state.SetLabel(
        std::format("load chain, ip4.saddr, {} elements set", nelems));
}

BENCHMARK(chain_set__ip4_saddr__x_elem_set)
    ->Arg(1 << 3)
    ->Arg(1 << 16)
    ->Arg(1 << 20)
    ->Unit(::benchmark::kMillisecond);

void chain_set__1000_ip4_saddr__x_elem_sets_c_l(::benchmark::State &state)
{
    constexpr uint32_t nrules = 1000;
    const uint32_t nelems = state.range(0);
    Chain chain("bf_bench_generation", BF_HOOK_XDP, BF_VERDICT_ACCEPT);

    for (uint32_t i = 0; i < 4; ++i) {
        Set set({BF_MATCHER_IP4_SADDR});

        for (uint32_t j = 0; j < nelems; ++j)
            set << uint32ToIp4(j);

        chain << set;
        chain << Rule(BF_VERDICT_DROP, {Matcher::in(set)}, bf_counter());
    }

    // Keep the random IPv4 matches identical across runs and set sizes.
    std::mt19937 random(0);
    for (uint32_t i = 4; i < nrules; ++i) {
        // Only log from the 5th rule to trigger ring buffer creation
        const uint8_t log = i == 4 ? BF_FLAG(BF_LOG_OPT_5_TUPLE) : 0;
        chain << Rule(BF_VERDICT_DROP,
                      {Matcher(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                               uint32ToIp4(static_cast<uint32_t>(random())))},
                      bf_counter(), log);
    }

    auto chainp = chain.get();

    // Measure CPU time for the C API call, including generation and loading.
    // Construct the input once and exclude unloading between iterations.
    for (auto _: state) {
        int ret = bf_chain_set(chainp.get(), NULL);
        if (ret < 0) {
            state.SkipWithError("failed to generate and load chain");
            break;
        }

        state.PauseTiming();
        ret = bf_chain_flush(chain.name().c_str());
        if (ret < 0) {
            state.SkipWithError("failed to flush chain");
            break;
        }
        state.ResumeTiming();
    }

    bm::set_flags(state,
                  {.use_set = true, .use_log = true, .userspace_only = true});
    state.SetLabel(
        "load chain, 1000 ip4.saddr rules with counters, 4 sets, logging");
}

BENCHMARK(chain_set__1000_ip4_saddr__x_elem_sets_c_l)
    ->Arg(1 << 3)
    ->Arg(1 << 16)
    ->Arg(1 << 20)
    ->Unit(::benchmark::kMillisecond);

void single_rule__ip4_saddr_c(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP,
                  std::vector<Matcher> {
                      Matcher(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                              {0x7f, 0x02, 0x0a, 0x0a}),
                  },
                  bf_counter());

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip4_icmp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, ip4.saddr, counter");
}

BENCHMARK(single_rule__ip4_saddr_c)->UseManualTime();

void single_rule__ip4_saddr_l(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP,
                  std::vector<Matcher> {
                      Matcher(BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                              {0x7f, 0x02, 0x0a, 0x0a}),
                  },
                  std::nullopt, BF_FLAG(BF_LOG_OPT_LINK));

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip4_icmp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    bm::set_flags(state, {.use_log = true});
    state.SetLabel("1 rule, ip4.saddr, log link");
}

BENCHMARK(single_rule__ip4_saddr_l)->UseManualTime();

void single_rule__ip6_saddr(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP,
                  std::vector<Matcher> {
                      Matcher(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                              {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
                  });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip6_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, ip6.saddr");
}

BENCHMARK(single_rule__ip6_saddr)->UseManualTime();

void multiple_rules__ip6_saddr(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);

    uint32_t nrules = state.range(0);
    for (uint32_t i = 0; i < nrules - 1; ++i) {
        chain << Rule(
            BF_VERDICT_DROP,
            std::vector<Matcher> {
                Matcher(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ, uint32ToIp6(i)),
            });
    }

    chain << Rule(BF_VERDICT_DROP,
                  std::vector<Matcher> {
                      Matcher(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                              {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
                  });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip6_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel(std::format("{} rules, ip6.saddr", nrules));
}

BENCHMARK(multiple_rules__ip6_saddr)
    ->Arg(8)
    ->Arg(32)
    ->Arg(128)
    ->UseManualTime();

void single_rule__ip6_saddr__x_elem_set(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);

    Set s = Set({BF_MATCHER_IP6_SADDR});

    uint32_t nrules = state.range(0);
    for (uint32_t i = 0; i < nrules - 1; ++i)
        s << uint32ToIp6(i);

    s << std::vector<uint8_t> {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    chain << Rule(BF_VERDICT_DROP, std::vector<Matcher> {
                                       Matcher::in(s),
                                   });

    chain << s;

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip6_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    bm::set_flags(state, {.use_set = true});
    state.SetLabel(std::format("1 rule, ip6.saddr, {} elements set", nrules));
}

BENCHMARK(single_rule__ip6_saddr__x_elem_set)
    ->Arg(1 << 3)
    ->Arg(1 << 7)
    ->Arg(1 << 15)
    ->UseManualTime();

void single_rule__ip6_saddr_c(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP,
                  std::vector<Matcher> {
                      Matcher(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                              {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
                  },
                  bf_counter());

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip6_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, ip6.saddr, counter");
}

BENCHMARK(single_rule__ip6_saddr_c)->UseManualTime();

void single_rule__ip6_saddr_l(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP,
                  std::vector<Matcher> {
                      Matcher(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                              {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
                  },
                  std::nullopt, BF_FLAG(BF_LOG_OPT_LINK));

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip6_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    bm::set_flags(state, {.use_log = true});
    state.SetLabel("1 rule, ip6.saddr, log link");
}

BENCHMARK(single_rule__ip6_saddr_l)->UseManualTime();

void single_rule__ip6_nexthdr(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP, std::vector<Matcher> {
                                       Matcher(BF_MATCHER_IP6_NEXTHDR,
                                               BF_MATCHER_EQ, {0x00, 0x00}),
                                   });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_remote_ip6_eh);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, ip6.nexthdr");
}

BENCHMARK(single_rule__ip6_nexthdr)->UseManualTime();

void single_rule__meta_sport_eq(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP, std::vector<Matcher> {
                                       Matcher(BF_MATCHER_META_SPORT,
                                               BF_MATCHER_EQ, {0x00, 0x17}),
                                   });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip4_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, meta.sport eq");
}

BENCHMARK(single_rule__meta_sport_eq)->UseManualTime();

void single_rule__meta_sport_range(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP,
                  std::vector<Matcher> {
                      Matcher(BF_MATCHER_META_SPORT, BF_MATCHER_RANGE,
                              {0x16, 0x00, 0x18, 0x00}),
                  });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip4_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, meta.sport range");
}

BENCHMARK(single_rule__meta_sport_range)->UseManualTime();

void single_rule__tcp_sport(::benchmark::State &state)
{
    Chain chain("bf_benchmark", BF_HOOK_XDP, BF_VERDICT_ACCEPT);
    chain << Rule(BF_VERDICT_DROP, std::vector<Matcher> {
                                       Matcher(BF_MATCHER_TCP_SPORT,
                                               BF_MATCHER_EQ, {0x00, 0x17}),
                                   });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip4_tcp);
        if (stats.retval != XDP_DROP)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, tcp.sport");
}

BENCHMARK(single_rule__tcp_sport)->UseManualTime();

void single_rule__meta_flow_hash(::benchmark::State &state)
{
    // meta.flow_hash is only supported on TC hooks
    Chain chain("bf_benchmark", BF_HOOK_TC_INGRESS, BF_VERDICT_ACCEPT);

    // Match flow hash in full range 0-UINT32_MAX (little-endian uint32_t: min, max)
    chain << Rule(BF_VERDICT_DROP,
                  std::vector<Matcher> {
                      Matcher(BF_MATCHER_META_FLOW_HASH, BF_MATCHER_RANGE,
                              {0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}),
                  });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    // TC_ACT_SHOT = 2 for DROP
    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip4_tcp);
        if (stats.retval != 2)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, meta.flow_hash");
}

BENCHMARK(single_rule__meta_flow_hash)->UseManualTime();

void single_rule__meta_flow_probability(::benchmark::State &state)
{
    // meta.flow_probability is supported on XDP, TC, and CGROUP_SKB hooks
    Chain chain("bf_benchmark", BF_HOOK_TC_INGRESS, BF_VERDICT_ACCEPT);

    // Match with 100% probability (float payload: 100.0f = 100%)
    float prob = 100.0f;
    std::vector<uint8_t> payload(sizeof(float));
    std::memcpy(payload.data(), &prob, sizeof(float));

    chain << Rule(BF_VERDICT_DROP, std::vector<Matcher> {
                                       Matcher(BF_MATCHER_META_FLOW_PROBABILITY,
                                               BF_MATCHER_EQ, payload),
                                   });

    auto chainp = chain.get();
    int ret = bf_chain_set(chainp.get(), nullptr);
    if (ret < 0)
        throw std::runtime_error("failed to load chain");

    auto prog = bft::Program(chain.name());

    // TC_ACT_SHOT = 2 for DROP
    while (state.KeepRunningBatch(::bft::progRunRepeat)) {
        auto stats = prog.run(::bft::pkt_local_ip4_tcp);
        if (stats.retval != 2)
            state.SkipWithError("benchmark run failed");

        state.SetIterationTime(stats.seconds());
    }

    state.counters["nInsn"] = prog.nInsn();
    state.SetLabel("1 rule, meta.flow_probability");
}

BENCHMARK(single_rule__meta_flow_probability)->UseManualTime();

} // namespace

int main(int argc, char *argv[])
{
    if (geteuid() != 0)
        return bf_err_r(-EPERM, "the benchmark should be run as root");

    if (::bft::disableASLR(argv) < 0)
        return -1;

    if (::bft::setup(std::span<char *>(argv, argc)) < 0)
        return -1;

    ::bft::restorePermissions(::bft::config.outfile);

    int r = bf_ctx_setup(false, "/sys/fs/bpf", 0);
    if (r < 0)
        return bf_err_r(r, "failed to initialise bpfilter context");

    bf_log_set_level(BF_LOG_WARN);

    try {
        ::benchmark::RunSpecifiedBenchmarks();
    } catch (const ::std::exception &e) {
        bf_err("failed to run benchmark: %s", e.what());
        bf_ctx_teardown();
        return -1;
    }

    ::benchmark::Shutdown();
    bf_ctx_teardown();

    return 0;
}
