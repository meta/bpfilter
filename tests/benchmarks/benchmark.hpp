/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <array>
#include <benchmark/benchmark.h>
#include <bpf/bpf.h>
#include <bpf/libbpf_common.h>
#include <cstdint>
#include <cstdio>
#include <format> // NOLINT: used by the logging macros
#include <git2/types.h>
#include <iostream> // NOLINT: used by the logging macros
#include <optional>
#include <span>
#include <string>
#include <sys/types.h> // NOLINT: for pid_t
#include <unistd.h>

extern "C" {
#include <bpfilter/bpfilter.h>
}

namespace bft
{

extern const int CGROUP_SKB_DROP;
extern const int CGROUP_SKB_ACCEPT;

/**
 * Dummy network packet, created using Python's `scapy` and the following
 * definition:
 *
 *  Ether(src=0x01, dst=0x02)/
 *  IPv6(src='::1', dst='::2')/
 *  TCP(sport=31337, dport=31415, flags='S')
 *
 * This packet defines an Ethernet, IPv6, and TCP header.
 */
extern const std::array<uint8_t, 80> pkt_local_ip6_tcp;

extern const std::array<uint8_t, 42> pkt_local_ip4_icmp;
extern const std::array<uint8_t, 54> pkt_local_ip4_tcp;
extern const std::array<uint8_t, 90> pkt_remote_ip6_eh;

/**
 * Number of iterations to run the program for.
 *
 * Google Benchmark will run each benchmark for a specific duration, so the
 * fastest functions will run for more iterations. This is problematic as
 * `BPF_PROG_TEST_RUN` requires a number of iterations. To solve this, we use
 * `KeepRunningBatch` in order to find out if we can run the benchmark for
 * `progRunRepeat` more iterations.
 *
 * `progRunRepeat` is big enough to have meaningful benchmark results and
 * reduce syscall overhead, while being small enough to avoid blocking the
 * system too long with longer benchmarks.
 */
extern const int progRunRepeat;

/**
 * Loop used to run the benchmark.
 *
 * Use this macro to loop over the state automatically.
 */
#define benchLoop(state) while ((state).KeepRunningBatch(::bft::progRunRepeat))

struct Config
{
public:
    ::std::string bfcli = "bfcli";
    ::std::string srcdir = ".";
    ::std::string outfile = "results.json";
    ::std::string gitrev = "<unknown>";
    ::std::optional<::std::string> adhoc;
    int adhocRepeat = 1;
    const ::std::string adhocBenchName = "bf_adhoc";
    int64_t gitdate = 0;

    Config() noexcept = default;
};

extern Config config;

int disableASLR(char **argv);
int setup(std::span<char *> args);
void restorePermissions(::std::string outfile);

class Sources
{
public:
    Sources(::std::string path);
    Sources(Sources &other) = delete;
    Sources(Sources &&other) = delete;
    ~Sources();

    Sources &operator=(Sources &other) = delete;
    Sources &operator=(Sources &&other) = delete;

    [[nodiscard]] ::std::string getLastCommitHash() const;
    [[nodiscard]] int64_t getLastCommitTime() const;
    [[nodiscard]] bool isDirty() const;

private:
    ::std::string path_;
    git_repository *repo_ = nullptr;
};

struct ProgRunStats
{
    uint32_t retval;
    uint32_t duration;
    uint32_t repeat;

    ProgRunStats(bpf_test_run_opts stats):
        retval {stats.retval},
        duration {stats.duration},
        repeat {static_cast<uint32_t>(stats.repeat)}
    {}

    /**
     * @brief Get the total duration of the runs, in seconds.
     *
     * `duration` is the average duration of a run, in nanoseconds.
     */
    [[nodiscard]] double seconds() const
    {
        return static_cast<double>(duration) * repeat / 1e9;
    }
};

class Program
{
private:
    int _fd;

public:
    Program(const std::string &chainName)
    {
        _fd = bf_chain_prog_fd(chainName.c_str());
        if (_fd < 0) {
            throw std::runtime_error(
                "failed to request BPF program file descriptor");
        }
    }

    ~Program()
    {
        close(_fd);
    }

    Program(Program &other) = delete;
    Program(Program &&other) = delete;
    Program &operator=(Program &other) = delete;
    Program &operator=(Program &&other) = delete;

    [[nodiscard]] ::std::size_t nInsn() const
    {
        struct bpf_prog_info prog_info = {};
        uint32_t prog_info_len = sizeof(prog_info);
        int r;

        r = bpf_prog_get_info_by_fd(_fd, &prog_info, &prog_info_len);
        if (r < 0)
            throw std::runtime_error("failed to get BPF program info");

        return prog_info.xlated_prog_len / sizeof(struct bpf_insn);
    }

    [[nodiscard]] ProgRunStats run(const std::span<const uint8_t> &pkt) const
    {
        LIBBPF_OPTS(
            bpf_test_run_opts, opts, .data_in = (const void *)pkt.data(),
            .data_size_in = (uint32_t)pkt.size(), .repeat = progRunRepeat);

        const int r = bpf_prog_test_run_opts(_fd, &opts);
        if (r < 0)
            throw std::runtime_error("failed to run BPF program");

        return {opts};
    }
};

} // namespace bft

namespace bft::benchmark
{

struct Flags
{
    bool use_set = false;
    bool use_log = false;
    bool userspace_only = false;
};

void set_flags(::benchmark::State &state, Flags flags);

} // namespace bft::benchmark
