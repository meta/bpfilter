/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <algorithm>
#include <cmath>

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "test.hpp"

extern "C" {
#include <bpfilter/bpfilter.h>
}

/**
 * Number of runs used by the statistical cases below.
 *
 * Statistical model: bpf_get_prandom_u32() is treated as uniform on [0, 2^32)
 * and independent across runs, so each run is a Bernoulli trial and the match
 * count over N runs is Binomial(N, p). With N = 10000 the standard deviation
 * is sqrt(N * p * (1 - p)) <= 50 runs (0.5 points). The bounds checked below
 * are the expected count +/- 6 standard deviations. Under a Gaussian
 * approximation that is a false failure probability of about 2e-9 per case;
 * the exact binomial tail is larger for the rare-event case (about 2e-8 for
 * 99.9%), so the suite-wide risk over all hooks and cases stays in the 1e-7
 * range. The regression this guards against (meta/bpfilter#583: every
 * probability above 50% behaving like 100%, and like 0% when negated) is 25+
 * points away at 75%.
 */
static constexpr size_t kProbaRuns = 10000;

/**
 * Number of runs for the 99.9% case: with p = 0.999 the misses are the rare
 * event (expected N * 0.001), so N = 100000 gives 100 expected misses with a
 * standard deviation of about 10. The 6-sigma window is then roughly
 * [99840, 99960] matches (41 to 159 misses), which excludes the regression's
 * constant 100000.
 */
static constexpr size_t kProbaRunsRare = 100000;

/**
 * @brief Set a chain with a single DROP rule matching meta.probability eq `proba`
 * (optionally negated), run `runs` packets through it, and assert the DROP
 * count is within 6 standard deviations of `runs` * `rate`.
 *
 * @param test Current matcher test (provides the hook and verdicts).
 * @param proba Probability payload, in percent.
 * @param negate Whether to negate the matcher.
 * @param rate Expected match rate, in [0, 1].
 * @param runs Number of packets to run.
 */
static void _bft_assert_probability_rate(MatcherTest *test, float proba,
                                         bool negate, double rate, size_t runs)
{
    const auto pkt = bft::Ethernet() /
                     bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
                     bft::TCP {.sport = 12345, .dport = 80};

    BFT_CHAIN_SET(
        bf::Chain("test_meta_prob", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ,
                                 bft_float_payload(proba), negate)},
                    bf_counter()));

    const size_t matches = bft_prog_run_count("test_meta_prob", test->hook(),
                                              pkt, runs, test->verdictDrop());

    const double expected = static_cast<double>(runs) * rate;
    const double sigma =
        std::sqrt(static_cast<double>(runs) * rate * (1.0 - rate));
    const double lo = std::max(0.0, expected - 6.0 * sigma);
    const double hi =
        std::min(static_cast<double>(runs), expected + 6.0 * sigma);

    print_message(
        "meta.probability %s%.4f%%: %zu/%zu runs matched (%.2f%%), 6 sigma window [%.0f, %.0f]\n",
        negate ? "not " : "", proba, matches, runs,
        100.0 * static_cast<double>(matches) / static_cast<double>(runs), lo,
        hi);

    if (static_cast<double>(matches) < lo ||
        static_cast<double>(matches) > hi) {
        fail_msg(
            "meta.probability %s%.4f%%: %zu/%zu runs matched (%.2f%%), expected %.0f +/- %.0f (6 sigma, [%.0f, %.0f])",
            negate ? "not " : "", proba, matches, runs,
            100.0 * static_cast<double>(matches) / static_cast<double>(runs),
            expected, 6.0 * sigma, lo, hi);
    }

    // The rule counter must agree with the verdicts we observed.
    bft_assert_counter_eq("test_meta_prob", 0, matches, -1);
}

/**
 * Verify meta.probability matches at the configured rate on both sides of the
 * 50% boundary, where the threshold crosses INT32_MAX (meta/bpfilter#583).
 */
static void _bft_meta_probability_eq_rate(MatcherTest *test)
{
    // Exactly 50%: threshold 0x7fffffff fits in a signed 32-bit immediate.
    _bft_assert_probability_rate(test, 50.0f, false, 0.50, kProbaRuns);
    // A value just above 50%, whose threshold no longer fits in a signed
    // 32-bit immediate (0x8000a7ad).
    _bft_assert_probability_rate(test, 50.001f, false, 0.50001, kProbaRuns);
    _bft_assert_probability_rate(test, 51.0f, false, 0.51, kProbaRuns);
    _bft_assert_probability_rate(test, 75.0f, false, 0.75, kProbaRuns);
    _bft_assert_probability_rate(test, 99.9f, false, 0.999, kProbaRunsRare);
    // Negated 75% must match 25% of the time, not 0%.
    _bft_assert_probability_rate(test, 75.0f, true, 0.25, kProbaRuns);
}

/**
 * Verify meta.probability eq at 100% always matches and at 0% does not match
 * on a single run. 100% is exact (threshold UINT32_MAX). 0% keeps a threshold
 * of 0, so the rule still matches when the random value is exactly 0
 * (probability 2^-32 under the current threshold formula, shared with
 * meta.flow_probability); a single run is used as a practical check only.
 */
static void meta_probability_eq(void **state)
{
    auto *test = static_cast<MatcherTest *>(*state);

    // 100.0f always matches
    BFT_CHAIN_SET(
        bf::Chain("test_meta_prob", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ,
                                 bft_float_payload(100.0f))},
                    bf_counter()));

    bft_assert_prog_run(
        "test_meta_prob", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_meta_prob", 0, 1, -1);

    // 0.0f is not expected to match on a single run (see above)
    BFT_CHAIN_SET(
        bf::Chain("test_meta_prob", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ,
                                 bft_float_payload(0.0f))},
                    bf_counter()));

    bft_assert_prog_run(
        "test_meta_prob", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_prob", 0, 0, -1);

    // Negated 100.0f should never match
    BFT_CHAIN_SET(
        bf::Chain("test_meta_prob", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ,
                                 bft_float_payload(100.0f), true)},
                    bf_counter()));

    bft_assert_prog_run(
        "test_meta_prob", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictAccept());

    bft_assert_counter_eq("test_meta_prob", 0, 0, -1);

    // Negated 0.0f is expected to match on a single run (see above)
    BFT_CHAIN_SET(
        bf::Chain("test_meta_prob", test->hook(), BF_VERDICT_ACCEPT)
        << bf::Rule(BF_VERDICT_DROP,
                    {bf::Matcher(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ,
                                 bft_float_payload(0.0f), true)},
                    bf_counter()));

    bft_assert_prog_run(
        "test_meta_prob", test->hook(),
        bft::Ethernet() /
            bft::IPv4 {.saddr = "192.0.2.1", .daddr = "192.0.2.2"} /
            bft::TCP {.sport = 12345, .dport = 80},
        test->verdictDrop());

    bft_assert_counter_eq("test_meta_prob", 0, 1, -1);

    _bft_meta_probability_eq_rate(test);
}

int main()
{
    auto suite = MatcherTestsSuite(BF_MATCHER_META_PROBABILITY);

    suite << MatcherTest(BF_MATCHER_META_PROBABILITY, BF_MATCHER_EQ,
                         meta_probability_eq);

    return suite.run();
}
