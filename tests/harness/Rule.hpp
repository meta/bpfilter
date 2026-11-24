/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <memory>
#include <optional>
#include <stdexcept>
#include <tuple>
#include <vector>

#include "Matcher.hpp"

extern "C" {
#include <bpfilter/counter.h>
#include <bpfilter/rule.h>
#include <bpfilter/runtime.h>
#include <bpfilter/verdict.h>
}

namespace bf
{

class Rule
{
private:
    struct deleter
    {
        void operator()(bf_rule *ptr)
        {
            bf_rule_free(&ptr);
        }
    };

    bf_verdict _verdict;
    std::optional<struct bf_counter> _counters;
    uint8_t _log;
    std::optional<uint64_t> _logRateNs;
    std::vector<Matcher> _matchers;

public:
    Rule(bf_verdict verdict, std::vector<Matcher> matchers = {},
         std::optional<struct bf_counter> counters = std::nullopt,
         uint8_t log = 0, std::optional<uint64_t> logRateNs = std::nullopt):
        _verdict {verdict},
        _counters {counters},
        _log {log},
        _logRateNs {logRateNs},
        _matchers {std::move(matchers)}
    {}

    Rule &operator<<(Matcher &&matcher)
    {
        _matchers.push_back(matcher);

        return *this;
    }

    [[nodiscard]] std::unique_ptr<bf_rule, deleter>
    get(const bf_chain *chain = nullptr) const
    {
        struct bf_rule *rule;

        int r = bf_rule_new(&rule);
        if (r != 0)
            throw std::runtime_error("failed to create bf_rule");

        std::unique_ptr<bf_rule, deleter> owned(rule);

        rule->log = _log;
        rule->log_rate_ns = _logRateNs.value_or(0);
        rule->has_counters = _counters.has_value();
        rule->verdict = _verdict;

        for (const Matcher &matcher: _matchers) {
            auto bfmatcher = matcher.get(chain);

            r = bf_list_add_tail(&rule->matchers, bfmatcher.get());
            if (r != 0)
                throw std::runtime_error("failed to add bf_matcher to bf_rule");

            std::ignore = bfmatcher.release();
        }

        return owned;
    }
};

} // namespace bf
