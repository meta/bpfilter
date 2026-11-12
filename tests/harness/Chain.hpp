/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <memory>
#include <tuple>
#include <vector>

extern "C" {
#include <bpfilter/chain.h>
#include <bpfilter/hook.h>
#include <bpfilter/verdict.h>
}

#include "Rule.hpp"
#include "Set.hpp"

namespace bf
{

class Chain
{
private:
    struct deleter
    {
        void operator()(bf_chain *ptr)
        {
            bf_chain_free(&ptr);
        }
    };

    std::string _name;
    bf_hook _hook;
    bf_verdict _policy;
    std::vector<Set> _sets;
    std::vector<Rule> _rules;

public:
    Chain(std::string name, bf_hook hook, bf_verdict policy,
          std::vector<Set> sets = {}, std::vector<Rule> rules = {}):
        _name {std::move(name)},
        _hook {hook},
        _policy {policy},
        _sets {std::move(sets)},
        _rules {std::move(rules)}
    {}

    [[nodiscard]] std::string name() const
    {
        return _name;
    }

    Chain &operator<<(Rule &&rule)
    {
        _rules.push_back(std::move(rule));

        return *this;
    }

    Chain &operator<<(Rule &rule)
    {
        _rules.push_back(rule);

        return *this;
    }

    Chain &operator<<(Set &&set)
    {
        _sets.push_back(set);

        return *this;
    }

    Chain &operator<<(Set &set)
    {
        _sets.push_back(set);

        return *this;
    }

    [[nodiscard]] std::unique_ptr<bf_chain, deleter> get() const
    {
        struct bf_chain *chain;

        int r = bf_chain_new(&chain, _name.c_str(), _hook, _policy, nullptr,
                             nullptr, nullptr);
        if (r != 0)
            throw std::runtime_error("failed to create bf_chain");

        std::unique_ptr<bf_chain, deleter> owned(chain);

        for (const Set &set: _sets) {
            if (bf_set_is_anonymous(set.ref().get()))
                continue;

            auto bfset = set.get();
            r = bf_chain_add_set(chain, bfset.get());
            if (r != 0) {
                throw std::runtime_error("failed to add bf_set to bf_chain");
            }

            std::ignore = bfset.release();
        }

        for (const Rule &rule: _rules) {
            auto bfrule = rule.get(chain);
            r = bf_chain_add_rule(chain, bfrule.get());
            if (r != 0) {
                throw std::runtime_error("failed to add bf_rule to bf_chain");
            }

            std::ignore = bfrule.release();
        }

        return owned;
    }
};

} // namespace bf
