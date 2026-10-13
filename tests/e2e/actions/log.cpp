/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "Set.hpp"
#include "test.hpp"

extern "C" {
#include <bpf/libbpf.h>

#include <bpfilter/bpfilter.h>
}

namespace
{

static void logsFdSurvivesSetUpdate(void **state)
{
    _cleanup_close_ int fd = -1;
    struct bft_log_capture capture;
    struct ring_buffer *rb;
    auto set = bf::Set({BF_MATCHER_UDP_DPORT}, "ports");
    auto to_add = bf::Set({BF_MATCHER_UDP_DPORT}, "ports");
    auto to_remove = bf::Set({BF_MATCHER_UDP_DPORT}, "ports");

    (void)state;

    set << bft_port_be(53);
    BFT_CHAIN_SET(
        bf::Chain("test_log_update_set", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, std::nullopt, BF_LOG_OPT_DEFAULT,
                    {bf::Matcher::in(set)}));

    assert_fd(fd = bf_chain_logs_fd("test_log_update_set"));
    assert_non_null(
        rb = ring_buffer__new(fd, bft_capture_log, &capture, nullptr));

    to_add << bft_port_be(5353);
    assert_ok(bf_chain_update_set("test_log_update_set", to_add.get().get(),
                                  to_remove.get().get()));
    bft_assert_prog_run("test_log_update_set", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} /
                            bft::UDP {.sport = 12345, .dport = 5353},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assert_int_equal(1, capture.entries.size());

    ring_buffer__free(rb);
}

static void logsFdSurvivesEmptySet(void **state)
{
    _cleanup_close_ int fd = -1;
    _cleanup_close_ int empty_fd = -1;
    struct bft_log_capture capture;
    struct ring_buffer *rb;
    auto set = bf::Set({BF_MATCHER_UDP_DPORT}, "ports");
    auto none = bf::Set({BF_MATCHER_UDP_DPORT}, "ports");
    auto port = bf::Set({BF_MATCHER_UDP_DPORT}, "ports");

    (void)state;

    set << bft_port_be(53);
    port << bft_port_be(53);
    BFT_CHAIN_SET(
        bf::Chain("test_log_empty_set", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
        << set
        << bf::Rule(BF_VERDICT_DROP, std::nullopt, BF_LOG_OPT_DEFAULT,
                    {bf::Matcher::in(set)}));

    assert_fd(fd = bf_chain_logs_fd("test_log_empty_set"));
    assert_non_null(
        rb = ring_buffer__new(fd, bft_capture_log, &capture, nullptr));

    /* Emptying the set disables the only logging rule: the chain doesn't log
     * anymore, but it keeps its logs buffer. */
    assert_ok(bf_chain_update_set("test_log_empty_set", none.get().get(),
                                  port.get().get()));
    bft_assert_prog_run("test_log_empty_set", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} /
                            bft::UDP {.sport = 12345, .dport = 53},
                        bft_hook_accept(BF_HOOK_XDP));
    assert_int_equal(0, ring_buffer__consume(rb));
    assert_fd(empty_fd = bf_chain_logs_fd("test_log_empty_set"));
    assert_int_equal(bft_map_id(fd), bft_map_id(empty_fd));

    // Refilling the set enables the rule again
    assert_ok(bf_chain_update_set("test_log_empty_set", port.get().get(),
                                  none.get().get()));
    bft_assert_prog_run("test_log_empty_set", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} /
                            bft::UDP {.sport = 12345, .dport = 53},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assert_int_equal(1, capture.entries.size());

    ring_buffer__free(rb);
}

} // namespace

int main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(logsFdSurvivesSetUpdate,
                                        bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
        cmocka_unit_test_setup_teardown(logsFdSurvivesEmptySet,
                                        bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
    };

    return cmocka_run_group_tests(tests, bft_e2e_setup, bft_e2e_teardown);
}
