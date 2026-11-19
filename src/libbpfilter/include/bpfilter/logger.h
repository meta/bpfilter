/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdio.h> // NOLINT: fprintf is used

#include <bpfilter/helper.h>

enum bf_color
{
    BF_COLOR_RESET = 0,

    BF_COLOR_DEFAULT = BF_FLAG(1),
    BF_COLOR_BLACK = BF_FLAG(2),
    BF_COLOR_RED = BF_FLAG(3),
    BF_COLOR_GREEN = BF_FLAG(4),
    BF_COLOR_YELLOW = BF_FLAG(5),
    BF_COLOR_BLUE = BF_FLAG(6),
    BF_COLOR_MAGENTA = BF_FLAG(7),
    BF_COLOR_CYAN = BF_FLAG(8),
    BF_COLOR_LIGHT_GRAY = BF_FLAG(9),
    BF_COLOR_DARK_GRAY = BF_FLAG(10),
    BF_COLOR_LIGHT_RED = BF_FLAG(11),
    BF_COLOR_LIGHT_GREEN = BF_FLAG(12),
    BF_COLOR_LIGHT_YELLOW = BF_FLAG(13),
    BF_COLOR_LIGHT_BLUE = BF_FLAG(14),
    BF_COLOR_LIGHT_MAGENTA = BF_FLAG(15),
    BF_COLOR_LIGHT_CYAN = BF_FLAG(16),
    BF_COLOR_WHITE = BF_FLAG(17),
};

enum bf_style
{
    BF_STYLE_RESET = 0,

    // First bit is for the weight.
    BF_STYLE_NORMAL = 0,
    BF_STYLE_BOLD = 1,
};

enum bf_log_level
{
    BF_LOG_DBG,
    BF_LOG_INFO,
    BF_LOG_WARN,
    BF_LOG_ERR,
    BF_LOG_ABORT,
    _BF_LOG_MAX,
};

#define _bf_logger_prefix_fmt "%s%-7s%s: "
#define _bf_logger_prefix_fmt_args(level, color)                               \
    bf_logger_get_color((color), BF_STYLE_BOLD), bf_log_level_to_str(level),   \
        bf_logger_get_color(BF_COLOR_RESET, BF_STYLE_RESET)

/**
 * Log an error message to stderr.
 *
 * @param level Log level of the message. Used to check if the log message
 *        should be printed, in which case the string representation of the log
 *        level will be used.
 * @param color Color to print the prefix with, as a @ref bf_color .
 * @param fmt Format string.
 * @param ... Format arguments.
 */
#define _bf_log_impl(level, color, fmt, ...)                                   \
    do {                                                                       \
        if (level >= bf_log_get_level()) {                                     \
            (void)fprintf(                                                     \
                stderr, _bf_logger_prefix_fmt fmt "\n",                        \
                _bf_logger_prefix_fmt_args(level, color), ##__VA_ARGS__);      \
        }                                                                      \
    } while (0)

#define bf_abort(fmt, ...)                                                     \
    ({                                                                         \
        _bf_log_impl(BF_LOG_ABORT, BF_COLOR_RED, fmt, ##__VA_ARGS__);          \
        abort();                                                               \
    })

#define bf_err(fmt, ...)                                                       \
    _bf_log_impl(BF_LOG_ERR, BF_COLOR_RED, fmt, ##__VA_ARGS__)

#define bf_warn(fmt, ...)                                                      \
    _bf_log_impl(BF_LOG_WARN, BF_COLOR_YELLOW, fmt, ##__VA_ARGS__)

#define bf_info(fmt, ...)                                                      \
    _bf_log_impl(BF_LOG_INFO, BF_COLOR_GREEN, fmt, ##__VA_ARGS__)

#define bf_dbg(fmt, ...)                                                       \
    _bf_log_impl(BF_LOG_DBG, BF_COLOR_BLUE, fmt, ##__VA_ARGS__)

/**
 * Log an error message to stderr, append the detail of the error code
 * provided and return the given error code.
 *
 * Convenience function to be used during error checks. It will log the error
 * message to stderr, append the detail of the error code provided and return
 * the given error code as a negative value. For example:
 *
 * @code{.c}
 *  if (ret < 0)
 *    return bf_err_r(ret, "failed to do something");
 * @endcode
 *
 * @param level Log level of the message. Used to check if the log message
 *        should be printed, in which case the string representation of the log
 *        level will be used.
 * @param color Color to print the prefix with, as a @ref bf_color .
 * @param code Error code, can be positive or negative.
 * @param fmt Format string.
 * @param ... Format arguments.
 * @return The given error code, as a negative value.
 */
#define _bf_log_code_impl(level, color, code, fmt, ...)                        \
    ({                                                                         \
        const int __code = (code);                                             \
        if ((level) >= bf_log_get_level()) {                                   \
            (void)fprintf(                                                     \
                stderr, _bf_logger_prefix_fmt fmt ": %s\n",                    \
                _bf_logger_prefix_fmt_args(level, color), ##__VA_ARGS__,       \
                bf_strerror(__code));                                          \
        }                                                                      \
        __code < 0 ? __code : -__code;                                         \
    })

#define bf_err_r(code, fmt, ...)                                               \
    _bf_log_code_impl(BF_LOG_ERR, BF_COLOR_RED, code, fmt, ##__VA_ARGS__)

#define bf_warn_r(code, fmt, ...)                                              \
    _bf_log_code_impl(BF_LOG_WARN, BF_COLOR_YELLOW, code, fmt, ##__VA_ARGS__)

#define bf_info_r(code, fmt, ...)                                              \
    _bf_log_code_impl(BF_LOG_INFO, BF_COLOR_GREEN, code, fmt, ##__VA_ARGS__)

#define bf_dbg_r(code, fmt, ...)                                               \
    _bf_log_code_impl(BF_LOG_DBG, BF_COLOR_BLUE, code, fmt, ##__VA_ARGS__)

/**
 * Identical to @ref _bf_log_impl but for @p va_list arguments.
 *
 * @param level Log level of the message. Used to check if the log message
 *        should be printed, in which case the string representation of the log
 *        level will be used.
 * @param color Color to print the prefix with, as a @ref bf_color .
 * @param fmt Format string.
 * @param vargs @p va_list of arguments.
 */
#define _bf_log_v_impl(level, color, fmt, vargs)                               \
    do {                                                                       \
        if ((level) >= bf_log_get_level()) {                                   \
            (void)fprintf(stderr, _bf_logger_prefix_fmt,                       \
                          _bf_logger_prefix_fmt_args(level, color));           \
            (void)vfprintf(stderr, (fmt), (vargs));                            \
            (void)fprintf(stderr, "\n");                                       \
        }                                                                      \
    } while (0)

#define bf_err_v(fmt, vargs)                                                   \
    _bf_log_v_impl(BF_LOG_ERR, BF_COLOR_RED, fmt, vargs)

#define bf_warn_v(fmt, vargs)                                                  \
    _bf_log_v_impl(BF_LOG_WARN, BF_COLOR_YELLOW, fmt, vargs)

#define bf_info_v(fmt, vargs)                                                  \
    _bf_log_v_impl(BF_LOG_INFO, BF_COLOR_GREEN, fmt, vargs)

#define bf_dbg_v(fmt, vargs)                                                   \
    _bf_log_v_impl(BF_LOG_DBG, BF_COLOR_BLUE, fmt, vargs)

/**
 * Initialise the logging system.
 *
 * Defines whether the logging system will print in colors or not. If both
 * `stdout` and `stderr` are TTYs, then `_bf_can_print_color` is set to true.
 */
void bf_logger_setup(void);

/**
 * Get color string for a given style.
 *
 * @p style can be a combination of @ref bf_style weight and color. If
 * `_bf_can_print_color` is set to false, then an empty string will be
 * returned so to not modify the output style.
 *
 * @param color Color identifier.
 * @param style Style identifier.
 * @return Style string.
 */
const char *bf_logger_get_color(enum bf_color color, enum bf_style style);

/**
 * Get the current log level.
 *
 * @return The current log level.
 */
enum bf_log_level bf_log_get_level(void);

/**
 * Set the current log level.
 *
 * All the log messages below this log level will be discarded. Defaults to
 * `BF_LOG_INFO`.
 *
 * @param level New log level.
 */
void bf_log_set_level(enum bf_log_level level);

/**
 * Convert a log level to a string.
 *
 * @param level Log level to convert to a string.
 * @return Log level, as a string.
 */
const char *bf_log_level_to_str(enum bf_log_level level);

/**
 * Convert a string to a log level.
 *
 * @param str String to convert to a `bf_log_level` value. Can't be NULL.
 * @return A `bf_log_level` value if `str` is a valid log level, `-EINVAL`
 *         otherwise.
 */
enum bf_log_level bf_log_level_from_str(const char *str);
