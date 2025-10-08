/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2025 Yeuham Wang <rcold@rcold.name>
 */

#ifndef SOCKS_LIBUV_LOGGING_H
#define SOCKS_LIBUV_LOGGING_H

#ifdef NDEBUG
#define LOG_TRACE(...) ((void)0)
#else
#define LOG_TRACE(tag, fmt, ...) log_print(LOG_TRACE, tag, fmt, ##__VA_ARGS__)
#endif

#define LOG_DEBUG(tag, fmt, ...) log_print(LOG_DEBUG, tag, fmt, ##__VA_ARGS__)
#define LOG_INFO(tag, fmt, ...) log_print(LOG_INFO, tag, fmt, ##__VA_ARGS__)
#define LOG_WARN(tag, fmt, ...) log_print(LOG_WARN, tag, fmt, ##__VA_ARGS__)
#define LOG_ERROR(tag, fmt, ...) log_print(LOG_ERROR, tag, fmt, ##__VA_ARGS__)

typedef enum {
#ifndef NDEBUG
  LOG_TRACE,
#endif
  LOG_DEBUG,
  LOG_INFO,
  LOG_WARN,
  LOG_ERROR,
} log_level_t;

void log_init(void);
void log_set_level(log_level_t level);
void log_print(log_level_t level, const char *tag, const char *fmt, ...);

#endif
