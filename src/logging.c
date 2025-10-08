/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2025 Yeuham Wang <rcold@rcold.name>
 */

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "logging.h"

static log_level_t g_level = LOG_WARN;

static const char *g_level_names[] = {
#ifndef NDEBUG
    "TRACE",
#endif
    "DEBUG", "INFO", "WARN", "ERROR",
};

void log_init(void) {
  char *level = getenv("C_LOG");
  if (level == NULL) {
    return;
  }
  for (char *s = level; *s != '\0'; s++) {
    *s = (char)toupper(*s);
  }
#ifndef NDEBUG
  if (strcmp(level, "TRACE") == 0) {
    g_level = LOG_TRACE;
    return;
  }
#endif
  if (strcmp(level, "DEBUG") == 0) {
    g_level = LOG_DEBUG;
  } else if (strcmp(level, "INFO") == 0) {
    g_level = LOG_INFO;
  } else if (strcmp(level, "WARN") == 0) {
    g_level = LOG_WARN;
  } else if (strcmp(level, "ERROR") == 0) {
    g_level = LOG_ERROR;
  }
}

void log_set_level(const log_level_t level) { g_level = level; }

void log_print(const log_level_t level, const char *tag, const char *fmt, ...) {
  if (level < g_level) {
    return;
  }
  const time_t t = time(NULL);
  const struct tm *tm = gmtime(&t);
  char time_buf[21];
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", tm);
  printf("[%s %-5s %s] ", time_buf, g_level_names[level], tag);
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  putchar('\n');
}
