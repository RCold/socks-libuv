/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2025 Yeuham Wang <rcold@rcold.name>
 */

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <uv.h>

#include "auth.h"
#include "logging.h"
#include "socks.h"
#include "tcp.h"
#include "util.h"

#define TAG "auth"

#define SOCKS5_METHOD_NO_AUTH 0x00
#define SOCKS5_METHOD_NO_ACCEPTABLE 0xFF

static int send_socks5_auth_response(socks_session_t *session,
                                     const uint8_t code) {
  LOG_TRACE(TAG, "send socks5 auth response: %" PRIu8, code);
  assert(session != NULL);
  char data[] = {5, (char)code};
  const uv_buf_t buf = uv_buf_init(data, sizeof(data));
  uv_write_cb cb;
  if (code == SOCKS5_METHOD_NO_ACCEPTABLE) {
    cb = on_write_response_reject;
  } else {
    cb = on_write_response_accept;
  }
  const int ret = send_response_data(session, &buf, cb);
  LOG_TRACE(TAG, "send socks5 auth response return %d", ret);
  return ret;
}

int parse_socks5_auth(socks_session_t *session) {
  assert(session != NULL);
  buf_t *buf = &session->read_buf;
  if (buf->size < 2) {
    return 0;
  }
  if (buf->base[0] != 5) {
    LOG_ERROR(
        TAG, "failed to handle socks5 request from client %s: version mismatch",
        session->client_addr);
    return -1;
  }
  const uint8_t n = buf->base[1];
  if (n < 1) {
    LOG_ERROR(
        TAG,
        "failed to handle socks5 request from client %s: invalid auth method",
        session->client_addr);
    return -1;
  }
  if (buf->size < 2 + n) {
    return 0;
  }
  if (memchr(session->read_buf.base + 2, SOCKS5_METHOD_NO_AUTH, n) == NULL) {
    LOG_INFO(TAG, "socks5 request from %s rejected: authentication failed",
             session->client_addr);
    return send_socks5_auth_response(session, SOCKS5_METHOD_NO_ACCEPTABLE);
  }
  if (send_socks5_auth_response(session, SOCKS5_METHOD_NO_AUTH) != 0) {
    return -1;
  }
  session->request.ver = buf->base[0];
  buf_consume(buf, 2 + n);
  return 2 + n;
}
