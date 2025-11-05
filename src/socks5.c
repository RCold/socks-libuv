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
#include "socks5.h"
#include "tcp.h"
#include "util.h"

#define TAG "socks5"

#define SOCKS5_ERR_INVALID_DOMAIN_NAME (-2)
#define SOCKS5_ERR_INVALID_ADDRESS_TYPE (-3)

int send_socks5_response(socks_session_t *session, const uint8_t code,
                         const struct sockaddr *addr) {
  LOG_TRACE(TAG, "send socks5 response: %" PRIu8, code);
  assert(session != NULL);
  char addr_type;
  unsigned int len;
  if (addr == NULL || addr->sa_family == AF_INET) {
    addr_type = SOCKS5_ADDR_TYPE_IPV4;
    len = 10;
  } else if (addr->sa_family == AF_INET6) {
    addr_type = SOCKS5_ADDR_TYPE_IPV6;
    len = 22;
  } else {
    LOG_ERROR(TAG, "send socks5 response: invalid address family");
    return -1;
  }
  char data[] = {5, (char)code, 0, addr_type, 0, 0, 0, 0, 0, 0, 0,
                 0, 0,          0, 0,         0, 0, 0, 0, 0, 0, 0};
  if (addr != NULL) {
    if (addr_type == SOCKS5_ADDR_TYPE_IPV4) {
      memcpy(data + 4, &((struct sockaddr_in *)addr)->sin_addr, 4);
      memcpy(data + 8, &((struct sockaddr_in *)addr)->sin_port, 2);
    } else {
      memcpy(data + 4, &((struct sockaddr_in6 *)addr)->sin6_addr, 16);
      memcpy(data + 20, &((struct sockaddr_in6 *)addr)->sin6_port, 2);
    }
  }
  const uv_buf_t buf = uv_buf_init(data, len);
  uv_write_cb cb;
  if (code == SOCKS5_REP_SUCCEEDED) {
    cb = on_write_response_accept;
  } else {
    cb = on_write_response_reject;
  }
  const int ret = send_response_data(session, &buf, cb);
  LOG_TRACE(TAG, "send socks5 response return %d", ret);
  return ret;
}

static int parse_socks5_addr(const uv_buf_t *buf, socks_addr_t *addr) {
  assert(buf != NULL);
  assert(addr != NULL);
  if (buf->len < 1) {
    return 0;
  }
  const uint8_t addr_type = buf->base[0];
  switch (addr_type) {
  case SOCKS5_ADDR_TYPE_IPV4: {
    if (buf->len < 7) {
      return 0;
    }
    struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr->sockaddr;
    addr4->sin_family = AF_INET;
    memcpy(&addr4->sin_addr, buf->base + 1, 4);
    memcpy(&addr4->sin_port, buf->base + 5, 2);
    addr->domain_name[0] = '\0';
    return 7;
  }
  case SOCKS5_ADDR_TYPE_DOMAIN_NAME: {
    if (buf->len < 2) {
      return 0;
    }
    const uint8_t n = buf->base[1];
    if (n < 1) {
      return SOCKS5_ERR_INVALID_DOMAIN_NAME;
    }
    if (buf->len < (unsigned int)(2 + n + 2)) {
      return 0;
    }
    assert(n <= MAX_DOMAIN_NAME_LEN);
    memcpy(addr->domain_name, buf->base + 2, n);
    addr->domain_name[n] = '\0';
    struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr->sockaddr;
    addr4->sin_family = AF_INET;
    memcpy(&addr4->sin_port, buf->base + 2 + n, 2);
    return 2 + n + 2;
  }
  case SOCKS5_ADDR_TYPE_IPV6: {
    if (buf->len < 19) {
      return 0;
    }
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr->sockaddr;
    addr6->sin6_family = AF_INET6;
    memcpy(&addr6->sin6_addr, buf->base + 1, 16);
    memcpy(&addr6->sin6_port, buf->base + 17, 2);
    addr->domain_name[0] = '\0';
    return 19;
  }
  default:
    return SOCKS5_ERR_INVALID_ADDRESS_TYPE;
  }
}

int parse_socks5_request(socks_session_t *session) {
  assert(session != NULL);
  if (session->request.ver != 5) {
    const int auth_ret = parse_socks5_auth(session);
    if (auth_ret <= 0) {
      return auth_ret;
    }
  }
  buf_t *buf = &session->read_buf;
  if (buf->size < 4) {
    return 0;
  }
  if (buf->base[0] != 5) {
    LOG_ERROR(
        TAG, "failed to handle socks5 request from client %s: version mismatch",
        session->client_addr);
    return -1;
  }
  if (buf->base[1] != SOCKS5_CMD_CONNECT && buf->base[1] != SOCKS5_CMD_BIND &&
      buf->base[1] != SOCKS5_CMD_UDP_ASSOCIATE) {
    LOG_ERROR(TAG,
              "failed to handle socks5 request from client %s: invalid command",
              session->client_addr);
    return -1;
  }
  session->request.ver = buf->base[0];
  session->request.cmd = buf->base[1];
  const uv_buf_t addr_buf =
      uv_buf_init(buf->base + 3, (unsigned int)(buf->size - 3));
  const int ret = parse_socks5_addr(&addr_buf, &session->request.addr);
  if (ret > 0) {
    buf_consume(buf, 3 + ret);
    return 3 + ret;
  }
  if (ret == 0) {
    return 0;
  }
  if (ret == SOCKS5_ERR_INVALID_DOMAIN_NAME) {
    LOG_ERROR(
        TAG,
        "failed to handle socks5 request from client %s: invalid domain name",
        session->client_addr);
    return -1;
  }
  if (ret == SOCKS5_ERR_INVALID_ADDRESS_TYPE) {
    LOG_ERROR(
        TAG,
        "failed to handle socks5 request from client %s: invalid address type",
        session->client_addr);
    return send_socks5_response(session, SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED,
                                NULL);
  }
  return -1;
}

int parse_socks5_udp_header(const char *client_addr, const uv_buf_t *buf,
                            socks_udp_header_t *header) {
  assert(client_addr != NULL);
  assert(buf != NULL);
  assert(header != NULL);
  if (buf->len < 4) {
    return -1;
  }
  if (buf->base[2] != 0) {
    LOG_ERROR(TAG,
              "failed to handle udp packet from client %s: fragmentation not "
              "supported",
              client_addr);
    return -1;
  }
  header->frag = buf->base[2];
  const uv_buf_t addr_buf = uv_buf_init(buf->base + 3, buf->len - 3);
  const int ret = parse_socks5_addr(&addr_buf, &header->addr);
  if (ret > 0) {
    return 3 + ret;
  }
  if (ret == SOCKS5_ERR_INVALID_DOMAIN_NAME) {
    LOG_ERROR(TAG,
              "failed to handle udp packet from client %s: invalid domain name",
              client_addr);
  } else if (ret == SOCKS5_ERR_INVALID_ADDRESS_TYPE) {
    LOG_ERROR(
        TAG, "failed to handle udp packet from client %s: invalid address type",
        client_addr);
  }
  return -1;
}

int build_socks5_udp_header(const struct sockaddr *addr, const uv_buf_t *buf) {
  assert(addr != NULL);
  assert(buf != NULL);
  if (addr->sa_family == AF_INET) {
    if (buf->len < 10) {
      return -1;
    }
    buf->base[0] = buf->base[1] = buf->base[2] = 0;
    buf->base[3] = SOCKS5_ADDR_TYPE_IPV4;
    const struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
    memcpy(buf->base + 4, &addr4->sin_addr, 4);
    memcpy(buf->base + 8, &addr4->sin_port, 2);
    return 10;
  }
  if (addr->sa_family == AF_INET6) {
    if (buf->len < 22) {
      return -1;
    }
    buf->base[0] = buf->base[1] = buf->base[2] = 0;
    buf->base[3] = SOCKS5_ADDR_TYPE_IPV6;
    const struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
    memcpy(buf->base + 4, &addr6->sin6_addr, 16);
    memcpy(buf->base + 20, &addr6->sin6_port, 2);
    return 22;
  }
  return -1;
}
