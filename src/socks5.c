#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "auth.h"
#include "logging.h"
#include "socks.h"
#include "socks5.h"
#include "tcp.h"
#include "util.h"

#define TAG "socks5"

int send_socks5_response(socks_session_t *session, const uint8_t code,
                         const struct sockaddr *addr) {
  LOG_TRACE(TAG, "send socks5 response: %" PRIu8, code);
  assert(session != NULL);
  char addr_type;
  size_t len;
  if (addr == NULL || addr->sa_family == AF_INET) {
    addr_type = SOCKS5_ADDR_TYPE_IPV4;
    len = 10;
  } else if (addr->sa_family == AF_INET6) {
    addr_type = SOCKS5_ADDR_TYPE_IPV6;
    len = 22;
  } else {
    LOG_ERROR(TAG, "invalid address family");
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
  const uint8_t addr_type = buf->base[3];
  struct sockaddr_in *addr = (struct sockaddr_in *)&session->request.addr;
  struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&session->request.addr;
  uint8_t n;
  switch (addr_type) {
  case SOCKS5_ADDR_TYPE_IPV4:
    if (buf->size < 10) {
      return 0;
    }
    addr->sin_family = AF_INET;
    memcpy(&addr->sin_addr, buf->base + 4, 4);
    memcpy(&addr->sin_port, buf->base + 8, 2);
    buf_consume(buf, 10);
    return 10;
  case SOCKS5_ADDR_TYPE_DOMAIN_NAME:
    if (buf->size < 5) {
      return 0;
    }
    n = buf->base[4];
    if (n < 1) {
      LOG_ERROR(
          TAG,
          "failed to handle socks5 request from client %s: invalid domain name",
          session->client_addr);
      return -1;
    }
    if (buf->size < 5 + n + 2) {
      return 0;
    }
    session->request.domain_name = malloc(n + 1);
    LOG_TRACE(TAG, "malloc domain name: %p", session->request.domain_name);
    if (session->request.domain_name == NULL) {
      LOG_ERROR(TAG, "alloc memory failed");
      return -1;
    }
    memcpy(session->request.domain_name, buf->base + 5, n);
    session->request.domain_name[n] = '\0';
    addr->sin_family = AF_INET;
    memcpy(&addr->sin_port, buf->base + 5 + n, 2);
    buf_consume(buf, 5 + n + 2);
    return 5 + n + 2;
  case SOCKS5_ADDR_TYPE_IPV6:
    if (buf->size < 22) {
      return 0;
    }
    addr6->sin6_family = AF_INET6;
    memcpy(&addr6->sin6_addr, buf->base + 4, 16);
    memcpy(&addr6->sin6_port, buf->base + 20, 2);
    buf_consume(buf, 22);
    return 22;
  default:
    LOG_ERROR(
        TAG,
        "failed to handle socks5 request from client %s: invalid address type",
        session->client_addr);
    return send_socks5_response(session, SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED,
                                NULL);
  }
}
