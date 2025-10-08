#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <uv.h>

#include "logging.h"
#include "socks.h"
#include "socks4.h"
#include "tcp.h"
#include "util.h"

#define TAG "socks4"

int send_socks4_response(socks_session_t *session, const uint8_t code) {
  LOG_TRACE(TAG, "send socks4 response: %" PRIu8, code);
  assert(session != NULL);
  char data[] = {0, (char)code, 0, 0, 0, 0, 0, 0};
  const uv_buf_t buf = uv_buf_init(data, sizeof(data));
  uv_write_cb cb;
  if (code == SOCKS4_REP_GRANTED) {
    cb = on_write_response_accept;
  } else {
    cb = on_write_response_reject;
  }
  const int ret = send_response_data(session, &buf, cb);
  LOG_TRACE(TAG, "send socks4 response return %d", ret);
  return ret;
}

int parse_socks4_request(socks_session_t *session) {
  assert(session != NULL);
  buf_t *buf = &session->read_buf;
  if (buf->size < 8) {
    return 0;
  }
  if (buf->base[0] != 4) {
    LOG_ERROR(
        TAG, "failed to handle socks4 request from client %s: version mismatch",
        session->client_addr);
    return -1;
  }
  if (buf->base[1] != SOCKS4_CMD_CONNECT && buf->base[1] != SOCKS4_CMD_BIND) {
    LOG_ERROR(TAG,
              "failed to handle socks4 request from client %s: invalid command",
              session->client_addr);
    return send_socks4_response(session, SOCKS4_REP_REJECTED_OR_FAILED);
  }
  session->request.ver = buf->base[0];
  session->request.cmd = buf->base[1];
  struct sockaddr_in *addr =
      (struct sockaddr_in *)&session->request.addr.sockaddr;
  addr->sin_family = AF_INET;
  memcpy(&addr->sin_port, buf->base + 2, 2);
  memcpy(&addr->sin_addr, buf->base + 4, 4);
  const char *user_id_start = buf->base + 8;
  const char *user_id_end = NULL;
  for (const char *p = user_id_start; p < buf->base + buf->size; p++) {
    if (p - user_id_start > MAX_USER_ID_LEN) {
      LOG_ERROR(TAG,
                "failed to handle socks4 request from client %s: user id is "
                "too large",
                session->client_addr);
      return -1;
    }
    if (*p == '\0') {
      user_id_end = p + 1;
      break;
    }
  }
  if (user_id_end == NULL) {
    return 0;
  }
  const uint32_t ip = ntohl(addr->sin_addr.s_addr);
  if (ip >> 8 == 0 && (ip & 0xFF) != 0) {
    const char *domain_start = user_id_end;
    const char *domain_end = NULL;
    for (const char *p = domain_start; p < buf->base + buf->size; p++) {
      if (p - domain_start > MAX_DOMAIN_NAME_LEN) {
        LOG_ERROR(TAG,
                  "failed to handle socks4 request from client %s: domain name "
                  "is too large",
                  session->client_addr);
        return -1;
      }
      if (*p == '\0') {
        domain_end = p + 1;
        break;
      }
    }
    if (domain_end == NULL) {
      return 0;
    }
    if (domain_end - domain_start < 2) {
      LOG_ERROR(
          TAG,
          "failed to handle socks4 request from client %s: invalid domain name",
          session->client_addr);
      return -1;
    }
    assert(domain_end - domain_start <= MAX_DOMAIN_NAME_LEN + 1);
    memcpy(session->request.addr.domain_name, domain_start,
           domain_end - domain_start);
    buf_consume(buf, domain_end - buf->base);
    return (int)(domain_end - buf->base);
  }
  buf_consume(buf, user_id_end - buf->base);
  return (int)(user_id_end - buf->base);
}
