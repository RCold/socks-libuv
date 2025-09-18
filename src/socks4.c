#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "logging.h"
#include "socks4.h"
#include "tcp.h"
#include "util.h"

#define TAG "socks4"

int send_socks4_response(session_t *session, const uint8_t code) {
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

int parse_socks4_request(session_t *session) {
  assert(session != NULL);
  const buf_t *buf = &session->read_buf;
  if (buf->size < 8) {
    return 0;
  }
  if (buf->base[0] != 4) {
    LOG_ERROR(
        TAG, "failed to handle socks4 request from client %s: version mismatch",
        session->client_addr);
    return -1;
  }
  if (buf->base[1] == SOCKS4_CMD_BIND) {
    LOG_INFO(TAG,
             "socks4 bind request from client %s rejected: not implemented",
             session->client_addr);
    return send_socks4_response(session, SOCKS4_REP_REJECTED_OR_FAILED);
  }
  if (buf->base[1] != SOCKS4_CMD_CONNECT) {
    LOG_ERROR(TAG,
              "failed to handle socks4 request from client %s: invalid command",
              session->client_addr);
    return send_socks4_response(session, SOCKS4_REP_REJECTED_OR_FAILED);
  }
  session->request.ver = buf->base[0];
  session->request.cmd = buf->base[1];
  struct sockaddr_in *addr = (struct sockaddr_in *)&session->request.addr;
  addr->sin_family = AF_INET;
  memcpy(&addr->sin_port, buf->base + 2, 2);
  memcpy(&addr->sin_addr, buf->base + 4, 4);
  const int user_id_start = 8;
  int user_id_end = -1;
  for (int i = user_id_start; i < buf->size; i++) {
    if (i > MAX_USER_ID_LEN) {
      LOG_ERROR(TAG,
                "failed to handle socks4 request from client %s: user id is "
                "too large",
                session->client_addr);
      return -1;
    }
    if (buf->base[i] == '\0') {
      user_id_end = i + 1;
      break;
    }
  }
  if (user_id_end == -1) {
    return 0;
  }
  const u_long ip = ntohl(addr->sin_addr.s_addr);
  if (ip >> 8 == 0 && (ip & 0xFF) != 0) {
    const int domain_start = user_id_end;
    int domain_end = -1;
    for (int i = domain_start; i < buf->size; i++) {
      if (i > MAX_DOMAIN_NAME_LEN) {
        LOG_ERROR(TAG,
                  "failed to handle socks4 request from client %s: domain name "
                  "is too large",
                  session->client_addr);
        return -1;
      }
      if (buf->base[i] == '\0') {
        domain_end = i + 1;
        break;
      }
    }
    if (domain_end == -1) {
      return 0;
    }
    if (domain_end - domain_start < 2) {
      LOG_ERROR(
          TAG,
          "failed to handle socks4 request from client %s: invalid domain name",
          session->client_addr);
      return -1;
    }
    session->request.domain_name = malloc(domain_end - domain_start);
    LOG_TRACE(TAG, "malloc domain name: %p", session->request.domain_name);
    if (session->request.domain_name == NULL) {
      LOG_ERROR(TAG, "alloc memory failed");
      return -1;
    }
    memcpy(session->request.domain_name, buf->base + domain_start,
           domain_end - domain_start);
    buf_consume(&session->read_buf, domain_end);
    return domain_end;
  }
  buf_consume(&session->read_buf, user_id_end);
  return user_id_end;
}
