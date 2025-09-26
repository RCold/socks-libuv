#include <assert.h>
#include <uv.h>

#include "logging.h"
#include "socks.h"
#include "socks5.h"
#include "udp.h"

#define TAG "udp"

int udp_associate_start(socks_session_t *session) {
  assert(session != NULL);
  assert(session->request.ver == 5 &&
         session->request.cmd == SOCKS5_CMD_UDP_ASSOCIATE);
  LOG_INFO(
      TAG,
      "socks5 udp associate request from client %s rejected: not implemented",
      session->client_addr);
  return send_socks5_response(session, SOCKS5_REP_COMMAND_NOT_SUPPORTED, NULL);
}

void udp_associate_stop(socks_session_t *session) {
  assert(session != NULL);
}
