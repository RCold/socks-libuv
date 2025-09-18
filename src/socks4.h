#ifndef SOCKS_LIBUV_SOCKS4_H
#define SOCKS_LIBUV_SOCKS4_H

#include <stdint.h>

#include "tcp.h"

#define SOCKS4_CMD_CONNECT 1
#define SOCKS4_CMD_BIND 2

#define SOCKS4_REP_GRANTED 90
#define SOCKS4_REP_REJECTED_OR_FAILED 91

int parse_socks4_request(session_t *session);
int send_socks4_response(session_t *session, uint8_t code);

#endif
