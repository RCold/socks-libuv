#ifndef SOCKS_LIBUV_SOCKS5_H
#define SOCKS_LIBUV_SOCKS5_H

#include <stdint.h>
#include <uv.h>

#include "tcp.h"

#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

#define SOCKS5_REP_SUCCEEDED 0x00
#define SOCKS5_REP_GENERAL_FAILURE 0x01
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPRTED 0x08

int parse_socks5_request(session_t *session);
int send_socks5_response(session_t *session, uint8_t code,
                         const struct sockaddr *addr);

#endif
