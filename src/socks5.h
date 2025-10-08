/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2025 Yeuham Wang <rcold@rcold.name>
 */

#ifndef SOCKS_LIBUV_SOCKS5_H
#define SOCKS_LIBUV_SOCKS5_H

#include <stdint.h>
#include <uv.h>

#include "socks.h"

#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

#define SOCKS5_ADDR_TYPE_IPV4 0x01
#define SOCKS5_ADDR_TYPE_DOMAIN_NAME 0x03
#define SOCKS5_ADDR_TYPE_IPV6 0x04

#define SOCKS5_REP_SUCCEEDED 0x00
#define SOCKS5_REP_GENERAL_FAILURE 0x01
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED 0x08

int parse_socks5_request(socks_session_t *session);
int send_socks5_response(socks_session_t *session, uint8_t code,
                         const struct sockaddr *addr);

int parse_socks5_udp_header(const uv_buf_t *buf, socks_udp_header_t *header,
                            const char *client_addr);
int build_socks5_udp_header(const uv_buf_t *buf, const struct sockaddr *addr);

#endif
