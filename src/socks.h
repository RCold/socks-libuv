/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2025 Yeuham Wang <rcold@rcold.name>
 */

#ifndef SOCKS_LIBUV_SOCKS_H
#define SOCKS_LIBUV_SOCKS_H

#include <stdint.h>
#include <uv.h>

#include "util.h"

#define MAX_USER_ID_LEN 255
#define MAX_DOMAIN_NAME_LEN 255
#define MAX_PORT_LEN 5

#define WRITE_BUF_SIZE 32

typedef struct {
  uv_loop_t *loop;
  uv_tcp_t *handle;
  struct sockaddr_storage sockaddr;
  char local_addr[INET6_ADDRSTRLEN + 3 + MAX_PORT_LEN + 1];
} socks_server_t;

typedef struct {
  struct sockaddr_storage sockaddr;
  char domain_name[MAX_DOMAIN_NAME_LEN + 1];
} socks_addr_t;

typedef struct {
  uint8_t ver;
  uint8_t cmd;
  socks_addr_t addr;
} socks_request_t;

typedef enum {
  STATE_NEW_CONNECTION,
  STATE_READING_REQUEST,
  STATE_CONNECTING,
  STATE_RELAYING,
  STATE_UDP_ASSOCIATING,
  STATE_BLACKHOLE,
} socks_client_state_t;

typedef struct {
  socks_request_t request;
  socks_client_state_t state;
  socks_server_t *server;
  uv_tcp_t *tcp_client_handle;
  uv_tcp_t *tcp_remote_handle;
  uv_udp_t *udp_client_handle;
  uv_connect_t *connect_req;
  uv_getaddrinfo_t *getaddrinfo_req;
  uv_write_t *write_req;
  hash_map_t udp_sessions;
  struct sockaddr_storage client_sockaddr;
  char client_addr[INET6_ADDRSTRLEN + 3 + MAX_PORT_LEN + 1];
  char remote_addr[MAX_DOMAIN_NAME_LEN + 1 + MAX_PORT_LEN + 1];
  buf_t read_buf;
  char write_buf[WRITE_BUF_SIZE];
} socks_session_t;

typedef struct {
  uint8_t frag;
  socks_addr_t addr;
} socks_udp_header_t;

typedef struct {
  uv_udp_t *udp_client_handle;
  uv_udp_t *udp4_remote_handle;
  uv_udp_t *udp6_remote_handle;
  struct sockaddr_storage client_sockaddr;
  char client_addr[INET6_ADDRSTRLEN + 3 + MAX_PORT_LEN + 1];
  hash_map_t resolve_cache;
  queue_t resolve_queue;
} socks_udp_session_t;

int socks_server_init(socks_server_t *server, uv_loop_t *loop, const char *host,
                      int port);
int socks_server_start(socks_server_t *server);
void socks_server_stop(socks_server_t *server);

#endif
