/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2025 Yeuham Wang <rcold@rcold.name>
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include "logging.h"
#include "socks.h"
#include "tcp.h"
#include "util.h"

#define TAG "socks"

#define DEFAULT_BACKLOG 128

int socks_server_init(socks_server_t *server, uv_loop_t *loop, const char *host,
                      const int port) {
  assert(server != NULL);
  assert(loop != NULL);
  assert(host != NULL);
  assert(port > 0 && port <= 65535);
  server->loop = loop;
  server->handle = NULL;
  if (uv_ip4_addr(host, port, (struct sockaddr_in *)&server->sockaddr) != 0 &&
      uv_ip6_addr(host, port, (struct sockaddr_in6 *)&server->sockaddr) != 0) {
    fprintf(stderr, "error: invalid bind address: %s\n", host);
    return -1;
  }
  getaddrname((struct sockaddr *)&server->sockaddr, server->local_addr,
              sizeof(server->local_addr));
  return 0;
}

int socks_server_start(socks_server_t *server) {
  assert(server != NULL);
  assert(server->handle == NULL);
  server->handle = malloc(sizeof(uv_tcp_t));
  if (server->handle == NULL) {
    fprintf(stderr, "error: alloc memory failed\n");
    return -1;
  }
  int err;
  if ((err = uv_tcp_init(server->loop, server->handle)) != 0) {
    fprintf(stderr, "error: init socks server failed: %s\n", uv_strerror(err));
    free(server->handle);
    server->handle = NULL;
    return -1;
  }
  server->handle->data = server;
  if ((err = uv_tcp_bind(server->handle, (struct sockaddr *)&server->sockaddr,
                         0)) != 0 ||
      (err = uv_listen((uv_stream_t *)server->handle, DEFAULT_BACKLOG,
                       on_new_connection)) != 0) {
    fprintf(stderr, "error: failed to bind to tcp://%s: %s\n",
            server->local_addr, uv_strerror(err));
    socks_server_stop(server);
    return -1;
  }
  log_init();
  return 0;
}

static void on_close(uv_handle_t *handle) { free(handle); }

void socks_server_stop(socks_server_t *server) {
  assert(server != NULL);
  if (server->handle != NULL) {
    server->handle->data = NULL;
    uv_close((uv_handle_t *)server->handle, on_close);
    server->handle = NULL;
  }
}
