#ifndef SOCKS_LIBUV_SOCKS_H
#define SOCKS_LIBUV_SOCKS_H

#include <uv.h>

#include "tcp.h"

typedef struct {
  uv_loop_t *loop;
  uv_tcp_t *handle;
  struct sockaddr_storage addr;
  char local_addr[INET6_ADDRSTRLEN + 3 + MAX_PORT_LEN + 1];
} socks_server_t;

int socks_server_init(socks_server_t *server, uv_loop_t *loop, const char *host,
                      int port);
int socks_server_start(socks_server_t *server);
void socks_server_stop(socks_server_t *server);

#endif
