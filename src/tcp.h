#ifndef SOCKS_LIBUV_TCP_H
#define SOCKS_LIBUV_TCP_H

#include <stdint.h>
#include <uv.h>

#include "util.h"

#define MAX_USER_ID_LEN 255
#define MAX_DOMAIN_NAME_LEN 255
#define MAX_PORT_LEN 5

#define WRITE_BUF_SIZE 32

typedef struct {
  uint8_t ver;
  uint8_t cmd;
  struct sockaddr_storage addr;
  char *domain_name;
} request_t;

typedef enum {
  STATE_NEW_CONNECTION,
  STATE_READING_REQUEST,
  STATE_CONNECTING,
  STATE_RELAYING,
} client_state_t;

typedef struct {
  request_t request;
  client_state_t state;
  uv_tcp_t *client_handle;
  uv_tcp_t *remote_handle;
  uv_connect_t *connect_req;
  uv_getaddrinfo_t *getaddrinfo_req;
  uv_write_t *write_req;
  char client_addr[INET6_ADDRSTRLEN + 3 + MAX_PORT_LEN + 1];
  char remote_addr[MAX_DOMAIN_NAME_LEN + 1 + MAX_PORT_LEN + 1];
  buf_t read_buf;
  char write_buf[WRITE_BUF_SIZE];
} session_t;

void on_new_connection(uv_stream_t *server, int status);
int send_response_data(session_t *session, const uv_buf_t *buf, uv_write_cb cb);
void on_write_response_accept(uv_write_t *req, int status);
void on_write_response_reject(uv_write_t *req, int status);

#endif
