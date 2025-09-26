#ifndef SOCKS_LIBUV_TCP_H
#define SOCKS_LIBUV_TCP_H

#include <uv.h>

#include "socks.h"

void on_new_connection(uv_stream_t *server, int status);
int send_response_data(socks_session_t *session, const uv_buf_t *buf,
                       uv_write_cb cb);
void on_write_response_accept(uv_write_t *req, int status);
void on_write_response_reject(uv_write_t *req, int status);

#endif
