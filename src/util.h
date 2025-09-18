#ifndef SOCKS_LIBUV_UTIL_H
#define SOCKS_LIBUV_UTIL_H

#include <uv.h>

typedef struct {
  char *base;
  size_t size;
  size_t capacity;
} buf_t;

int getaddrname(const struct sockaddr *addr, char *dst, size_t size);
int tcp_getpeername(const uv_tcp_t *handle, char *dst, size_t size);

void buf_init(buf_t *buf);
int buf_append(buf_t *buf, const char *src, size_t len);
int buf_consume(buf_t *buf, size_t len);

#endif
