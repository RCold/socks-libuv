#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "logging.h"
#include "util.h"

#define TAG "util"

int getaddrname(const struct sockaddr *addr, char *dst, const size_t size) {
  char ip[INET6_ADDRSTRLEN];
  uint16_t port;
  if (addr->sa_family == AF_INET) {
    uv_ip4_name((struct sockaddr_in *)addr, ip, sizeof(ip));
    port = ntohs(((struct sockaddr_in *)addr)->sin_port);
    snprintf(dst, size, "%s:%" PRIu16, ip, port);
  } else if (addr->sa_family == AF_INET6) {
    uv_ip6_name((struct sockaddr_in6 *)addr, ip, sizeof(ip));
    port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
    snprintf(dst, size, "[%s]:%" PRIu16, ip, port);
  } else {
    LOG_ERROR(TAG, "invalid address family");
    return UV_EINVAL;
  }
  return 0;
}

int tcp_getpeername(const uv_tcp_t *handle, char *dst, const size_t size) {
  struct sockaddr_storage name;
  int namelen = sizeof(name);
  int err;
  if ((err = uv_tcp_getpeername(handle, (struct sockaddr *)&name, &namelen)) !=
      0) {
    LOG_ERROR(TAG, "get peer name failed: %s", uv_strerror(err));
    return err;
  }
  getaddrname((struct sockaddr *)&name, dst, size);
  return 0;
}

void buf_init(buf_t *buf) {
  buf->base = NULL;
  buf->size = 0;
  buf->capacity = 0;
}

int buf_append(buf_t *buf, const char *src, const size_t len) {
  if (buf->size + len > buf->capacity) {
    size_t new_cap = buf->capacity != 0 ? buf->capacity * 2 : 64;
    while (new_cap < buf->size + len) {
      new_cap *= 2;
    }
    char *base = realloc(buf->base, new_cap);
    if (buf->base == NULL) {
      LOG_TRACE(TAG, "malloc buf: %p", base);
    }
    if (base == NULL) {
      LOG_ERROR(TAG, "alloc memory failed");
      return -1;
    }
    buf->base = base;
    buf->capacity = new_cap;
  }
  memcpy(buf->base + buf->size, src, len);
  buf->size += len;
  return 0;
}

int buf_consume(buf_t *buf, const size_t len) {
  if (len > buf->size) {
    return -1;
  }
  buf->size -= len;
  if (buf->size > 0) {
    memmove(buf->base, buf->base + len, buf->size);
  }
  return 0;
}
