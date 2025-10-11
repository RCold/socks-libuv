/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2025 Yeuham Wang <rcold@rcold.name>
 */

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "logging.h"
#include "socks.h"
#include "socks5.h"
#include "udp.h"
#include "util.h"

#define TAG "udp"

#define MAX_UDP_HEADER_LEN 22

typedef struct {
  socks_udp_session_t *udp_session;
  uv_buf_t data_buf;
  socks_addr_t addr;
} getaddrinfo_context_t;

static void on_udp_send(uv_udp_send_t *req, const int status) {
  LOG_TRACE(TAG, "on udp send: %d", status);
  if (status != 0) {
    LOG_ERROR(TAG, "on udp send failed: %s", uv_strerror(status));
  }
  if (req->data != NULL) {
    LOG_TRACE(TAG, "free buf: %p", req->data);
    free(req->data);
  }
  LOG_TRACE(TAG, "free udp send req: %p", req);
  free(req);
  LOG_TRACE(TAG, "on udp send return");
}

static void on_remote_udp_recv(uv_udp_t *handle, const ssize_t nread,
                               const uv_buf_t *buf, const struct sockaddr *addr,
                               const unsigned int
                               __attribute__((unused)) flags) {
  LOG_TRACE(TAG, "on remote udp recv: %zd", nread);
  if (nread < 0) {
    LOG_ERROR(TAG, "on remote udp recv failed: %s", uv_strerror((int)nread));
    goto cleanup;
  }
  if (nread == 0 || addr == NULL) {
    goto cleanup;
  }
  char *data = malloc(MAX_UDP_HEADER_LEN + nread);
  LOG_TRACE(TAG, "malloc buf: %p", data);
  if (data == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    goto cleanup;
  }
  const uv_buf_t header_buf = uv_buf_init(data, MAX_UDP_HEADER_LEN);
  const int header_len = build_socks5_udp_header(addr, &header_buf);
  assert(header_len > 0 && header_len <= MAX_UDP_HEADER_LEN);
  memcpy(data + header_len, buf->base, nread);
  uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
  LOG_TRACE(TAG, "malloc udp send req: %p", send_req);
  if (send_req == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    LOG_TRACE(TAG, "free buf: %p", data);
    free(data);
    goto cleanup;
  }
  send_req->data = data;
  socks_udp_session_t *udp_session = handle->data;
  assert(udp_session != NULL);
  const uv_buf_t bufs[] = {uv_buf_init(data, header_len + nread)};
  int err;
  if ((err = uv_udp_send(send_req, udp_session->udp_client_handle, bufs, 1,
                         (struct sockaddr *)&udp_session->client_sockaddr,
                         on_udp_send)) != 0) {
    LOG_ERROR(TAG, "on remote udp recv: udp send failed: %s", uv_strerror(err));
    LOG_TRACE(TAG, "free buf: %p", data);
    free(data);
    LOG_TRACE(TAG, "free udp send req: %p", send_req);
    free(send_req);
  }
cleanup:
  free_buf(buf);
  LOG_TRACE(TAG, "on remote udp recv return");
}

static int handle_client_data(const socks_udp_session_t *udp_session,
                              const uv_buf_t *buf,
                              const struct sockaddr *addr) {
  assert(udp_session != NULL);
  assert(buf != NULL);
  assert(addr != NULL);
  uv_udp_t *remote_handle;
  if (addr->sa_family == AF_INET) {
    remote_handle = udp_session->udp4_remote_handle;
  } else if (addr->sa_family == AF_INET6) {
    remote_handle = udp_session->udp6_remote_handle;
  } else {
    LOG_ERROR(TAG, "handle client data: invalid address family");
    return -1;
  }
  uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
  LOG_TRACE(TAG, "malloc udp send req: %p", send_req);
  if (send_req == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    return -1;
  }
  assert(buf->base != NULL && buf->len > 0);
  send_req->data = buf->base;
  const uv_buf_t bufs[] = {uv_buf_init(buf->base, buf->len)};
  int err;
  if ((err = uv_udp_send(send_req, remote_handle, bufs, 1, addr,
                         on_udp_send)) != 0) {
    LOG_ERROR(TAG, "handle client data: udp send failed: %s", uv_strerror(err));
    LOG_TRACE(TAG, "free udp send req: %p", send_req);
    free(send_req);
    return -1;
  }
  return 0;
}

static void free_getaddrinfo_context(getaddrinfo_context_t *context) {
  assert(context != NULL);
  if (context->data_buf.base != NULL) {
    LOG_TRACE(TAG, "free buf: %p", context->data_buf.base);
    free(context->data_buf.base);
    context->data_buf = uv_buf_init(NULL, 0);
  }
  LOG_TRACE(TAG, "free getaddrinfo context: %p", context);
  free(context);
}

static void free_getaddrinfo_req(uv_getaddrinfo_t *req) {
  assert(req != NULL);
  if (req->data != NULL) {
    free_getaddrinfo_context(req->data);
    req->data = NULL;
  }
  LOG_TRACE(TAG, "free getaddrinfo req: %p", req);
  free(req);
}

static void resolve_addr(socks_udp_session_t *udp_session);

static void on_addr_resolve(uv_getaddrinfo_t *req, const int status,
                            struct addrinfo *res) {
  LOG_TRACE(TAG, "on addr resolve: %d", status);
  getaddrinfo_context_t *context = req->data;
  socks_udp_session_t *udp_session = NULL;
  if (context != NULL) {
    udp_session = context->udp_session;
    queue_dequeue(&udp_session->resolve_queue);
  }
  if (status != 0) {
    LOG_ERROR(TAG, "on addr resolve failed: %s", uv_strerror(status));
    goto cleanup;
  }
  if (context == NULL) {
    goto cleanup;
  }
  struct sockaddr *addr = malloc(sizeof(struct sockaddr_storage));
  LOG_TRACE(TAG, "malloc sockaddr: %p", addr);
  if (addr == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    goto cleanup;
  }
  sockaddr_copy(addr, res->ai_addr);
  if (sockaddr_set_port(addr, 0) != 0 ||
      hash_map_put(&udp_session->resolve_cache, context->addr.domain_name,
                   addr) != 0) {
    LOG_TRACE(TAG, "free sockaddr: %p", addr);
    free(addr);
    goto cleanup;
  }
  if (handle_client_data(udp_session, &context->data_buf, res->ai_addr) == 0) {
    context->data_buf = uv_buf_init(NULL, 0);
  }
cleanup:
  free_getaddrinfo_req(req);
  uv_freeaddrinfo(res);
  if (udp_session != NULL) {
    resolve_addr(udp_session);
  }
  LOG_TRACE(TAG, "on addr resolve return");
}

static void resolve_addr(socks_udp_session_t *udp_session) {
  assert(udp_session != NULL);
  uv_getaddrinfo_t *getaddrinfo_req = queue_peek(&udp_session->resolve_queue);
  if (getaddrinfo_req == NULL) {
    return;
  }
  getaddrinfo_context_t *context = getaddrinfo_req->data;
  assert(context != NULL);
  uint16_t port;
  if (sockaddr_get_port((struct sockaddr *)&context->addr.sockaddr, &port) !=
      0) {
    goto cleanup;
  }
  const struct sockaddr *addr =
      hash_map_get(&udp_session->resolve_cache, context->addr.domain_name);
  if (addr != NULL) {
    sockaddr_copy((struct sockaddr *)&context->addr.sockaddr, addr);
    if (sockaddr_set_port((struct sockaddr *)&context->addr.sockaddr, port) ==
            0 &&
        handle_client_data(udp_session, &context->data_buf,
                           (struct sockaddr *)&context->addr.sockaddr) == 0) {
      context->data_buf = uv_buf_init(NULL, 0);
    }
    goto cleanup;
  }
  char service[MAX_PORT_LEN + 1];
  snprintf(service, sizeof(service), "%" PRIu16, port);
  int err;
  if ((err = uv_getaddrinfo(udp_session->udp_client_handle->loop,
                            getaddrinfo_req, on_addr_resolve,
                            context->addr.domain_name, service, NULL)) != 0) {
    LOG_ERROR(TAG, "resolve addr: getaddrinfo failed: %s", uv_strerror(err));
    goto cleanup;
  }
  return;
cleanup:
  free_getaddrinfo_req(getaddrinfo_req);
  queue_dequeue(&udp_session->resolve_queue);
  resolve_addr(udp_session);
}

static void on_close(uv_handle_t *handle) {
  LOG_TRACE(TAG, "on close");
  LOG_TRACE(TAG, "free handle: %p", handle);
  free(handle);
  LOG_TRACE(TAG, "on close return");
}

static void free_sockaddr(struct sockaddr *addr) {
  assert(addr != NULL);
  LOG_TRACE(TAG, "free sockaddr: %p", addr);
  free(addr);
}

static void free_udp_session(socks_udp_session_t *session) {
  assert(session != NULL);
  session->udp_client_handle = NULL;
  if (session->udp4_remote_handle != NULL) {
    session->udp4_remote_handle->data = NULL;
    assert(!uv_is_closing((uv_handle_t *)session->udp4_remote_handle));
    uv_udp_recv_stop(session->udp4_remote_handle);
    uv_close((uv_handle_t *)session->udp4_remote_handle, on_close);
    session->udp4_remote_handle = NULL;
  }
  if (session->udp6_remote_handle != NULL) {
    session->udp6_remote_handle->data = NULL;
    assert(!uv_is_closing((uv_handle_t *)session->udp6_remote_handle));
    uv_udp_recv_stop(session->udp6_remote_handle);
    uv_close((uv_handle_t *)session->udp6_remote_handle, on_close);
    session->udp6_remote_handle = NULL;
  }
  hash_map_destroy(&session->resolve_cache, (void (*)(void *))free_sockaddr);
  uv_getaddrinfo_t *getaddrinfo_req = queue_dequeue(&session->resolve_queue);
  if (getaddrinfo_req != NULL) {
    free_getaddrinfo_context(getaddrinfo_req->data);
    getaddrinfo_req->data = NULL;
    uv_cancel((uv_req_t *)getaddrinfo_req);
  }
  queue_destroy(&session->resolve_queue,
                (void (*)(void *))free_getaddrinfo_req);
  LOG_DEBUG(TAG, "udp session for client %s closed", session->client_addr);
  LOG_TRACE(TAG, "free udp session: %p", session);
  free(session);
}

static void on_client_udp_recv(uv_udp_t *handle, const ssize_t nread,
                               const uv_buf_t *buf, const struct sockaddr *addr,
                               const unsigned int
                               __attribute__((unused)) flags) {
  LOG_TRACE(TAG, "on client udp recv: %zd", nread);
  if (nread < 0) {
    LOG_ERROR(TAG, "on client udp recv failed: %s", uv_strerror((int)nread));
    goto cleanup;
  }
  if (nread == 0 || addr == NULL) {
    goto cleanup;
  }
  char client_addr[INET6_ADDRSTRLEN + 3 + MAX_PORT_LEN + 1];
  getaddrname(addr, client_addr, sizeof(client_addr));
  socks_session_t *session = handle->data;
  assert(session != NULL);
  if (addr->sa_family != session->client_sockaddr.ss_family ||
      addr->sa_family == AF_INET &&
          ((struct sockaddr_in *)addr)->sin_addr.s_addr !=
              ((struct sockaddr_in *)&session->client_sockaddr)
                  ->sin_addr.s_addr ||
      addr->sa_family == AF_INET6 &&
          memcmp(&((struct sockaddr_in6 *)addr)->sin6_addr,
                 &((struct sockaddr_in6 *)&session->client_sockaddr)->sin6_addr,
                 sizeof(struct in6_addr)) != 0) {
    LOG_INFO(
        TAG,
        "udp packets from client %s dropped: client ip address not allowed",
        client_addr);
    goto cleanup;
  }
  const uv_buf_t header_buf = uv_buf_init(buf->base, nread);
  socks_udp_header_t header;
  const size_t header_len =
      parse_socks5_udp_header(client_addr, &header_buf, &header);
  if (header_len <= 0) {
    goto cleanup;
  }
  socks_udp_session_t *udp_session =
      hash_map_get(&session->udp_sessions, client_addr);
  if (udp_session == NULL) {
    udp_session = malloc(sizeof(socks_udp_session_t));
    LOG_TRACE(TAG, "malloc udp session: %p", udp_session);
    if (udp_session == NULL) {
      LOG_ERROR(TAG, "alloc memory failed");
      goto cleanup;
    }
    memset(udp_session, 0, sizeof(socks_udp_session_t));
    sockaddr_copy((struct sockaddr *)&udp_session->client_sockaddr, addr);
    strcpy(udp_session->client_addr, client_addr);
    udp_session->udp_client_handle = session->udp_client_handle;
    udp_session->udp4_remote_handle = malloc(sizeof(uv_udp_t));
    LOG_TRACE(TAG, "malloc udp4 remote handle: %p",
              udp_session->udp4_remote_handle);
    if (udp_session->udp4_remote_handle == NULL) {
      LOG_ERROR(TAG, "alloc memory failed");
      LOG_TRACE(TAG, "free udp session: %p", udp_session);
      free(udp_session);
      goto cleanup;
    }
    int err;
    if ((err = uv_udp_init(handle->loop, udp_session->udp4_remote_handle)) !=
        0) {
      LOG_ERROR(TAG, "on client udp recv: udp init failed: %s",
                uv_strerror(err));
      LOG_TRACE(TAG, "free udp4 remote handle: %p",
                udp_session->udp4_remote_handle);
      free(udp_session->udp4_remote_handle);
      LOG_TRACE(TAG, "free udp session: %p", udp_session);
      free(udp_session);
      goto cleanup;
    }
    udp_session->udp4_remote_handle->data = udp_session;
    udp_session->udp6_remote_handle = malloc(sizeof(uv_udp_t));
    LOG_TRACE(TAG, "malloc udp6 remote handle: %p",
              udp_session->udp6_remote_handle);
    if (udp_session->udp6_remote_handle == NULL) {
      LOG_ERROR(TAG, "alloc memory failed");
      uv_close((uv_handle_t *)udp_session->udp4_remote_handle, on_close);
      LOG_TRACE(TAG, "free udp session: %p", udp_session);
      free(udp_session);
      goto cleanup;
    }
    if ((err = uv_udp_init(handle->loop, udp_session->udp6_remote_handle)) !=
        0) {
      LOG_ERROR(TAG, "on client udp recv: udp init failed: %s",
                uv_strerror(err));
      uv_close((uv_handle_t *)udp_session->udp4_remote_handle, on_close);
      LOG_TRACE(TAG, "free udp6 remote handle: %p",
                udp_session->udp6_remote_handle);
      free(udp_session->udp6_remote_handle);
      LOG_TRACE(TAG, "free udp session: %p", udp_session);
      free(udp_session);
      goto cleanup;
    }
    udp_session->udp6_remote_handle->data = udp_session;
    if (hash_map_init(&udp_session->resolve_cache, 16) != 0) {
      uv_close((uv_handle_t *)udp_session->udp4_remote_handle, on_close);
      uv_close((uv_handle_t *)udp_session->udp6_remote_handle, on_close);
      LOG_TRACE(TAG, "free udp session: %p", udp_session);
      free(udp_session);
      goto cleanup;
    }
    queue_init(&udp_session->resolve_queue);
    struct sockaddr_storage addr4, addr6;
    uv_ip4_addr("0.0.0.0", 0, (struct sockaddr_in *)&addr4);
    uv_ip6_addr("::", 0, (struct sockaddr_in6 *)&addr6);
    if ((err = uv_udp_bind(udp_session->udp4_remote_handle,
                           (struct sockaddr *)&addr4, 0)) != 0 ||
        (err = uv_udp_bind(udp_session->udp6_remote_handle,
                           (struct sockaddr *)&addr6, 0)) != 0) {
      LOG_ERROR(TAG, "on client udp recv: udp bind failed: %s",
                uv_strerror(err));
      goto error;
    }
    if ((err = uv_udp_recv_start(udp_session->udp4_remote_handle, alloc_buf,
                                 on_remote_udp_recv)) != 0) {
      LOG_ERROR(TAG, "on client udp recv: udp recv start failed: %s",
                uv_strerror(err));
      goto error;
    }
    if ((err = uv_udp_recv_start(udp_session->udp6_remote_handle, alloc_buf,
                                 on_remote_udp_recv)) != 0) {
      LOG_ERROR(TAG, "on client udp recv: udp recv start failed: %s",
                uv_strerror(err));
      uv_udp_recv_stop(udp_session->udp4_remote_handle);
      goto error;
    }
    if (hash_map_put(&session->udp_sessions, client_addr, udp_session) != 0) {
      LOG_ERROR(TAG, "on client udp recv: hash map put failed");
      uv_udp_recv_stop(udp_session->udp4_remote_handle);
      uv_udp_recv_stop(udp_session->udp6_remote_handle);
      goto error;
    }
    LOG_DEBUG(TAG, "udp session for client %s opened", client_addr);
  }
  char *data = malloc(nread - header_len);
  LOG_TRACE(TAG, "malloc buf: %p", data);
  if (data == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    goto cleanup;
  }
  memcpy(data, buf->base + header_len, nread - header_len);
  if (header.addr.domain_name[0] == '\0') {
    const uv_buf_t data_buf = uv_buf_init(data, nread - header_len);
    if (handle_client_data(udp_session, &data_buf,
                           (struct sockaddr *)&header.addr.sockaddr) != 0) {
      LOG_TRACE(TAG, "free buf: %p", data);
      free(data);
    }
    goto cleanup;
  }
  if (queue_size(&udp_session->resolve_queue) >= 32) {
    LOG_TRACE(TAG, "free buf: %p", data);
    free(data);
    goto cleanup;
  }
  getaddrinfo_context_t *context = malloc(sizeof(getaddrinfo_context_t));
  LOG_TRACE(TAG, "malloc getaddrinfo context: %p", context);
  if (context == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    LOG_TRACE(TAG, "free buf: %p", data);
    free(data);
    goto cleanup;
  }
  context->udp_session = udp_session;
  context->data_buf = uv_buf_init(data, nread - header_len);
  context->addr = header.addr;
  uv_getaddrinfo_t *getaddrinfo_req = malloc(sizeof(uv_getaddrinfo_t));
  LOG_TRACE(TAG, "malloc getaddrinfo req: %p", getaddrinfo_req);
  if (getaddrinfo_req == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    free_getaddrinfo_context(context);
    goto cleanup;
  }
  getaddrinfo_req->data = context;
  const int need_start_resolve = queue_is_empty(&udp_session->resolve_queue);
  if (queue_enqueue(&udp_session->resolve_queue, getaddrinfo_req) != 0) {
    free_getaddrinfo_req(getaddrinfo_req);
    goto cleanup;
  }
  if (need_start_resolve) {
    resolve_addr(udp_session);
  }
  goto cleanup;
error:
  uv_close((uv_handle_t *)udp_session->udp4_remote_handle, on_close);
  udp_session->udp4_remote_handle = NULL;
  uv_close((uv_handle_t *)udp_session->udp6_remote_handle, on_close);
  udp_session->udp6_remote_handle = NULL;
  free_udp_session(udp_session);
cleanup:
  free_buf(buf);
  LOG_TRACE(TAG, "on client udp recv return");
}

int udp_associate_start(socks_session_t *session) {
  assert(session != NULL);
  assert(session->request.ver == 5 &&
         session->request.cmd == SOCKS5_CMD_UDP_ASSOCIATE);
  session->udp_client_handle = malloc(sizeof(uv_udp_t));
  LOG_TRACE(TAG, "malloc udp client handle: %p", session->udp_client_handle);
  if (session->udp_client_handle == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    return -1;
  }
  int err;
  if ((err = uv_udp_init(session->tcp_client_handle->loop,
                         session->udp_client_handle)) != 0) {
    LOG_ERROR(TAG, "udp associate start: udp init failed: %s",
              uv_strerror(err));
    LOG_TRACE(TAG, "free udp client handle: %p", session->udp_client_handle);
    free(session->udp_client_handle);
    session->udp_client_handle = NULL;
    return -1;
  }
  if (hash_map_init(&session->udp_sessions, 16) != 0) {
    LOG_ERROR(TAG, "udp associate start: hash map init failed");
    uv_close((uv_handle_t *)session->udp_client_handle, on_close);
    session->udp_client_handle = NULL;
    return -1;
  }
  struct sockaddr_storage bind_addr = session->server->sockaddr;
  if (sockaddr_set_port((struct sockaddr *)&bind_addr, 0) != 0) {
    uv_close((uv_handle_t *)session->udp_client_handle, on_close);
    session->udp_client_handle = NULL;
    udp_associate_stop(session);
    return -1;
  }
  if ((err = uv_udp_bind(session->udp_client_handle,
                         (struct sockaddr *)&bind_addr, 0)) != 0) {
    LOG_ERROR(TAG, "udp associate start: udp bind failed: %s",
              uv_strerror(err));
    goto error;
  }
  int namelen = sizeof(bind_addr);
  if ((err = uv_udp_getsockname(session->udp_client_handle,
                                (struct sockaddr *)&bind_addr, &namelen)) !=
      0) {
    LOG_ERROR(TAG, "udp associate start: udp getsockname failed: %s",
              uv_strerror(err));
    goto error;
  }
  session->udp_client_handle->data = session;
  if ((err = uv_udp_recv_start(session->udp_client_handle, alloc_buf,
                               on_client_udp_recv)) != 0) {
    LOG_ERROR(TAG, "udp associate start: udp recv start failed: %s",
              uv_strerror(err));
    goto error;
  }
  LOG_INFO(TAG,
           "socks udp associate request from client %s to udp://%s accepted",
           session->client_addr, session->remote_addr);
  return send_socks5_response(session, SOCKS5_REP_SUCCEEDED,
                              (struct sockaddr *)&bind_addr);
error:
  uv_close((uv_handle_t *)session->udp_client_handle, on_close);
  session->udp_client_handle = NULL;
  udp_associate_stop(session);
  return send_socks5_response(session, SOCKS5_REP_GENERAL_FAILURE, NULL);
}

void udp_associate_stop(socks_session_t *session) {
  assert(session != NULL);
  hash_map_destroy(&session->udp_sessions, (void (*)(void *))free_udp_session);
  if (session->udp_client_handle != NULL) {
    session->udp_client_handle->data = NULL;
    uv_udp_recv_stop(session->udp_client_handle);
    uv_close((uv_handle_t *)session->udp_client_handle, on_close);
    session->udp_client_handle = NULL;
  }
}
