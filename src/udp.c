#include <assert.h>
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
  const int header_len = build_socks5_udp_header(&header_buf, addr);
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
  if (buf->base != NULL) {
    LOG_TRACE(TAG, "free buf: %p", buf->base);
    free(buf->base);
  }
  LOG_TRACE(TAG, "on remote udp recv return");
}

static void alloc_buf(uv_handle_t *__attribute__((unused)) handle,
                      const size_t suggested_size, uv_buf_t *buf) {
  buf->base = malloc(suggested_size);
  LOG_TRACE(TAG, "malloc buf: %p", buf->base);
  if (buf->base == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    buf->len = 0;
  } else {
    buf->len = suggested_size;
  }
}

static void on_close(uv_handle_t *handle) {
  LOG_TRACE(TAG, "on close");
  LOG_TRACE(TAG, "free handle: %p", handle);
  free(handle);
  LOG_TRACE(TAG, "on close return");
}

static void udp_session_destroy(socks_udp_session_t *session) {
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
      parse_socks5_udp_header(&header_buf, &header, client_addr);
  if (header_len <= 0) {
    goto cleanup;
  }
  if (header.addr.domain_name[0] != '\0') {
    LOG_ERROR(
        TAG,
        "failed to handle udp packet from client %s: domain name not supported",
        client_addr);
    goto cleanup;
  }
  assert(session->udp_sessions.buckets != NULL);
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
    memcpy(&udp_session->client_sockaddr, addr,
           sizeof(struct sockaddr_storage));
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
  uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
  LOG_TRACE(TAG, "malloc udp send req: %p", send_req);
  if (send_req == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    LOG_TRACE(TAG, "free buf: %p", data);
    free(data);
    goto cleanup;
  }
  send_req->data = data;
  uv_udp_t *remote_handle;
  if (header.addr.sockaddr.ss_family == AF_INET) {
    remote_handle = udp_session->udp4_remote_handle;
  } else if (header.addr.sockaddr.ss_family == AF_INET6) {
    remote_handle = udp_session->udp6_remote_handle;
  } else {
    LOG_ERROR(TAG, "on client udp recv: invalid address family");
    LOG_TRACE(TAG, "free buf: %p", data);
    free(data);
    LOG_TRACE(TAG, "free udp send req: %p", send_req);
    free(send_req);
    goto cleanup;
  }
  const uv_buf_t bufs[] = {uv_buf_init(data, nread - header_len)};
  int err;
  if ((err = uv_udp_send(send_req, remote_handle, bufs, 1,
                         (struct sockaddr *)&header.addr.sockaddr,
                         on_udp_send)) != 0) {
    LOG_ERROR(TAG, "on client udp recv: udp send failed: %s", uv_strerror(err));
    LOG_TRACE(TAG, "free buf: %p", data);
    free(data);
    LOG_TRACE(TAG, "free udp send req: %p", send_req);
    free(send_req);
  }
  goto cleanup;
error:
  uv_close((uv_handle_t *)udp_session->udp4_remote_handle, on_close);
  udp_session->udp4_remote_handle = NULL;
  uv_close((uv_handle_t *)udp_session->udp6_remote_handle, on_close);
  udp_session->udp6_remote_handle = NULL;
  udp_session_destroy(udp_session);
cleanup:
  if (buf->base != NULL) {
    LOG_TRACE(TAG, "free buf: %p", buf->base);
    free(buf->base);
  }
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
  if ((err = uv_udp_init(session->server->loop, session->udp_client_handle)) !=
      0) {
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
  if (bind_addr.ss_family == AF_INET) {
    ((struct sockaddr_in *)&bind_addr)->sin_port = 0;
  } else if (bind_addr.ss_family == AF_INET6) {
    ((struct sockaddr_in6 *)&bind_addr)->sin6_port = 0;
  } else {
    LOG_ERROR(TAG, "udp associate start: invalid address family");
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
  if (session->udp_sessions.buckets != NULL) {
    hash_map_destroy(&session->udp_sessions,
                     (void (*)(void *))udp_session_destroy);
  }
  if (session->udp_client_handle != NULL) {
    session->udp_client_handle->data = NULL;
    uv_udp_recv_stop(session->udp_client_handle);
    uv_close((uv_handle_t *)session->udp_client_handle, on_close);
    session->udp_client_handle = NULL;
  }
}
