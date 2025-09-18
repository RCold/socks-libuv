#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "logging.h"
#include "socks4.h"
#include "socks5.h"
#include "tcp.h"
#include "util.h"

#define TAG "tcp"

static void session_init(session_t *session, uv_tcp_t *client_handle) {
  assert(session != NULL);
  assert(client_handle != NULL);
  memset(session, 0, sizeof(session_t));
  session->state = STATE_NEW_CONNECTION;
  session->client_handle = client_handle;
  buf_init(&session->read_buf);
}

static void on_close(uv_handle_t *handle) {
  LOG_TRACE(TAG, "on close");
  LOG_TRACE(TAG, "free handle: %p", handle);
  free(handle);
  LOG_TRACE(TAG, "on close return");
}

static void session_destroy(session_t *session) {
  assert(session != NULL);
  if (session->request.domain_name != NULL) {
    LOG_TRACE(TAG, "free domain name: %p", session->request.domain_name);
    free(session->request.domain_name);
    session->request.domain_name = NULL;
  }
  if (session->remote_handle != NULL) {
    session->remote_handle->data = NULL;
    assert(!uv_is_closing((uv_handle_t *)session->remote_handle));
    uv_read_stop((uv_stream_t *)session->remote_handle);
    uv_close((uv_handle_t *)session->remote_handle, on_close);
    session->remote_handle = NULL;
    LOG_DEBUG(TAG, "tcp://%s disconnected", session->remote_addr);
  }
  if (session->client_handle != NULL) {
    session->client_handle->data = NULL;
    assert(!uv_is_closing((uv_handle_t *)session->client_handle));
    uv_read_stop((uv_stream_t *)session->client_handle);
    uv_close((uv_handle_t *)session->client_handle, on_close);
    session->client_handle = NULL;
    LOG_DEBUG(TAG, "client %s disconnected", session->client_addr);
  }
  if (session->connect_req != NULL) {
    session->connect_req->data = NULL;
    session->connect_req = NULL;
  }
  if (session->getaddrinfo_req != NULL) {
    session->getaddrinfo_req->data = NULL;
    uv_cancel((uv_req_t *)session->getaddrinfo_req);
    session->getaddrinfo_req = NULL;
  }
  if (session->write_req != NULL) {
    session->write_req->data = NULL;
    session->write_req = NULL;
  }
  if (session->read_buf.base != NULL) {
    LOG_TRACE(TAG, "free buf: %p", session->read_buf.base);
    free(session->read_buf.base);
    session->read_buf.base = NULL;
  }
  LOG_TRACE(TAG, "free session: %p", session);
  free(session);
}

static void on_write(uv_write_t *req, const int status) {
  LOG_TRACE(TAG, "on write: %d", status);
  if (status != 0) {
    LOG_ERROR(TAG, "on write failed: %s", uv_strerror(status));
  }
  if (req->data != NULL) {
    LOG_TRACE(TAG, "free buf: %p", req->data);
    free(req->data);
  }
  LOG_TRACE(TAG, "free write req: %p", req);
  free(req);
  LOG_TRACE(TAG, "on write return");
}

static void on_remote_read(uv_stream_t *stream, const ssize_t nread,
                           const uv_buf_t *buf) {
  LOG_TRACE(TAG, "on remote read: %zd", nread);
  uv_write_t *write_req = NULL;
  session_t *session = stream->data;
  assert(session != NULL);
  if (nread < 0) {
    if (nread != UV_EOF) {
      LOG_ERROR(TAG, "on remote read failed: %s", uv_strerror((int)nread));
    }
    goto error;
  }
  if (nread == 0) {
    goto cleanup;
  }
  write_req = malloc(sizeof(uv_write_t));
  LOG_TRACE(TAG, "malloc write req: %p", write_req);
  if (write_req == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    goto error;
  }
  write_req->data = buf->base;
  const uv_buf_t bufs[] = {uv_buf_init(buf->base, nread)};
  assert(!uv_is_closing((uv_handle_t *)session->client_handle));
  int err;
  if ((err = uv_write(write_req, (uv_stream_t *)session->client_handle, bufs, 1,
                      on_write)) != 0) {
    LOG_ERROR(TAG, "on remote read: write failed: %s", uv_strerror(err));
    goto error;
  }
  LOG_TRACE(TAG, "on remote read return");
  return;
error:
  session_destroy(session);
  if (write_req != NULL) {
    LOG_TRACE(TAG, "free write req: %p", write_req);
    free(write_req);
  }
cleanup:
  if (buf->base != NULL) {
    LOG_TRACE(TAG, "free buf: %p", buf->base);
    free(buf->base);
  }
  LOG_TRACE(TAG, "on remote read return");
}

void on_write_response_accept(uv_write_t *req, const int status) {
  LOG_TRACE(TAG, "on write response accept: %d", status);
  session_t *session = req->data;
  if (status != 0) {
    LOG_ERROR(TAG, "on write response accept failed: %s", uv_strerror(status));
    if (session != NULL) {
      goto error;
    }
  }
  if (session != NULL) {
    session->write_req = NULL;
  }
  goto cleanup;
error:
  session_destroy(session);
cleanup:
  LOG_TRACE(TAG, "free response write req: %p", req);
  free(req);
  LOG_TRACE(TAG, "on write response accept return");
}

void on_write_response_reject(uv_write_t *req, const int status) {
  LOG_TRACE(TAG, "on write response reject: %d", status);
  if (status != 0) {
    LOG_ERROR(TAG, "on write response reject failed: %s", uv_strerror(status));
  }
  session_t *session = req->data;
  if (session != NULL) {
    session_destroy(session);
  }
  LOG_TRACE(TAG, "free response write req: %p", req);
  free(req);
  LOG_TRACE(TAG, "on write response reject return");
}

int send_response_data(session_t *session, const uv_buf_t *buf,
                       const uv_write_cb cb) {
  LOG_TRACE(TAG, "send response data");
  assert(session != NULL);
  assert(buf->len <= WRITE_BUF_SIZE);
  session->write_req = malloc(sizeof(uv_write_t));
  LOG_TRACE(TAG, "malloc response write req: %p", session->write_req);
  if (session->write_req == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    goto error;
  }
  session->write_req->data = session;
  memcpy(session->write_buf, buf->base, buf->len);
  const uv_buf_t bufs[] = {uv_buf_init(session->write_buf, buf->len)};
  assert(!uv_is_closing((uv_handle_t *)session->client_handle));
  int err;
  if ((err = uv_write(session->write_req, (uv_stream_t *)session->client_handle,
                      bufs, 1, cb)) != 0) {
    LOG_ERROR(TAG, "send response data: write failed: %s", uv_strerror(err));
    LOG_TRACE(TAG, "free response write req: %p", session->write_req);
    free(session->write_req);
    session->write_req = NULL;
    goto error;
  }
  LOG_TRACE(TAG, "send response data return 0");
  return 0;
error:
  LOG_TRACE(TAG, "send response data return -1");
  return -1;
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

static void on_remote_connect(uv_connect_t *req, const int status) {
  LOG_TRACE(TAG, "on remote connect: %d", status);
  uv_write_t *write_req = NULL;
  session_t *session = req->data;
  if (status != 0) {
    LOG_ERROR(TAG, "on remote connect failed: %s", uv_strerror(status));
    if (session != NULL) {
      if (session->request.ver == 4 &&
              send_socks4_response(session, SOCKS4_REP_REJECTED_OR_FAILED) !=
                  0 ||
          session->request.ver == 5 &&
              send_socks5_response(session, SOCKS5_REP_GENERAL_FAILURE, NULL) !=
                  0) {
        goto error;
      }
      uv_close((uv_handle_t *)req->handle, on_close);
      session->remote_handle = NULL;
      session->connect_req = NULL;
    }
    goto cleanup;
  }
  if (session == NULL) {
    goto cleanup;
  }
  uv_tcp_nodelay((uv_tcp_t *)req->handle, 1);
  if (session->request.ver == 4 &&
          send_socks4_response(session, SOCKS4_REP_GRANTED) != 0 ||
      session->request.ver == 5 &&
          send_socks5_response(session, SOCKS5_REP_SUCCEEDED, NULL) != 0) {
    goto error;
  }
  int err;
  if (session->read_buf.size > 0) {
    write_req = malloc(sizeof(uv_write_t));
    LOG_TRACE(TAG, "malloc write req: %p", write_req);
    if (write_req == NULL) {
      LOG_ERROR(TAG, "alloc memory failed");
      goto error;
    }
    write_req->data = session->read_buf.base;
    const uv_buf_t bufs[] = {
        uv_buf_init(session->read_buf.base, session->read_buf.size)};
    if ((err = uv_write(write_req, req->handle, bufs, 1, on_write)) != 0) {
      LOG_ERROR(TAG, "on remote connect: write failed: %s", uv_strerror(err));
      goto error;
    }
  } else {
    LOG_TRACE(TAG, "free buf: %p", session->read_buf.base);
    free(session->read_buf.base);
  }
  buf_init(&session->read_buf);
  if ((err = uv_read_start(req->handle, alloc_buf, on_remote_read)) != 0) {
    LOG_ERROR(TAG, "on remote connect: read start failed: %s",
              uv_strerror(err));
    goto error;
  }
  LOG_DEBUG(TAG, "tcp://%s connected", session->remote_addr);
  session->state = STATE_RELAYING;
  session->connect_req = NULL;
  goto cleanup;
error:
  uv_close((uv_handle_t *)req->handle, on_close);
  session->remote_handle = NULL;
  session_destroy(session);
  if (write_req != NULL) {
    LOG_TRACE(TAG, "free write req: %p", write_req);
    free(write_req);
  }
cleanup:
  LOG_TRACE(TAG, "free connect req: %p", req);
  free(req);
  LOG_TRACE(TAG, "on remote connect return");
}

static void on_addr_resolve(uv_getaddrinfo_t *req, const int status,
                            struct addrinfo *res) {
  LOG_TRACE(TAG, "on addr resolve: %d", status);
  session_t *session = req->data;
  if (status != 0) {
    LOG_ERROR(TAG, "addr resolve failed: %s", uv_strerror(status));
    if (session != NULL) {
      if (session->request.ver == 4 &&
              send_socks4_response(session, SOCKS4_REP_REJECTED_OR_FAILED) !=
                  0 ||
          session->request.ver == 5 &&
              send_socks5_response(session, SOCKS5_REP_GENERAL_FAILURE, NULL) !=
                  0) {
        goto error;
      }
      uv_close((uv_handle_t *)session->remote_handle, on_close);
      session->remote_handle = NULL;
      session->getaddrinfo_req = NULL;
    }
    goto cleanup;
  }
  if (session == NULL) {
    goto cleanup;
  }
  session->connect_req = malloc(sizeof(uv_connect_t));
  LOG_TRACE(TAG, "malloc connect req: %p", session->connect_req);
  if (session->connect_req == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    goto error;
  }
  session->connect_req->data = session;
  assert(!uv_is_closing((uv_handle_t *)session->remote_handle));
  int err;
  if ((err = uv_tcp_connect(session->connect_req, session->remote_handle,
                            res->ai_addr, on_remote_connect)) != 0) {
    LOG_ERROR(TAG, "on addr resolve: tcp connect failed: %s", uv_strerror(err));
    LOG_TRACE(TAG, "free connect req: %p", session->connect_req);
    free(session->connect_req);
    session->connect_req = NULL;
    if (session->request.ver == 4 &&
            send_socks4_response(session, SOCKS4_REP_REJECTED_OR_FAILED) != 0 ||
        session->request.ver == 5 &&
            send_socks5_response(session, SOCKS5_REP_GENERAL_FAILURE, NULL) !=
                0) {
      goto error;
    }
    uv_close((uv_handle_t *)session->remote_handle, on_close);
    session->remote_handle = NULL;
  }
  session->getaddrinfo_req = NULL;
  goto cleanup;
error:
  uv_close((uv_handle_t *)session->remote_handle, on_close);
  session->remote_handle = NULL;
  session_destroy(session);
cleanup:
  LOG_TRACE(TAG, "free getaddrinfo req: %p", req);
  free(req);
  uv_freeaddrinfo(res);
  LOG_TRACE(TAG, "on addr resolve return");
}

static void on_client_read(uv_stream_t *stream, const ssize_t nread,
                           const uv_buf_t *buf) {
  LOG_TRACE(TAG, "on client read: %zd", nread);
  uv_write_t *write_req = NULL;
  session_t *session = stream->data;
  assert(session != NULL);
  if (nread < 0) {
    if (nread != UV_EOF) {
      LOG_ERROR(TAG, "on client read failed: %s", uv_strerror((int)nread));
    }
    goto error;
  }
  if (nread == 0) {
    goto cleanup;
  }
  switch (session->state) {
  case STATE_NEW_CONNECTION:
    tcp_getpeername((uv_tcp_t *)stream, session->client_addr,
                    sizeof(session->client_addr));
    LOG_DEBUG(TAG, "client %s connected", session->client_addr);
    if (buf->base[0] == 4) {
      LOG_DEBUG(TAG, "handle socks4 request from client %s",
                session->client_addr);
    } else if (buf->base[0] == 5) {
      LOG_DEBUG(TAG, "handle socks5 request from client %s",
                session->client_addr);
    }
    session->state = STATE_READING_REQUEST;
  case STATE_READING_REQUEST:
    if (buf_append(&session->read_buf, buf->base, nread) != 0) {
      goto error;
    }
    int request_ret;
    if (session->request.ver == 4 || session->read_buf.base[0] == 4) {
      request_ret = parse_socks4_request(session);
    } else if (session->request.ver == 5 || session->read_buf.base[0] == 5) {
      request_ret = parse_socks5_request(session);
    } else {
      LOG_ERROR(
          TAG,
          "failed to handle socks request from client %s: version mismatch",
          session->client_addr);
      goto error;
    }
    if (request_ret < 0) {
      goto error;
    }
    if (request_ret == 0) {
      goto cleanup;
    }
    uint16_t port;
    if (session->request.addr.ss_family == AF_INET) {
      port = ntohs(((struct sockaddr_in *)&session->request.addr)->sin_port);
    } else if (session->request.addr.ss_family == AF_INET6) {
      port = ntohs(((struct sockaddr_in6 *)&session->request.addr)->sin6_port);
    } else {
      LOG_ERROR(TAG, "invalid address family");
      goto error;
    }
    if (session->request.domain_name == NULL) {
      if (session->request.addr.ss_family == AF_INET) {
        char ip4[INET_ADDRSTRLEN];
        uv_ip4_name((struct sockaddr_in *)&session->request.addr, ip4,
                    sizeof(ip4));
        snprintf(session->remote_addr, sizeof(session->remote_addr),
                 "%s:%" PRIu16, ip4, port);
      } else if (session->request.addr.ss_family == AF_INET6) {
        char ip6[INET6_ADDRSTRLEN];
        uv_ip6_name((struct sockaddr_in6 *)&session->request.addr, ip6,
                    sizeof(ip6));
        snprintf(session->remote_addr, sizeof(session->remote_addr),
                 "[%s]:%" PRIu16, ip6, port);
      }
    } else {
      struct sockaddr_in6 addr6;
      if (uv_ip6_addr(session->request.domain_name, port, &addr6) == 0) {
        memcpy(&session->request.addr, &addr6, sizeof(addr6));
        LOG_TRACE(TAG, "free domain name: %p", session->request.domain_name);
        free(session->request.domain_name);
        session->request.domain_name = NULL;
        char ip[INET6_ADDRSTRLEN];
        uv_ip6_name(&addr6, ip, sizeof(ip));
        snprintf(session->remote_addr, sizeof(session->remote_addr),
                 "[%s]:%" PRIu16, ip, port);
      } else {
        snprintf(session->remote_addr, sizeof(session->remote_addr),
                 "%s:%" PRIu16, session->request.domain_name, port);
      }
    }
    LOG_INFO(TAG, "socks connect request from client %s to tcp://%s accepted",
             session->client_addr, session->remote_addr);
    session->remote_handle = malloc(sizeof(uv_tcp_t));
    LOG_TRACE(TAG, "malloc remote handle: %p", session->remote_handle);
    if (session->remote_handle == NULL) {
      LOG_ERROR(TAG, "alloc memory failed");
      goto error;
    }
    int err;
    if ((err = uv_tcp_init(stream->loop, session->remote_handle)) != 0) {
      LOG_ERROR(TAG, "on client read: tcp init failed: %s", uv_strerror(err));
      LOG_TRACE(TAG, "free remote handle: %p", session->remote_handle);
      free(session->remote_handle);
      session->remote_handle = NULL;
      goto error;
    }
    session->remote_handle->data = session;
    if (session->request.domain_name == NULL) {
      session->connect_req = malloc(sizeof(uv_connect_t));
      LOG_TRACE(TAG, "malloc connect req: %p", session->connect_req);
      if (session->connect_req == NULL) {
        LOG_ERROR(TAG, "alloc memory failed");
        uv_close((uv_handle_t *)session->remote_handle, on_close);
        session->remote_handle = NULL;
        goto error;
      }
      session->connect_req->data = session;
      if ((err = uv_tcp_connect(session->connect_req, session->remote_handle,
                                (struct sockaddr *)&session->request.addr,
                                on_remote_connect)) != 0) {
        LOG_ERROR(TAG, "on client read: tcp connect failed: %s",
                  uv_strerror(err));
        LOG_TRACE(TAG, "free connect req: %p", session->connect_req);
        free(session->connect_req);
        session->connect_req = NULL;
        uv_close((uv_handle_t *)session->remote_handle, on_close);
        session->remote_handle = NULL;
        if (session->request.ver == 4 &&
                send_socks4_response(session, SOCKS4_REP_REJECTED_OR_FAILED) !=
                    0 ||
            session->request.ver == 5 &&
                send_socks5_response(session, SOCKS5_REP_GENERAL_FAILURE,
                                     NULL) != 0) {
          goto error;
        }
        goto cleanup;
      }
    } else {
      session->getaddrinfo_req = malloc(sizeof(uv_getaddrinfo_t));
      LOG_TRACE(TAG, "malloc getaddrinfo req: %p", session->getaddrinfo_req);
      if (session->getaddrinfo_req == NULL) {
        LOG_ERROR(TAG, "alloc memory failed");
        uv_close((uv_handle_t *)session->remote_handle, on_close);
        session->remote_handle = NULL;
        goto error;
      }
      session->getaddrinfo_req->data = session;
      char service[MAX_PORT_LEN + 1];
      snprintf(service, sizeof(service), "%" PRIu16, port);
      if ((err = uv_getaddrinfo(stream->loop, session->getaddrinfo_req,
                                on_addr_resolve, session->request.domain_name,
                                service, NULL)) != 0) {
        LOG_ERROR(TAG, "on client read: getaddrinfo failed: %s",
                  uv_strerror(err));
        LOG_TRACE(TAG, "free getaddrinfo req: %p", session->getaddrinfo_req);
        free(session->getaddrinfo_req);
        session->getaddrinfo_req = NULL;
        uv_close((uv_handle_t *)session->remote_handle, on_close);
        session->remote_handle = NULL;
        if (session->request.ver == 4 &&
                send_socks4_response(session, SOCKS4_REP_REJECTED_OR_FAILED) !=
                    0 ||
            session->request.ver == 5 &&
                send_socks5_response(session, SOCKS5_REP_GENERAL_FAILURE,
                                     NULL) != 0) {
          goto error;
        }
        goto cleanup;
      }
    }
    session->state = STATE_CONNECTING;
    goto cleanup;
  case STATE_CONNECTING:
    if (session->read_buf.size + nread > 16 * 1024) {
      LOG_ERROR(
          TAG,
          "failed to handle socks request from client %s: request is too large",
          session->client_addr);
      goto error;
    }
    if (buf_append(&session->read_buf, buf->base, nread) != 0) {
      goto error;
    }
    goto cleanup;
  case STATE_RELAYING:
    write_req = malloc(sizeof(uv_write_t));
    LOG_TRACE(TAG, "malloc write req: %p", write_req);
    if (write_req == NULL) {
      LOG_ERROR(TAG, "alloc memory failed");
      goto error;
    }
    write_req->data = buf->base;
    const uv_buf_t bufs[] = {uv_buf_init(buf->base, nread)};
    assert(!uv_is_closing((uv_handle_t *)session->remote_handle));
    if ((err = uv_write(write_req, (uv_stream_t *)session->remote_handle, bufs,
                        1, on_write)) != 0) {
      LOG_ERROR(TAG, "on client read: write failed: %s", uv_strerror(err));
      goto error;
    }
    LOG_TRACE(TAG, "on client read return");
    return;
  default:
    assert(0);
  }
error:
  session_destroy(session);
  if (write_req != NULL) {
    LOG_TRACE(TAG, "free write req: %p", write_req);
    free(write_req);
  }
cleanup:
  if (buf->base != NULL) {
    LOG_TRACE(TAG, "free buf: %p", buf->base);
    free(buf->base);
  }
  LOG_TRACE(TAG, "on client read return");
}

void on_new_connection(uv_stream_t *server, const int status) {
  LOG_TRACE(TAG, "on new connection: %d", status);
  uv_tcp_t *stream = NULL;
  if (status != 0) {
    LOG_ERROR(TAG, "on new connection failed: %s", uv_strerror(status));
    goto cleanup;
  }
  stream = malloc(sizeof(uv_tcp_t));
  LOG_TRACE(TAG, "malloc client handle: %p", stream);
  if (stream == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    goto cleanup;
  }
  int err;
  if ((err = uv_tcp_init(server->loop, stream)) != 0) {
    LOG_ERROR(TAG, "on new connection: tcp init failed: %s", uv_strerror(err));
    goto cleanup;
  }
  stream->data = malloc(sizeof(session_t));
  LOG_TRACE(TAG, "malloc session: %p", stream->data);
  if (stream->data == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    goto error;
  }
  session_init(stream->data, stream);
  if ((err = uv_accept(server, (uv_stream_t *)stream)) != 0) {
    LOG_ERROR(TAG, "on new connection: accept failed: %s", uv_strerror(err));
    goto error;
  }
  uv_tcp_nodelay(stream, 1);
  if ((err = uv_read_start((uv_stream_t *)stream, alloc_buf, on_client_read)) !=
      0) {
    LOG_ERROR(TAG, "on new connection: read start failed: %s",
              uv_strerror(err));
    goto error;
  }
  LOG_TRACE(TAG, "on new connection return");
  return;
error:
  if (stream->data != NULL) {
    LOG_TRACE(TAG, "free session: %p", stream->data);
    free(stream->data);
  }
  uv_close((uv_handle_t *)stream, on_close);
  LOG_TRACE(TAG, "on new connection return");
  return;
cleanup:
  if (stream != NULL) {
    if (stream->data != NULL) {
      LOG_TRACE(TAG, "free session: %p", stream->data);
      free(stream->data);
    }
    LOG_TRACE(TAG, "free client handle: %p", stream);
    free(stream);
  }
  LOG_TRACE(TAG, "on new connection return");
}
