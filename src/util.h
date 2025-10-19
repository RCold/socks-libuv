/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2025 Yeuham Wang <rcold@rcold.name>
 */

#ifndef SOCKS_LIBUV_UTIL_H
#define SOCKS_LIBUV_UTIL_H

#include <uv.h>

#define UNUSED(x) ((void)x)

typedef struct {
  char *base;
  size_t size;
  size_t capacity;
} buf_t;

typedef struct hash_map_entry {
  const char *key;
  void *value;
  struct hash_map_entry *next;
} hash_map_entry_t;

typedef struct {
  hash_map_entry_t **buckets;
  size_t bucket_count;
  size_t size;
} hash_map_t;

typedef struct queue_node {
  void *data;
  struct queue_node *next;
} queue_node_t;

typedef struct {
  queue_node_t *front;
  queue_node_t *rear;
  size_t size;
} queue_t;

int sockaddr_get_port(const struct sockaddr *addr, uint16_t *port);
int sockaddr_set_port(struct sockaddr *addr, uint16_t port);
void *sockaddr_copy(struct sockaddr *dst, const struct sockaddr *src);
int getaddrname(const struct sockaddr *addr, char *dst, size_t size);

void alloc_buf(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
void free_buf(const uv_buf_t *buf);

void buf_init(buf_t *buf);
int buf_append(buf_t *buf, const char *src, size_t len);
int buf_consume(buf_t *buf, size_t len);
void buf_destroy(buf_t *buf);

int hash_map_init(hash_map_t *map, size_t bucket_count);
int hash_map_put(hash_map_t *map, const char *key, void *value);
void *hash_map_get(const hash_map_t *map, const char *key);
int hash_map_remove(hash_map_t *map, const char *key);
size_t hash_map_size(const hash_map_t *map);
void hash_map_clear(hash_map_t *map, void (*value_destructor)(void *));
void hash_map_destroy(hash_map_t *map, void (*value_destructor)(void *));

void queue_init(queue_t *queue);
int queue_enqueue(queue_t *queue, void *data);
void *queue_dequeue(queue_t *queue);
void *queue_peek(const queue_t *queue);
int queue_is_empty(const queue_t *queue);
size_t queue_size(const queue_t *queue);
void queue_clear(queue_t *queue, void (*data_destructor)(void *));
void queue_destroy(queue_t *queue, void (*data_destructor)(void *));

#endif
