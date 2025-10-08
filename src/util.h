/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2025 Yeuham Wang <rcold@rcold.name>
 */

#ifndef SOCKS_LIBUV_UTIL_H
#define SOCKS_LIBUV_UTIL_H

#include <uv.h>

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

int getaddrname(const struct sockaddr *addr, char *dst, size_t size);

void buf_init(buf_t *buf);
int buf_append(buf_t *buf, const char *src, size_t len);
int buf_consume(buf_t *buf, size_t len);

int hash_map_init(hash_map_t *map, size_t bucket_count);
int hash_map_put(hash_map_t *map, const char *key, void *value);
void *hash_map_get(const hash_map_t *map, const char *key);
int hash_map_remove(hash_map_t *map, const char *key);
size_t hash_map_size(const hash_map_t *map);
void hash_map_clear(hash_map_t *map, void (*value_destructor)(void *));
void hash_map_destroy(hash_map_t *map, void (*value_destructor)(void *));

#endif
