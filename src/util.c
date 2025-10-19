/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2025 Yeuham Wang <rcold@rcold.name>
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "logging.h"
#include "util.h"

#define TAG "util"

int sockaddr_get_port(const struct sockaddr *addr, uint16_t *port) {
  if (addr->sa_family == AF_INET) {
    *port = ntohs(((struct sockaddr_in *)addr)->sin_port);
  } else if (addr->sa_family == AF_INET6) {
    *port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
  } else {
    LOG_ERROR(TAG, "sockaddr get port: invalid address family");
    return -1;
  }
  return 0;
}

int sockaddr_set_port(struct sockaddr *addr, const uint16_t port) {
  if (addr->sa_family == AF_INET) {
    ((struct sockaddr_in *)addr)->sin_port = htons(port);
  } else if (addr->sa_family == AF_INET6) {
    ((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
  } else {
    LOG_ERROR(TAG, "sockaddr set port: invalid address family");
    return -1;
  }
  return 0;
}

void *sockaddr_copy(struct sockaddr *dst, const struct sockaddr *src) {
  if (src->sa_family == AF_INET) {
    return memcpy(dst, src, sizeof(struct sockaddr_in));
  }
  if (src->sa_family == AF_INET6) {
    return memcpy(dst, src, sizeof(struct sockaddr_in6));
  }
  LOG_ERROR(TAG, "sockaddr copy: invalid address family");
  dst->sa_family = AF_UNSPEC;
  return NULL;
}

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
    LOG_ERROR(TAG, "getaddrname: invalid address family");
    return UV_EINVAL;
  }
  return 0;
}

void alloc_buf(uv_handle_t *handle, const size_t suggested_size,
               uv_buf_t *buf) {
  UNUSED(handle);
  buf->base = malloc(suggested_size);
  LOG_TRACE(TAG, "malloc buf: %p", buf->base);
  if (buf->base == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    buf->len = 0;
  } else {
    buf->len = suggested_size;
  }
}

void free_buf(const uv_buf_t *buf) {
  if (buf->base != NULL) {
    LOG_TRACE(TAG, "free buf: %p", buf->base);
    free(buf->base);
  }
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

void buf_destroy(buf_t *buf) {
  if (buf->base != NULL) {
    LOG_TRACE(TAG, "free buf: %p", buf->base);
    free(buf->base);
    buf->base = NULL;
  }
  buf->size = 0;
  buf->capacity = 0;
}

static unsigned long int hash_function(const char *str) {
  unsigned long int hash = 5381;
  int c;
  while ((c = *(unsigned char *)str++)) {
    hash = (hash << 5) + hash + c;
  }
  return hash;
}

int hash_map_init(hash_map_t *map, size_t bucket_count) {
  if (bucket_count < 16) {
    bucket_count = 16;
  }
  map->buckets = calloc(bucket_count, sizeof(hash_map_entry_t *));
  LOG_TRACE(TAG, "malloc hash map buckets: %p", map->buckets);
  if (map->buckets == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    return -1;
  }
  map->bucket_count = bucket_count;
  map->size = 0;
  return 0;
}

int hash_map_put(hash_map_t *map, const char *key, void *value) {
  if (key == NULL) {
    return -1;
  }
  const unsigned long int hash = hash_function(key);
  const size_t index = hash % map->bucket_count;
  hash_map_entry_t *entry = map->buckets[index];
  while (entry != NULL) {
    if (strcmp(entry->key, key) == 0) {
      entry->value = value;
      return 0;
    }
    entry = entry->next;
  }
  hash_map_entry_t *new_entry = malloc(sizeof(hash_map_entry_t));
  LOG_TRACE(TAG, "malloc hash map entry: %p", new_entry);
  if (new_entry == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    return -1;
  }
  char *key_copy = malloc(strlen(key) + 1);
  LOG_TRACE(TAG, "malloc hash map key: %p", key_copy);
  if (key_copy == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    LOG_TRACE(TAG, "free hash map entry: %p", new_entry);
    free(new_entry);
    return -1;
  }
  strcpy(key_copy, key);
  new_entry->key = key_copy;
  new_entry->value = value;
  new_entry->next = map->buckets[index];
  map->buckets[index] = new_entry;
  map->size++;
  return 0;
}

void *hash_map_get(const hash_map_t *map, const char *key) {
  if (key == NULL) {
    return NULL;
  }
  const unsigned long int hash = hash_function(key);
  const size_t index = hash % map->bucket_count;
  const hash_map_entry_t *entry = map->buckets[index];
  while (entry != NULL) {
    if (strcmp(entry->key, key) == 0) {
      return entry->value;
    }
    entry = entry->next;
  }
  return NULL;
}

int hash_map_remove(hash_map_t *map, const char *key) {
  if (key == NULL) {
    return -1;
  }
  const unsigned long int hash = hash_function(key);
  const size_t index = hash % map->bucket_count;
  hash_map_entry_t *entry = map->buckets[index];
  hash_map_entry_t *prev = NULL;
  while (entry != NULL) {
    if (strcmp(entry->key, key) == 0) {
      if (prev == NULL) {
        map->buckets[index] = entry->next;
      } else {
        prev->next = entry->next;
      }
      LOG_TRACE(TAG, "free hash map key: %p", entry->key);
      free((void *)entry->key);
      LOG_TRACE(TAG, "free hash map entry: %p", entry);
      free(entry);
      map->size--;
      return 0;
    }
    prev = entry;
    entry = entry->next;
  }
  return -1;
}

size_t hash_map_size(const hash_map_t *map) { return map->size; }

void hash_map_clear(hash_map_t *map, void (*value_destructor)(void *)) {
  for (size_t i = 0; i < map->bucket_count; i++) {
    hash_map_entry_t *entry = map->buckets[i];
    while (entry != NULL) {
      hash_map_entry_t *next = entry->next;
      if (value_destructor != NULL && entry->value != NULL) {
        value_destructor(entry->value);
      }
      LOG_TRACE(TAG, "free hash map key: %p", entry->key);
      free((void *)entry->key);
      LOG_TRACE(TAG, "free hash map entry: %p", entry);
      free(entry);
      entry = next;
    }
    map->buckets[i] = NULL;
  }
  map->size = 0;
}

void hash_map_destroy(hash_map_t *map, void (*value_destructor)(void *)) {
  if (map->buckets != NULL) {
    hash_map_clear(map, value_destructor);
    LOG_TRACE(TAG, "free hash map buckets: %p", map->buckets);
    free(map->buckets);
    map->buckets = NULL;
  }
  map->bucket_count = 0;
  map->size = 0;
}

void queue_init(queue_t *queue) {
  queue->front = NULL;
  queue->rear = NULL;
  queue->size = 0;
}

int queue_enqueue(queue_t *queue, void *data) {
  queue_node_t *node = malloc(sizeof(queue_node_t));
  LOG_TRACE(TAG, "malloc queue node: %p", node);
  if (node == NULL) {
    LOG_ERROR(TAG, "alloc memory failed");
    return -1;
  }
  node->data = data;
  node->next = NULL;
  if (queue->rear == NULL) {
    queue->front = node;
    queue->rear = node;
  } else {
    queue->rear->next = node;
    queue->rear = node;
  }
  queue->size++;
  return 0;
}

void *queue_dequeue(queue_t *queue) {
  if (queue->front == NULL) {
    return NULL;
  }
  queue_node_t *node = queue->front;
  void *data = node->data;
  queue->front = node->next;
  if (queue->front == NULL) {
    queue->rear = NULL;
  }
  LOG_TRACE(TAG, "free queue node: %p", node);
  free(node);
  queue->size--;
  return data;
}

void *queue_peek(const queue_t *queue) {
  if (queue->front == NULL) {
    return NULL;
  }
  return queue->front->data;
}

int queue_is_empty(const queue_t *queue) { return queue->front == NULL; }

size_t queue_size(const queue_t *queue) { return queue->size; }

void queue_clear(queue_t *queue, void (*data_destructor)(void *)) {
  queue_node_t *current = queue->front;
  while (current != NULL) {
    queue_node_t *next = current->next;
    if (data_destructor != NULL && current->data != NULL) {
      data_destructor(current->data);
    }
    LOG_TRACE(TAG, "free queue node: %p", current);
    free(current);
    current = next;
  }
  queue->front = NULL;
  queue->rear = NULL;
  queue->size = 0;
}

void queue_destroy(queue_t *queue, void (*data_destructor)(void *)) {
  queue_clear(queue, data_destructor);
}
