/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2025 Yeuham Wang <rcold@rcold.name>
 */

#ifndef SOCKS_LIBUV_UDP_H
#define SOCKS_LIBUV_UDP_H

#include "socks.h"

int udp_associate_start(socks_session_t *session);
void udp_associate_stop(socks_session_t *session);

#endif
