/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2025 Yeuham Wang <rcold@rcold.name>
 */

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include "socks.h"

#define VERSION "0.2.0"

typedef struct {
  char *bind;
  int port;
} args_t;

static int parse_port(const char *port_str, int *port) {
  if (port_str == NULL || *port_str == '\0') {
    return -1;
  }
  char *p;
  const long int v = strtol(port_str, &p, 10);
  if (*p != '\0') {
    fprintf(stderr, "error: invalid port number: %s\n", port_str);
    return -1;
  }
  if (v < 1 || v > 65535) {
    fputs("error: the port number must be between 1 and 65535\n", stderr);
    return -1;
  }
  *port = (int)v;
  return 0;
}

static int parse_args(const int argc, char *argv[], args_t *args) {
  args->bind = "0.0.0.0";
  args->port = 1080;
  const struct option longopts[] = {{"help", no_argument, 0, 'h'},
                                    {"bind", required_argument, 0, 'b'},
                                    {"version", optional_argument, 0, 'V'},
                                    {0, 0, 0, 0}};
  int opt;
  while ((opt = getopt_long(argc, argv, "hb:V", longopts, NULL)) != -1) {
    switch (opt) {
    case 'h':
      printf("usage: %s [-h] [-b ADDRESS] [-V] [PORT]\n\n", argv[0]);
      puts("positional arguments:");
      puts("  PORT                specify bind port [default: 1080]\n");
      puts("options:");
      puts("  -h, --help          show this help message and exit");
      puts("  -b, --bind ADDRESS  specify bind address [default: 0.0.0.0]");
      puts("  -V, --version       show program's version number and exit");
      exit(EXIT_SUCCESS);
    case 'b':
      args->bind = optarg;
      continue;
    case 'V':
      printf("%s " VERSION "\n", argv[0]);
      exit(EXIT_SUCCESS);
    default:
      return -1;
    }
  }
  if (optind < argc) {
    if (parse_port(argv[optind], &args->port) != 0) {
      return -1;
    }
    if (optind + 1 < argc) {
      fputs("error: unrecognized arguments:", stderr);
      for (int i = optind + 1; i < argc; i++) {
        fputc(' ', stderr);
        fputs(argv[i], stderr);
      }
      fputc('\n', stderr);
      return -1;
    }
  }
  return 0;
}

static void on_signal(uv_signal_t *handle, const int signum) {
  if (signum == SIGINT) {
    puts("\nKeyboard interrupt received, exiting.");
  }
  socks_server_t *server = handle->data;
  socks_server_stop(server);
  uv_stop(server->loop);
  uv_signal_stop(handle);
}

int main(const int argc, char *argv[]) {
  args_t args;
  if (parse_args(argc, argv, &args) != 0) {
    return EXIT_FAILURE;
  }
  uv_loop_t *loop = uv_default_loop();
  socks_server_t server;
  uv_signal_t sigint_handle, sigterm_handle;
  uv_signal_init(loop, &sigint_handle);
  sigint_handle.data = &server;
  uv_signal_start(&sigint_handle, on_signal, SIGINT);
  uv_signal_init(loop, &sigterm_handle);
  sigterm_handle.data = &server;
  uv_signal_start(&sigterm_handle, on_signal, SIGTERM);
  if (socks_server_init(&server, loop, args.bind, args.port) != 0 ||
      socks_server_start(&server) != 0) {
    return EXIT_FAILURE;
  }
  printf("Serving SOCKS on %s\n", server.local_addr);
  const int ret = uv_run(loop, UV_RUN_DEFAULT);
  uv_close((uv_handle_t *)&sigint_handle, NULL);
  uv_close((uv_handle_t *)&sigterm_handle, NULL);
  return ret;
}
