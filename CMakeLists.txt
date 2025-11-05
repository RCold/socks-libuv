# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.10)
project(socks-libuv VERSION 0.2.1 LANGUAGES C)

include(FetchContent)
FetchContent_Declare(getopt-win32
  GIT_REPOSITORY https://github.com/xiaozhuai/getopt-win32.git
  GIT_TAG b69a586f0b1aa37b77c3cf0a9dedba1900007678
)
FetchContent_Declare(libuv
  GIT_REPOSITORY https://github.com/libuv/libuv.git
  GIT_TAG v1.51.0
)

add_executable(socks-libuv
  src/auth.c
  src/logging.c
  src/main.c
  src/socks.c
  src/socks4.c
  src/socks5.c
  src/tcp.c
  src/udp.c
  src/util.c
)

set_property(TARGET socks-libuv PROPERTY C_STANDARD 99)
configure_file(src/config.h.in config.h)
target_include_directories(socks-libuv PRIVATE "${PROJECT_BINARY_DIR}")

include(CheckIncludeFile)
check_include_file(getopt.h HAVE_GETOPT_H)

find_package(PkgConfig)
if(PkgConfig_FOUND)
  pkg_check_modules(LIBUV IMPORTED_TARGET libuv>=1.0.0)
endif()

if(NOT HAVE_GETOPT_H)
  if(WIN32)
    FetchContent_MakeAvailable(getopt-win32)
    # Due to the LGPL license terms, the code should be used here as a shared
    # library.
    add_library(getopt SHARED "${getopt-win32_SOURCE_DIR}/getopt.c")
    target_compile_definitions(getopt PRIVATE EXPORTS_GETOPT)
    target_include_directories(socks-libuv PRIVATE "${getopt-win32_SOURCE_DIR}")
    target_link_libraries(socks-libuv PRIVATE getopt)
  else()
    message(FATAL_ERROR "getopt.h not found - this is required for compilation")
  endif()
endif()

if(LIBUV_FOUND)
  target_link_libraries(socks-libuv PRIVATE PkgConfig::LIBUV)
else()
  FetchContent_MakeAvailable(libuv)
  if(LIBUV_BUILD_SHARED)
    target_link_libraries(socks-libuv PRIVATE uv)
  else()
    target_link_libraries(socks-libuv PRIVATE uv_a)
  endif()
endif()
