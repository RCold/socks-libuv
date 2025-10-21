# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.10)
project(socks-libuv VERSION 0.2.1 LANGUAGES C)
set(CMAKE_C_STANDARD 99)

include(CheckIncludeFile)
set(REQUIRED_HEADERS
    assert.h
    ctype.h
    getopt.h
    inttypes.h
    signal.h
    stdarg.h
    stdint.h
    stdio.h
    stdlib.h
    string.h
    time.h
)
foreach(header ${REQUIRED_HEADERS})
    string(REPLACE "." "_" header_var ${header})
    string(TOUPPER ${header_var} header_var)
    set(header_var "HAVE_${header_var}")
    check_include_file("${header}" ${header_var})
    if(NOT ${header_var})
        message(FATAL_ERROR "${header} header file not found - this is required for compilation")
    endif()
endforeach()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED IMPORTED_TARGET libuv>=1.0.0)

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
configure_file(src/config.h.in config.h)
target_include_directories(socks-libuv PRIVATE "${PROJECT_BINARY_DIR}")
target_link_libraries(socks-libuv PRIVATE PkgConfig::LIBUV)
