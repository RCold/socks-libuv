cmake_minimum_required(VERSION 3.10)
project(socks-libuv C)

set(CMAKE_C_STANDARD 99)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED IMPORTED_TARGET libuv-static>=1.0.0)

add_executable(socks-libuv
        src/logging.c
        src/main.c
        src/socks.c
        src/socks4.c
        src/socks5.c
        src/tcp.c
        src/util.c
)
target_link_libraries(socks-libuv PRIVATE PkgConfig::LIBUV)
