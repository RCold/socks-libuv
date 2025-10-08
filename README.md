# socks-libuv

A minimal SOCKS server implemented based on [libuv](https://github.com/libuv/libuv)

## Features

- Asynchronous non-blocking I/O based on libuv event loop
- Ultra lightweight
- Cross-platform support (Windows/Linux/macOS)
- SOCKS4 is supported
- SOCKS4a is supported
- SOCKS5 no-auth method (`0x00`) is supported
- SOCKS5 connect is supported

## Building

### Required Dependencies

- libuv library (1.x version)
- C99 compatible compiler
- CMake
- pkg-config

### Install Dependencies

- Windows

1. Install MSYS2: <https://www.msys2.org/>
2. Open "MSYS2 MINGW64" shell
3. Install dependencies:

```bash
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-gcc mingw-w64-x86_64-libuv mingw-w64-x86_64-pkgconf
```

- Linux

```bash
# Ubuntu/Debian
sudo apt-get install cmake gcc libuv1-dev pkg-config

# CentOS/RHEL
sudo yum install epel-release
sudo yum install cmake gcc libuv-devel pkgconfig
```

- macOS

1. Install Homebrew: <https://brew.sh/>
2. Install dependencies:

```bash
brew install cmake libuv pkgconf
```

### Build with CMake

```bash
cmake -B build
cmake --build build
```

## Running

```bash
C_LOG=debug ./build/socks-libuv --bind 127.0.0.1 1080
```

## Important Notes

This SOCKS server does not implement any authentication methods. Anyone
connecting to this server has unrestricted access to your network. You should
only use this server within a trusted private network (home LAN, VPN, etc.) or
behind a firewall.

## License

Licensed under Apache License Version 2.0 ([LICENSE](LICENSE) or <https://www.apache.org/licenses/LICENSE-2.0>)
