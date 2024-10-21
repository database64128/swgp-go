# swgp-go

[![Go Reference](https://pkg.go.dev/badge/github.com/database64128/swgp-go.svg)](https://pkg.go.dev/github.com/database64128/swgp-go)
[![Test](https://github.com/database64128/swgp-go/actions/workflows/test.yml/badge.svg)](https://github.com/database64128/swgp-go/actions/workflows/test.yml)
[![Release](https://github.com/database64128/swgp-go/actions/workflows/release.yml/badge.svg)](https://github.com/database64128/swgp-go/actions/workflows/release.yml)

🐉 Simple WireGuard proxy with minimal overhead for WireGuard traffic.

## Proxy modes

### 1. Zero overhead

- Encrypts the first 16 bytes as an AES block.
- Adds padding of random length to handshake packets, then encrypts all bytes after the first 16 using XChaCha20-Poly1305.

#### When to use

- ✅ Does not affect tunnel MTU.
- ✅ Minimal processing of data packets.

### 2. Paranoid

Packets are padded to the maximum packet size allowed by the MTU, then encrypted using XChaCha20-Poly1305.

#### When to use

- ✅ Full-packet AEAD.
- ✅ Hides in-tunnel packet sizes.
    - The length of a WireGuard data packet is always a multiple of 16.
    - Many IPv6 websites cap their outgoing MTU to 1280 for maximum compatibility.
- ❗️ Slight reduction of tunnel MTU.
- ❗️ Increased bandwidth usage.

## Deployment

### Arch Linux package

Release and VCS packages are available in the AUR:

- [![swgp-go AUR package](https://img.shields.io/aur/version/swgp-go?label=swgp-go)](https://aur.archlinux.org/packages/swgp-go)
- [![swgp-go-git AUR package](https://img.shields.io/aur/version/swgp-go-git?label=swgp-go-git)](https://aur.archlinux.org/packages/swgp-go-git)

### Prebuilt binaries

Download from [releases](https://github.com/database64128/swgp-go/releases).

### Container images

There are container images maintained by the community:

- [vnxme/docker-swgp-go](https://github.com/vnxme/docker-swgp-go)

### Build from source

Build and install the latest version using Go:

```sh
go install github.com/database64128/swgp-go@latest
```

Or clone the repository and build it manually:

```sh
go build -trimpath -ldflags '-s -w' ./cmd/swgp-go
```

## Configuration

All configuration examples and systemd unit files can be found in the [docs](docs) directory.

`swgp-go` uses the same PSK format as WireGuard. A PSK can be generated using `wg genpsk` or `openssl rand -base64 32`.

Make sure to use the right MTU for both server and client. To encourage correct use, `swgp-go` disables IP fragmentation and drops packets that are bigger than expected.

### 1. Server

In this example, `swgp-go` runs a proxy server instance on port 20220. Decrypted WireGuard packets are forwarded to `[::1]:20221`.

```json
{
    "servers": [
        {
            "name": "server",
            "proxyListen": ":20220",
            "proxyMode": "zero-overhead",
            "proxyPSK": "sAe5RvzLJ3Q0Ll88QRM1N01dYk83Q4y0rXMP1i4rDmI=",
            "proxyFwmark": 0,
            "wgEndpoint": "[::1]:20221",
            "wgFwmark": 0,
            "mtu": 1500
        }
    ]
}
```

### 2. Client

In this example, `swgp-go` runs a proxy client instance on port 20222. Encrypted proxy packets are sent to the proxy server at `[2001:db8:1f74:3c86:aef9:a75:5d2a:425e]:20220`.

```json
{
    "clients": [
        {
            "name": "client",
            "wgListen": ":20222",
            "wgFwmark": 0,
            "proxyEndpoint": "[2001:db8:1f74:3c86:aef9:a75:5d2a:425e]:20220",
            "proxyMode": "zero-overhead",
            "proxyPSK": "sAe5RvzLJ3Q0Ll88QRM1N01dYk83Q4y0rXMP1i4rDmI=",
            "proxyFwmark": 0,
            "mtu": 1500
        }
    ]
}
```

## License

[AGPL-3.0-or-later](LICENSE)
