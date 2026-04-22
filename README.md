# swgp-go

[![Go Reference](https://pkg.go.dev/badge/github.com/database64128/swgp-go.svg)](https://pkg.go.dev/github.com/database64128/swgp-go)
[![Test](https://github.com/database64128/swgp-go/actions/workflows/test.yml/badge.svg)](https://github.com/database64128/swgp-go/actions/workflows/test.yml)
[![Release](https://github.com/database64128/swgp-go/actions/workflows/release.yml/badge.svg)](https://github.com/database64128/swgp-go/actions/workflows/release.yml)

🐉 Simple WireGuard proxy with minimal overhead for WireGuard traffic.

## Proxy modes

### 1. Zero overhead

Mode identifier: `"zero-overhead-2026"`

- The first 16 bytes are encrypted as an AES block for obfuscation.
- Data packets have no further processing.
- For handshake packets, the rest of the packet is randomly padded and encrypted with XChaCha20-Poly1305 AEAD.
- Replayed handshake packets are dropped by checking the nonce and an encrypted timestamp.

#### When to use

- ✅ Does not affect tunnel MTU.
- ✅ Minimal processing of data packets.

### 2. Paranoid

Mode identifier: `"paranoid-2026"`

Packets are padded to the maximum packet size allowed by the MTU, then encrypted using XChaCha20-Poly1305.

#### When to use

- ✅ Full-packet AEAD.
- ✅ Hides in-tunnel packet sizes.
    - The length of a WireGuard data packet is always a multiple of 16.
    - Many IPv6 websites cap their outgoing MTU to 1280 for maximum compatibility.
- ❗️ Slight reduction of tunnel MTU.
- ❗️ Increased bandwidth usage.

### 3. Legacy modes

The `"zero-overhead"` and `"paranoid"` modes are also supported for backward compatibility with previous versions. These modes do not provide replay protection at the obfuscation layer, and do not require the client and server to have synchronized clocks.

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
go install github.com/database64128/swgp-go/cmd/swgp-go@latest
```

Or clone the repository and build it manually:

```sh
go build -trimpath -ldflags '-s -w' ./cmd/swgp-go
```

## Configuration

All configuration examples and systemd unit files can be found in the [docs](docs) directory.

`swgp-go` uses the same PSK format as WireGuard. A base64-encoded PSK can be generated using `wg genpsk` or `openssl rand -base64 32` for use with `"proxyPSK"`. Alternatively, specify a separate PSK file with `"proxyPSKFilePath"`, which can be generated using `openssl rand -out psk_file 32`.

Make sure to use the right MTU for both server and client. To encourage correct use, by default, `swgp-go` disables IP fragmentation and drops packets that are bigger than expected. If your network does not work well with this, set `"pathMTUDiscovery"` to one of the modes below.

| Mode | Behavior | Linux | Windows | macOS | FreeBSD | Other OSes |
| --- | --- | --- | --- | --- | --- | --- |
| `"default"` | App default (equivalent to `"do"`). | - | - | - | - | - |
| `"system"` | System default (usually allows fragmentation; WireGuard uses this). | - | - | - | - | - |
| `"dont"` | Disable PMTUD and allow fragmentation. | ✅ | ✅ | ✅ | ✅ | ❌ |
| `"do"` | Enable PMTUD and drop packets that exceed MTU. | ✅ | ✅ | ✅ | ✅ | ❌ |
| `"probe"` | Like `"do"`, but permit packets above probed MTU. | ✅ | ✅ | ❌ | ❌ | ❌ |
| `"want"` | Linux IP_PMTUDISC_WANT behavior. | ✅ | ❌ | ❌ | ❌ | ❌ |
| `"interface"` | Use interface MTU; no local fragmentation. | ✅ | ❌ | ❌ | ❌ | ❌ |
| `"omit"` | Like `"interface"`, but permits fragmentation if needed. | ✅ | ❌ | ❌ | ❌ | ❌ |

*Legend: ✅ = supported, ❌ = ignored.*

### 1. Server

In this example, `swgp-go` runs a proxy server instance on port 20220. Decrypted WireGuard packets are forwarded to `[::1]:20221`.

```json
{
    "servers": [
        {
            "name": "server",
            "proxyListen": ":20220",
            "proxyMode": "zero-overhead-2026",
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
            "proxyMode": "zero-overhead-2026",
            "proxyPSK": "sAe5RvzLJ3Q0Ll88QRM1N01dYk83Q4y0rXMP1i4rDmI=",
            "proxyFwmark": 0,
            "mtu": 1500
        }
    ]
}
```

#### Routing loop prevention

If you configure your WireGuard tunnel to be the default network interface for internet access, it is important that traffic from `swgp-go` is not routed back into the tunnel, which would cause a routing loop. Depending on your operating system and network configuration, there are a few options:

1. `"proxyFwmark"`: Set to the same `fwmark` in your WireGuard configuration. Most reliable, but only available on Linux and FreeBSD.
2. `"proxyAutoPickInterface": true`: Automagically selects a physical egress interface. Should just work on common macOS[^1] and Windows[^2] setups.
3. `"proxyConnListenAddress"`: Works everywhere, but requires hardcoding the egress address to bind the proxy socket to.

[^1]: Theoretically also works on DragonFly BSD, FreeBSD, NetBSD, and OpenBSD, but not tested.
[^2]: Depending on your Windows version and network configuration, `IPV6_PKTINFO` may be ignored by the OS, which can result in a routing loop. WireGuard itself is also affected by this Windows quirk. Consider setting `"proxyConnListenAddress"`, or use WireGuard's pre-up/post-down scripts to add/remove static routes for the proxy server.

## License

[AGPL-3.0-or-later](LICENSE)
