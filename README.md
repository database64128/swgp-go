# swgp-go

[![Go Reference](https://pkg.go.dev/badge/github.com/database64128/swgp-go.svg)](https://pkg.go.dev/github.com/database64128/swgp-go)
[![Test](https://github.com/database64128/swgp-go/actions/workflows/test.yml/badge.svg)](https://github.com/database64128/swgp-go/actions/workflows/test.yml)
[![Release](https://github.com/database64128/swgp-go/actions/workflows/release.yml/badge.svg)](https://github.com/database64128/swgp-go/actions/workflows/release.yml)
[![swgp-go AUR package](https://img.shields.io/aur/version/swgp-go?label=swgp-go)](https://aur.archlinux.org/packages/swgp-go)
[![swgp-go-git AUR package](https://img.shields.io/aur/version/swgp-go-git?label=swgp-go-git)](https://aur.archlinux.org/packages/swgp-go-git)

🐉 Simple WireGuard proxy with minimal overhead for WireGuard traffic.

## Proxy Modes

### 1. Zero overhead

The first 16 bytes of all packets are encrypted using an AES block cipher. The remainder of handshake packets (message type 1, 2, 3) are also randomly padded and encrypted using an XChaCha20-Poly1305 AEAD cipher to blend into normal traffic.

### 2. Paranoid

Pad all types of packets without exceeding MTU, then XChaCha20-Poly1305 encrypt the whole packet. We pad data packets because:

- The length of a WireGuard data packet is always a multiple of 16.
- Many IPv6 websites cap their outgoing MTU to 1280 for maximum compatibility.

## Configuration Examples

All configuration examples and systemd unit files can be found in the [docs](docs) directory.

Make sure to use the right MTU for both server and client. To encourage correct use, `swgp-go` disables IP fragmentation and drops packets that are bigger than expected.

```jsonc
{
    "interfaces": [
        {
            "name": "wg0",
            "proxyListen": "[::]:20220",
            "proxyMode": "zero-overhead",
            "proxyPSK": "sAe5RvzLJ3Q0Ll88QRM1N01dYk83Q4y0rXMP1i4rDmI=",
            "proxyFwmark": 0,
            "wgEndpoint": "[::1]:20221",
            "wgFwmark": 0,
            "mtu": 1500,
            "batchMode": ""
        }
    ],
    "peers": [
        {
            "name": "laptop",
            "wgListen": "[::]:20222",
            "wgFwmark": 0,
            "proxyEndpoint": "[2001:db8:1f74:3c86:aef9:a75:5d2a:425e]:20220",
            "proxyMode": "zero-overhead",
            "proxyPSK": "sAe5RvzLJ3Q0Ll88QRM1N01dYk83Q4y0rXMP1i4rDmI=",
            "proxyFwmark": 0,
            "mtu": 1500,
            "batchMode": ""
        }
    ]
}
```

## License

[AGPLv3](LICENSE)
