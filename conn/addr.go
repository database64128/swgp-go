package conn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"unsafe"
)

type addressFamily byte

const (
	addressFamilyNone addressFamily = iota
	addressFamilyNetip
	addressFamilyDomain
)

type netipAddrHeader struct {
	hi uint64
	lo uint64
	z  *byte
}

// Addr is the base address type used throughout the package.
//
// An Addr is a port number combined with either an IP address or a domain name.
//
// For space efficiency, the IP address and the domain string share the same space.
// The [netip.Addr] is stored in its original layout.
// The domain string's data pointer is stored in the ip.z field.
// Its length is stored at the beginning of the structure.
// This is essentially an unsafe "enum".
type Addr struct {
	_    [0]func()
	addr netipAddrHeader
	port uint16
	af   addressFamily
}

func (a Addr) ip() netip.Addr {
	return *(*netip.Addr)(unsafe.Pointer(&a))
}

func (a Addr) ipPort() netip.AddrPort {
	return *(*netip.AddrPort)(unsafe.Pointer(&a))
}

func (a Addr) domain() string {
	return unsafe.String(a.addr.z, a.addr.hi)
}

// Equals returns whether two addresses are the same.
func (a Addr) Equals(b Addr) bool {
	if a.af != b.af || a.port != b.port {
		return false
	}

	switch a.af {
	case addressFamilyNetip:
		return a.addr == b.addr
	case addressFamilyDomain:
		return a.domain() == b.domain()
	default:
		return true
	}
}

// IsValid returns whether the address is an initialized address (not a zero value).
func (a Addr) IsValid() bool {
	return a.af != addressFamilyNone
}

// IsIP returns whether the address is an IP address.
func (a Addr) IsIP() bool {
	return a.af == addressFamilyNetip
}

// IsDomain returns whether the address is a domain name.
func (a Addr) IsDomain() bool {
	return a.af == addressFamilyDomain
}

// IP returns the IP address.
//
// If the address is a domain name or zero value, this method panics.
func (a Addr) IP() netip.Addr {
	if a.af != addressFamilyNetip {
		panic("IP() called on non-IP address")
	}
	return a.ip()
}

// Domain returns the domain name.
//
// If the address is an IP address or zero value, this method panics.
func (a Addr) Domain() string {
	if a.af != addressFamilyDomain {
		panic("Domain() called on non-domain address")
	}
	return a.domain()
}

// Port returns the port number.
func (a Addr) Port() uint16 {
	return a.port
}

// IPPort returns a netip.AddrPort.
//
// If the address is a domain name or zero value, this method panics.
func (a Addr) IPPort() netip.AddrPort {
	if a.af != addressFamilyNetip {
		panic("IPPort() called on non-IP address")
	}
	return a.ipPort()
}

// ResolveIP resolves a domain name string into an IP address.
//
// This function always returns the first IP address returned by the resolver,
// because the resolver takes care of sorting the IP addresses by address family
// availability and preference.
//
// String representations of IP addresses are not supported.
func ResolveIP(ctx context.Context, host string) (netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	return ips[0], nil
}

// ResolveIP returns the IP address itself or the resolved IP address of the domain name.
//
// If the address is zero value, this method panics.
func (a Addr) ResolveIP(ctx context.Context) (netip.Addr, error) {
	switch a.af {
	case addressFamilyNetip:
		return a.ip(), nil
	case addressFamilyDomain:
		return ResolveIP(ctx, a.domain())
	default:
		panic("ResolveIP() called on zero value")
	}
}

// ResolveIPPort returns the IP address itself or the resolved IP address of the domain name
// and the port number as a [netip.AddrPort].
//
// If the address is zero value, this method panics.
func (a Addr) ResolveIPPort(ctx context.Context) (netip.AddrPort, error) {
	switch a.af {
	case addressFamilyNetip:
		return a.ipPort(), nil
	case addressFamilyDomain:
		ip, err := ResolveIP(ctx, a.domain())
		if err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(ip, a.port), nil
	default:
		panic("ResolveIPPort() called on zero value")
	}
}

// Host returns the string representation of the IP address or the domain name.
//
// If the address is zero value, this method panics.
func (a Addr) Host() string {
	switch a.af {
	case addressFamilyNetip:
		return a.ip().String()
	case addressFamilyDomain:
		return a.domain()
	default:
		panic("Host() called on zero value")
	}
}

// String returns the string representation of the address.
//
// If the address is zero value, an empty string is returned.
func (a Addr) String() string {
	switch a.af {
	case addressFamilyNetip:
		return a.ipPort().String()
	case addressFamilyDomain:
		return fmt.Sprintf("%s:%d", a.domain(), a.port)
	default:
		return ""
	}
}

// AppendTo appends the string representation of the address to the provided buffer.
//
// If the address is zero value, nothing is appended.
func (a Addr) AppendTo(b []byte) []byte {
	switch a.af {
	case addressFamilyNetip:
		return a.ipPort().AppendTo(b)
	case addressFamilyDomain:
		return fmt.Appendf(b, "%s:%d", a.domain(), a.port)
	default:
		return b
	}
}

// MarshalText implements the encoding.TextMarshaler MarshalText method.
func (a Addr) MarshalText() ([]byte, error) {
	switch a.af {
	case addressFamilyNetip:
		return a.ipPort().MarshalText()
	case addressFamilyDomain:
		return fmt.Appendf(nil, "%s:%d", a.domain(), a.port), nil
	default:
		return nil, nil
	}
}

// UnmarshalText implements the encoding.TextUnmarshaler UnmarshalText method.
func (a *Addr) UnmarshalText(text []byte) error {
	addr, err := ParseAddr(text)
	if err != nil {
		return err
	}
	*a = addr
	return nil
}

// AddrFromIPPort returns an Addr from the provided netip.AddrPort.
func AddrFromIPPort(addrPort netip.AddrPort) (addr Addr) {
	*(*netip.AddrPort)(unsafe.Pointer(&addr)) = addrPort
	addr.af = addressFamilyNetip
	return
}

// AddrFromDomainPort returns an Addr from the provided domain name and port number.
func AddrFromDomainPort(domain string, port uint16) (Addr, error) {
	if len(domain) == 0 || len(domain) > 255 {
		return Addr{}, fmt.Errorf("length of domain %s out of range [1, 255]", domain)
	}
	return Addr{
		addr: netipAddrHeader{
			hi: uint64(len(domain)),
			z:  unsafe.StringData(domain),
		},
		port: port,
		af:   addressFamilyDomain,
	}, nil
}

// MustAddrFromDomainPort calls [AddrFromDomainPort] and panics on error.
func MustAddrFromDomainPort(domain string, port uint16) Addr {
	addr, err := AddrFromDomainPort(domain, port)
	if err != nil {
		panic(err)
	}
	return addr
}

// AddrFromHostPort returns an Addr from the provided host string and port number.
// The host string may be a string representation of an IP address or a domain name.
func AddrFromHostPort(host string, port uint16) (Addr, error) {
	if host == "" {
		host = "::"
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return Addr{addr: *(*netipAddrHeader)(unsafe.Pointer(&ip)), port: port, af: addressFamilyNetip}, nil
	}

	return AddrFromDomainPort(host, port)
}

// ParseAddr parses the provided string representation of an address
// and returns the parsed address or an error.
func ParseAddr[T ~[]byte | ~string](s T) (Addr, error) {
	host, portString, err := net.SplitHostPort(*(*string)(unsafe.Pointer(&s)))
	if err != nil {
		return Addr{}, err
	}

	portNumber, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return Addr{}, fmt.Errorf("failed to parse port string: %w", err)
	}
	port := uint16(portNumber)

	return AddrFromHostPort(host, port)
}

type addrPortHeader struct {
	ip   [16]byte
	z    unsafe.Pointer
	port uint16
}

// AddrPortMappedEqual returns whether the two addresses point to the same endpoint.
// An IPv4 address and an IPv4-mapped IPv6 address pointing to the same endpoint are considered equal.
// For example, 1.1.1.1:53 and [::ffff:1.1.1.1]:53 are considered equal.
func AddrPortMappedEqual(l, r netip.AddrPort) bool {
	lp := (*addrPortHeader)(unsafe.Pointer(&l))
	rp := (*addrPortHeader)(unsafe.Pointer(&r))
	return lp.ip == rp.ip && lp.port == rp.port
}
