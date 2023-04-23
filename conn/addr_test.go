package conn

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/netip"
	"strings"
	"testing"
)

// Test zero value.
var (
	addrZero       Addr
	addrZeroPort   uint16
	addrZeroString string
)

// Test IP address.
var (
	addrIP                = AddrFromIPPort(addrIPAddrPort)
	addrIPAddr            = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e})
	addrIPPort     uint16 = 1080
	addrIPAddrPort        = netip.AddrPortFrom(addrIPAddr, addrIPPort)
	addrIPHost            = "2001:db8:fad6:572:acbe:7143:14e5:7a6e"
	addrIPString          = "[2001:db8:fad6:572:acbe:7143:14e5:7a6e]:1080"
)

// Test domain name.
var (
	addrDomain              = MustAddrFromDomainPort(addrDomainHost, addrDomainPort)
	addrDomainHost          = "example.com"
	addrDomainPort   uint16 = 443
	addrDomainString        = "example.com:443"
)

func TestAddrEquals(t *testing.T) {
	if !addrZero.Equals(addrZero) {
		t.Error("addrZero.Equals(addrZero) returned false.")
	}
	if !addrIP.Equals(addrIP) {
		t.Error("addrIP.Equals(addrIP) returned false.")
	}
	if !addrDomain.Equals(addrDomain) {
		t.Error("addrDomain.Equals(addrDomain) returned false.")
	}

	if addrZero.Equals(addrIP) {
		t.Error("addrZero.Equals(addrIP) returned true.")
	}
	if addrZero.Equals(addrDomain) {
		t.Error("addrZero.Equals(addrDomain) returned true.")
	}
	if addrIP.Equals(addrDomain) {
		t.Error("addrIP.Equals(addrDomain) returned true.")
	}

	if addrIP443 := AddrFromIPPort(netip.AddrPortFrom(addrIPAddr, 443)); addrIP443.Equals(addrIP) {
		t.Error("addrIP443.Equals(addrIP) returned true.")
	}
}

func TestAddrIs(t *testing.T) {
	if addrZero.IsValid() {
		t.Error("addrZero.IsValid() returned true.")
	}
	if addrZero.IsIP() {
		t.Error("addrZero.IsIP() returned true.")
	}
	if addrZero.IsDomain() {
		t.Error("addrZero.IsDomain() returned true.")
	}

	if !addrIP.IsValid() {
		t.Error("addrIP.IsValid() returned false.")
	}
	if !addrIP.IsIP() {
		t.Error("addrIP.IsIP() returned false.")
	}
	if addrIP.IsDomain() {
		t.Error("addrIP.IsDomain() returned true.")
	}

	if !addrDomain.IsValid() {
		t.Error("addrDomain.IsValid() returned false.")
	}
	if addrDomain.IsIP() {
		t.Error("addrDomain.IsIP() returned true.")
	}
	if !addrDomain.IsDomain() {
		t.Error("addrDomain.IsDomain() returned false.")
	}
}

func assertPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic, got none.")
		}
	}()
	f()
}

func TestAddrIP(t *testing.T) {
	if ip := addrIP.IP(); ip != addrIPAddr {
		t.Errorf("addrIP.IP() returned %s, expected %s.", ip, addrIPAddr)
	}

	assertPanic(t, func() { addrZero.IP() })
	assertPanic(t, func() { addrDomain.IP() })
}

func TestAddrDomain(t *testing.T) {
	if domain := addrDomain.Domain(); domain != addrDomainHost {
		t.Errorf("addrDomain.Domain() returned %s, expected %s.", domain, addrDomainHost)
	}

	assertPanic(t, func() { addrZero.Domain() })
	assertPanic(t, func() { addrIP.Domain() })
}

func TestAddrPort(t *testing.T) {
	if port := addrZero.Port(); port != addrZeroPort {
		t.Errorf("addrZero.Port() returned %d, expected %d.", port, addrZeroPort)
	}

	if port := addrIP.Port(); port != addrIPPort {
		t.Errorf("addrIP.Port() returned %d, expected %d.", port, addrIPPort)
	}

	if port := addrDomain.Port(); port != addrDomainPort {
		t.Errorf("addrDomain.Port() returned %d, expected %d.", port, addrDomainPort)
	}
}

func TestAddrIPPort(t *testing.T) {
	if ap := addrIP.IPPort(); ap != addrIPAddrPort {
		t.Errorf("addrIP.IPPort() returned %s, expected %s.", ap, addrIPAddrPort)
	}

	assertPanic(t, func() { addrZero.IPPort() })
	assertPanic(t, func() { addrDomain.IPPort() })
}

func TestAddrResolveIP(t *testing.T) {
	ctx := context.Background()

	ip, err := addrIP.ResolveIP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ip != addrIPAddr {
		t.Errorf("addrIP.ResolveIP() returned %s, expected %s.", ip, addrIPAddr)
	}

	ip, err = addrDomain.ResolveIP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.IsValid() {
		t.Error("addrDomain.ResolveIP() returned invalid IP address.")
	}

	assertPanic(t, func() { addrZero.ResolveIP(ctx) })
}

func TestAddrResolveIPPort(t *testing.T) {
	ctx := context.Background()

	ipPort, err := addrIP.ResolveIPPort(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ipPort != addrIPAddrPort {
		t.Errorf("addrIP.ResolveIPPort() returned %s, expected %s.", ipPort, addrIPAddrPort)
	}

	ipPort, err = addrDomain.ResolveIPPort(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ipPort.Addr().IsValid() {
		t.Error("addrDomain.ResolveIPPort() returned invalid IP address.")
	}
	if ipPort.Port() != addrDomainPort {
		t.Errorf("addrDomain.ResolveIPPort(false) returned %s, expected port %d.", ipPort, addrDomainPort)
	}

	assertPanic(t, func() { addrZero.ResolveIPPort(ctx) })
}

func TestAddrHost(t *testing.T) {
	if host := addrIP.Host(); host != addrIPHost {
		t.Errorf("addrIP.Host() returned %s, expected %s.", host, addrIPHost)
	}

	if host := addrDomain.Host(); host != addrDomainHost {
		t.Errorf("addrDomain.Host() returned %s, expected %s.", host, addrDomainHost)
	}

	assertPanic(t, func() { addrZero.Host() })
}

func TestAddrString(t *testing.T) {
	if s := addrZero.String(); s != addrZeroString {
		t.Errorf("addrZero.String() returned %s, expected %s.", s, addrZeroString)
	}

	if s := addrIP.String(); s != addrIPString {
		t.Errorf("addrIP.String() returned %s, expected %s.", s, addrIPString)
	}

	if s := addrDomain.String(); s != addrDomainString {
		t.Errorf("addrDomain.String() returned %s, expected %s.", s, addrDomainString)
	}
}

func TestAddrAppendTo(t *testing.T) {
	head := make([]byte, 64)
	_, err := rand.Read(head)
	if err != nil {
		t.Fatal(err)
	}

	b := make([]byte, 0, 128)
	b = append(b, head...)
	bHead := b

	b = addrZero.AppendTo(b)
	if !bytes.Equal(bHead, head) {
		t.Error("addrIP.AppendTo() returned modified head.")
	}
	if string(b[64:]) != addrZeroString {
		t.Errorf("addrZero.AppendTo() returned %s, expected %s.", b[64:], addrZeroString)
	}

	b = addrIP.AppendTo(bHead)
	if !bytes.Equal(bHead, head) {
		t.Error("addrIP.AppendTo() returned modified head.")
	}
	if string(b[64:]) != addrIPString {
		t.Errorf("addrIP.AppendTo() returned %s, expected %s.", b[64:], addrIPString)
	}

	b = addrDomain.AppendTo(bHead)
	if !bytes.Equal(bHead, head) {
		t.Error("addrDomain.AppendTo() returned modified head.")
	}
	if string(b[64:]) != addrDomainString {
		t.Errorf("addrDomain.AppendTo() returned %s, expected %s.", b[64:], addrDomainString)
	}
}

func TestAddrMarshalAndUnmarshalText(t *testing.T) {
	text, err := addrZero.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != addrZeroString {
		t.Errorf("addrZero.MarshalText() returned %s, expected %s.", text, addrZeroString)
	}

	text, err = addrIP.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != addrIPString {
		t.Errorf("addrIP.MarshalText() returned %s, expected %s.", text, addrIPString)
	}

	var addrUnmarshaled Addr
	err = addrUnmarshaled.UnmarshalText(text)
	if err != nil {
		t.Fatal(err)
	}
	if !addrUnmarshaled.Equals(addrIP) {
		t.Errorf("addrIP.UnmarshalText() returned %s, expected %s.", addrUnmarshaled, addrIP)
	}

	text, err = addrDomain.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != addrDomainString {
		t.Errorf("addrDomain.MarshalText() returned %s, expected %s.", text, addrDomainString)
	}

	err = addrUnmarshaled.UnmarshalText(text)
	if err != nil {
		t.Fatal(err)
	}
	if !addrUnmarshaled.Equals(addrDomain) {
		t.Errorf("addrDomain.UnmarshalText() returned %s, expected %s.", addrUnmarshaled, addrDomain)
	}
}

func TestAddrFromDomainPort(t *testing.T) {
	if _, err := AddrFromDomainPort("", 443); err == nil {
		t.Error("AddrFromDomainPort(\"\", 443) did not return error.")
	}
	s := strings.Repeat(" ", 256)
	if _, err := AddrFromDomainPort(s, 443); err == nil {
		t.Error("AddrFromDomainPort(s, 443) did not return error.")
	}
}

func TestAddrFromHostPort(t *testing.T) {
	addrFromHostPort, err := AddrFromHostPort(addrIPHost, addrIPPort)
	if err != nil {
		t.Fatal(err)
	}
	if !addrFromHostPort.Equals(addrIP) {
		t.Errorf("AddrFromHostPort() returned %s, expected %s.", addrFromHostPort, addrIP)
	}

	addrFromHostPort, err = AddrFromHostPort(addrDomainHost, addrDomainPort)
	if err != nil {
		t.Fatal(err)
	}
	if !addrFromHostPort.Equals(addrDomain) {
		t.Errorf("AddrFromHostPort() returned %s, expected %s.", addrFromHostPort, addrDomain)
	}
}

func TestAddrParsing(t *testing.T) {
	addrParsed, err := ParseAddr(addrIPString)
	if err != nil {
		t.Fatal(err)
	}
	if !addrParsed.Equals(addrIP) {
		t.Errorf("ParseAddr() returned %s, expected %s.", addrParsed, addrIP)
	}

	addrParsed, err = ParseAddr(addrDomainString)
	if err != nil {
		t.Fatal(err)
	}
	if !addrParsed.Equals(addrDomain) {
		t.Errorf("ParseAddr() returned %s, expected %s.", addrParsed, addrDomain)
	}
}

var (
	addrPort4    = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 1080)
	addrPort4in6 = netip.AddrPortFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1}), 1080)
)

func TestAddrPortMappedEqual(t *testing.T) {
	if !AddrPortMappedEqual(addrPort4, addrPort4) {
		t.Error("AddrPortMappedEqual(addrPort4, addrPort4) returned false.")
	}

	if !AddrPortMappedEqual(addrPort4, addrPort4in6) {
		t.Error("AddrPortMappedEqual(addrPort4, addrPort4in6) returned false.")
	}

	if !AddrPortMappedEqual(addrPort4in6, addrPort4in6) {
		t.Error("AddrPortMappedEqual(addrPort4in6, addrPort4in6) returned false.")
	}

	if AddrPortMappedEqual(addrPort4, addrIPAddrPort) {
		t.Error("AddrPortMappedEqual(addrPort4, addrIPAddrPort) returned true.")
	}

	if AddrPortMappedEqual(addrPort4in6, addrIPAddrPort) {
		t.Error("AddrPortMappedEqual(addrPort4in6, addrIPAddrPort) returned true.")
	}
}
