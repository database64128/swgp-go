package conn

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"slices"
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
	addrIP443 := AddrFromIPPort(netip.AddrPortFrom(addrIPAddr, 443))
	addrDomain80 := MustAddrFromDomainPort(addrDomainHost, 80)

	for _, c := range []struct {
		a, b Addr
		eq   bool
	}{
		{addrZero, addrZero, true},
		{addrZero, addrIP, false},
		{addrZero, addrDomain, false},
		{addrZero, addrIP443, false},
		{addrZero, addrDomain80, false},
		{addrIP, addrZero, false},
		{addrIP, addrIP, true},
		{addrIP, addrDomain, false},
		{addrIP, addrIP443, false},
		{addrIP, addrDomain80, false},
		{addrDomain, addrZero, false},
		{addrDomain, addrIP, false},
		{addrDomain, addrDomain, true},
		{addrDomain, addrIP443, false},
		{addrDomain, addrDomain80, false},
		{addrIP443, addrZero, false},
		{addrIP443, addrIP, false},
		{addrIP443, addrDomain, false},
		{addrIP443, addrIP443, true},
		{addrIP443, addrDomain80, false},
		{addrDomain80, addrZero, false},
		{addrDomain80, addrIP, false},
		{addrDomain80, addrDomain, false},
		{addrDomain80, addrIP443, false},
		{addrDomain80, addrDomain80, true},
	} {
		if eq := c.a.Equals(c.b); eq != c.eq {
			t.Errorf("%q.Equals(%q) = %t, want %t", c.a, c.b, eq, c.eq)
		}
	}
}

func TestAddrIsValid(t *testing.T) {
	for _, c := range []struct {
		a Addr
		v bool
	}{
		{addrZero, false},
		{addrIP, true},
		{addrDomain, true},
	} {
		if v := c.a.IsValid(); v != c.v {
			t.Errorf("%q.IsValid() = %t, want %t", c.a, v, c.v)
		}
	}
}

func TestAddrIsIP(t *testing.T) {
	for _, c := range []struct {
		a Addr
		v bool
	}{
		{addrZero, false},
		{addrIP, true},
		{addrDomain, false},
	} {
		if v := c.a.IsIP(); v != c.v {
			t.Errorf("%q.IsIP() = %t, want %t", c.a, v, c.v)
		}
	}
}

func TestAddrIsDomain(t *testing.T) {
	for _, c := range []struct {
		a Addr
		v bool
	}{
		{addrZero, false},
		{addrIP, false},
		{addrDomain, true},
	} {
		if v := c.a.IsDomain(); v != c.v {
			t.Errorf("%q.IsDomain() = %t, want %t", c.a, v, c.v)
		}
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
		t.Errorf("%q.IP() = %q, want %q", addrIP, ip, addrIPAddr)
	}

	assertPanic(t, func() { addrZero.IP() })
	assertPanic(t, func() { addrDomain.IP() })
}

func TestAddrDomain(t *testing.T) {
	if domain := addrDomain.Domain(); domain != addrDomainHost {
		t.Errorf("%q.Domain() = %q, want %q", addrDomain, domain, addrDomainHost)
	}

	assertPanic(t, func() { addrZero.Domain() })
	assertPanic(t, func() { addrIP.Domain() })
}

func TestAddrPort(t *testing.T) {
	for _, c := range []struct {
		a Addr
		p uint16
	}{
		{addrZero, addrZeroPort},
		{addrIP, addrIPPort},
		{addrDomain, addrDomainPort},
	} {
		if p := c.a.Port(); p != c.p {
			t.Errorf("%q.Port() = %d, want %d", c.a, p, c.p)
		}
	}
}

func TestAddrIPPort(t *testing.T) {
	if ap := addrIP.IPPort(); ap != addrIPAddrPort {
		t.Errorf("%q.IPPort() = %q, want %q", addrIP, ap, addrIPAddrPort)
	}

	assertPanic(t, func() { addrZero.IPPort() })
	assertPanic(t, func() { addrDomain.IPPort() })
}

func TestAddrResolveIP(t *testing.T) {
	ctx := t.Context()

	ip, err := addrIP.ResolveIP(ctx, "ip")
	if err != nil {
		t.Fatal(err)
	}
	if ip != addrIPAddr {
		t.Errorf("%q.ResolveIP() = %q, want %q", addrIP, ip, addrIPAddr)
	}

	ip, err = addrDomain.ResolveIP(ctx, "ip")
	if err != nil {
		t.Fatal(err)
	}
	if !ip.IsValid() {
		t.Errorf("%q.ResolveIP().IsValid() = false, want true", addrDomain)
	}

	assertPanic(t, func() { addrZero.ResolveIP(ctx, "ip") })
}

func TestAddrResolveIPPort(t *testing.T) {
	ctx := t.Context()

	ipPort, err := addrIP.ResolveIPPort(ctx, "ip")
	if err != nil {
		t.Fatal(err)
	}
	if ipPort != addrIPAddrPort {
		t.Errorf("%q.ResolveIPPort() = %q, want %q", addrIP, ipPort, addrIPAddrPort)
	}

	ipPort, err = addrDomain.ResolveIPPort(ctx, "ip")
	if err != nil {
		t.Fatal(err)
	}
	if !ipPort.Addr().IsValid() {
		t.Errorf("%q.ResolveIPPort().Addr().IsValid() = false, want true", addrDomain)
	}
	if ipPort.Port() != addrDomainPort {
		t.Errorf("%q.ResolveIPPort() = %q, want port %d", addrDomain, ipPort, addrDomainPort)
	}

	assertPanic(t, func() { addrZero.ResolveIPPort(ctx, "ip") })
}

func TestAddrHost(t *testing.T) {
	if host := addrIP.Host(); host != addrIPHost {
		t.Errorf("%q.Host() = %q, want %q", addrIP, host, addrIPHost)
	}

	if host := addrDomain.Host(); host != addrDomainHost {
		t.Errorf("%q.Host() = %q, want %q", addrDomain, host, addrDomainHost)
	}

	assertPanic(t, func() { addrZero.Host() })
}

func TestAddrString(t *testing.T) {
	for _, c := range []struct {
		a Addr
		s string
	}{
		{addrZero, addrZeroString},
		{addrIP, addrIPString},
		{addrDomain, addrDomainString},
	} {
		if s := c.a.String(); s != c.s {
			t.Errorf("%q.String() = %q, want %q", c.a, s, c.s)
		}
	}
}

func TestAddrAppendTo(t *testing.T) {
	head := make([]byte, 64)
	rand.Read(head)

	b := slices.Grow(head, 64)

	for _, c := range []struct {
		a Addr
		s string
	}{
		{addrZero, addrZeroString},
		{addrIP, addrIPString},
		{addrDomain, addrDomainString},
	} {
		full := c.a.AppendTo(b)
		if !bytes.Equal(full[:len(b)], head) {
			t.Errorf("%q.AppendTo() modified b[:len(b)]", c.a)
		}
		if tail := full[len(b):]; string(tail) != c.s {
			t.Errorf("%q.AppendTo() = %q, want %q", c.a, tail, c.s)
		}
	}
}

func TestAddrAppendText(t *testing.T) {
	head := make([]byte, 64)
	rand.Read(head)

	b := slices.Grow(head, 64)

	for _, c := range []struct {
		a Addr
		s string
	}{
		{addrZero, addrZeroString},
		{addrIP, addrIPString},
		{addrDomain, addrDomainString},
	} {
		full, err := c.a.AppendText(b)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(full[:len(b)], head) {
			t.Errorf("%q.AppendText() modified b[:len(b)]", c.a)
		}
		if tail := full[len(b):]; string(tail) != c.s {
			t.Errorf("%q.AppendText() = %q, want %q", c.a, tail, c.s)
		}
	}
}

func TestAddrMarshalAndUnmarshalText(t *testing.T) {
	for _, c := range []struct {
		a Addr
		s string
	}{
		{addrZero, addrZeroString},
		{addrIP, addrIPString},
		{addrDomain, addrDomainString},
	} {
		text, err := c.a.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		if string(text) != c.s {
			t.Errorf("%q.MarshalText() = %q, want %q", c.a, text, c.s)
		}

		var a Addr
		if err = a.UnmarshalText(text); err != nil {
			t.Fatal(err)
		}
		if !a.Equals(c.a) {
			t.Errorf("%q.UnmarshalText(%q) = %q, want %q", c.a, text, a, c.a)
		}
	}
}

func TestAddrFromDomainPort(t *testing.T) {
	for _, c := range []struct {
		name   string
		domain string
		port   uint16
	}{
		{"EmptyDomain", "", 443},
		{"LongDomain", strings.Repeat(" ", 256), 443},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := AddrFromDomainPort(c.domain, c.port); err == nil {
				t.Errorf("AddrFromDomainPort(%q, %d) did not return error.", c.domain, c.port)
			}
		})
	}
}

func TestAddrFromHostPort(t *testing.T) {
	for _, c := range []struct {
		name         string
		host         string
		port         uint16
		expectedAddr Addr
	}{
		{"IP", addrIPHost, addrIPPort, addrIP},
		{"Domain", addrDomainHost, addrDomainPort, addrDomain},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, err := AddrFromHostPort(c.host, c.port)
			if err != nil {
				t.Fatal(err)
			}
			if !addr.Equals(c.expectedAddr) {
				t.Errorf("AddrFromHostPort(%q, %d) = %q, want %q", c.host, c.port, addr, c.expectedAddr)
			}
		})
	}
}

func TestAddrParsing(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		if _, err := ParseAddr(""); err == nil {
			t.Error("ParseAddr(\"\") did not return error.")
		}
	})

	for _, c := range []struct {
		name         string
		text         string
		expectedAddr Addr
	}{
		{"IP", addrIPString, addrIP},
		{"Domain", addrDomainString, addrDomain},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, err := ParseAddr(c.text)
			if err != nil {
				t.Fatal(err)
			}
			if !addr.Equals(c.expectedAddr) {
				t.Errorf("ParseAddr(%q) = %q, want %q", c.text, addr, c.expectedAddr)
			}
		})
	}
}

var (
	addrPort4    = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 1080)
	addrPort4in6 = netip.AddrPortFrom(netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 127, 0, 0, 1}), 1080)
)

func TestAddrPortMappedEqual(t *testing.T) {
	for _, c := range []struct {
		a, b netip.AddrPort
		eq   bool
	}{
		{addrPort4, addrPort4, true},
		{addrPort4, addrPort4in6, true},
		{addrPort4in6, addrPort4in6, true},
		{addrPort4, addrIPAddrPort, false},
		{addrPort4in6, addrIPAddrPort, false},
	} {
		if eq := AddrPortMappedEqual(c.a, c.b); eq != c.eq {
			t.Errorf("AddrPortMappedEqual(%q, %q) = %t, want %t", c.a, c.b, eq, c.eq)
		}
	}
}
