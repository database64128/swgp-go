package service

import (
	"bytes"
	"crypto/rand"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/packet"
	"github.com/database64128/swgp-go/tslog"
	"github.com/database64128/swgp-go/tslogtest"
)

var proxyModeCases = [...]struct {
	name        string
	proxyMode   string
	generatePSK func() []byte
}{
	{
		name:      "ZeroOverhead",
		proxyMode: "zero-overhead",
		generatePSK: func() []byte {
			psk := make([]byte, 32)
			rand.Read(psk)
			return psk
		},
	},
	{
		name:      "Paranoid",
		proxyMode: "paranoid",
		generatePSK: func() []byte {
			psk := make([]byte, 32)
			rand.Read(psk)
			return psk
		},
	},
}

var addressFamilyCases = [...]struct {
	name                string
	listenNetwork       string
	listenAddress       string
	endpointNetwork     string
	connectLocalAddress conn.Addr
}{
	{
		name:            "IPv4Implicit",
		listenNetwork:   "udp",
		listenAddress:   "127.0.0.1:",
		endpointNetwork: "ip",
	},
	{
		name:            "IPv6Implicit",
		listenNetwork:   "udp",
		listenAddress:   "[::1]:",
		endpointNetwork: "ip",
	},
	{
		name:                "IPv4Explicit",
		listenNetwork:       "udp4",
		listenAddress:       "127.0.0.1:",
		endpointNetwork:     "ip4",
		connectLocalAddress: conn.AddrFromIPAndPort(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0),
	},
	{
		name:                "IPv6Explicit",
		listenNetwork:       "udp6",
		listenAddress:       "[::1]:",
		endpointNetwork:     "ip6",
		connectLocalAddress: conn.AddrFromIPAndPort(netip.IPv6Loopback(), 0),
	},
	{
		name:                "localhost4",
		listenNetwork:       "udp4",
		listenAddress:       "localhost:",
		endpointNetwork:     "ip4",
		connectLocalAddress: conn.MustAddrFromDomainPort("localhost", 0),
	},
	{
		name:                "localhost6",
		listenNetwork:       "udp6",
		listenAddress:       "localhost:",
		endpointNetwork:     "ip6",
		connectLocalAddress: conn.MustAddrFromDomainPort("localhost", 0),
	},
}

var mtuCases = [...]struct {
	name string
	mtu  int
}{
	{
		name: "1492",
		mtu:  1492,
	},
	{
		name: "1500",
		mtu:  1500,
	},
	{
		name: "9000",
		mtu:  9000,
	},
	{
		name: "65535",
		mtu:  65535,
	},
}

func TestClientServer(t *testing.T) {
	logCfg := tslogtest.Config{Level: slog.LevelDebug}
	logger := logCfg.NewTestLogger(t)

	for _, proxyModeCase := range proxyModeCases {
		t.Run(proxyModeCase.name, func(t *testing.T) {
			t.Parallel()
			for _, afCase := range addressFamilyCases {
				t.Run(afCase.name, func(t *testing.T) {
					t.Parallel()
					for _, mtuCase := range mtuCases {
						t.Run(mtuCase.name, func(t *testing.T) {
							t.Parallel()

							t.Run("Handshake", func(t *testing.T) {
								testClientServerConn(
									t,
									logger,
									proxyModeCase.proxyMode,
									proxyModeCase.generatePSK,
									afCase.listenNetwork,
									afCase.listenAddress,
									afCase.endpointNetwork,
									afCase.connectLocalAddress,
									mtuCase.mtu,
									func(clientConn, serverConn *net.UDPConn) {
										testClientServerHandshake(t, clientConn, serverConn)
									},
								)
							})

							t.Run("DataPackets", func(t *testing.T) {
								testClientServerConn(
									t,
									logger,
									proxyModeCase.proxyMode,
									proxyModeCase.generatePSK,
									afCase.listenNetwork,
									afCase.listenAddress,
									afCase.endpointNetwork,
									afCase.connectLocalAddress,
									mtuCase.mtu,
									func(clientConn, serverConn *net.UDPConn) {
										testClientServerDataPackets(t, clientConn, serverConn)
									},
								)
							})
						})
					}
				})
			}
		})
	}
}

func testClientServerConn(
	t testing.TB,
	logger *tslog.Logger,
	proxyMode string,
	generatePSK func() []byte,
	listenNetwork string,
	listenAddress string,
	endpointNetwork string,
	connectLocalAddress conn.Addr,
	mtu int,
	f func(clientConn, serverConn *net.UDPConn),
) {
	ctx := t.Context()
	listenConfigCache := conn.NewListenConfigCache()

	serverConn, _, err := conn.DefaultUDPServerListenConfig.ListenUDP(ctx, listenNetwork, listenAddress)
	if err != nil {
		t.Fatalf("Failed to listen server connection: %v", err)
	}
	defer serverConn.Close()

	serverWgAddrPort := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()

	psk := generatePSK()
	connectListenAddress := connectLocalAddress.String()
	serverConfig := ServerConfig{
		Name:                "wg0",
		ProxyListenNetwork:  listenNetwork,
		ProxyListenAddress:  listenAddress,
		ProxyMode:           proxyMode,
		ProxyPSK:            psk,
		WgEndpointNetwork:   endpointNetwork,
		WgEndpointAddress:   conn.AddrFromIPPort(serverWgAddrPort),
		WgConnListenAddress: connectListenAddress,
		MTU:                 mtu,
	}

	s, err := serverConfig.Server(logger, listenConfigCache)
	if err != nil {
		t.Fatalf("Failed to create server service %q: %v", serverConfig.Name, err)
	}
	if err = s.Start(ctx); err != nil {
		t.Fatalf("Failed to start server service %q: %v", serverConfig.Name, err)
	}
	defer s.Stop()

	proxyAddrPort := s.proxyConn.LocalAddr().(*net.UDPAddr).AddrPort()

	clientConfig := ClientConfig{
		Name:                   "wg0",
		WgListenNetwork:        listenNetwork,
		WgListenAddress:        listenAddress,
		ProxyEndpointNetwork:   endpointNetwork,
		ProxyEndpointAddress:   conn.AddrFromIPPort(proxyAddrPort),
		ProxyConnListenAddress: connectListenAddress,
		ProxyMode:              proxyMode,
		ProxyPSK:               psk,
		MTU:                    mtu,
	}

	c, err := clientConfig.Client(logger, listenConfigCache)
	if err != nil {
		t.Fatalf("Failed to create client service %q: %v", clientConfig.Name, err)
	}
	if err = c.Start(ctx); err != nil {
		t.Fatalf("Failed to start client service %q: %v", clientConfig.Name, err)
	}
	defer c.Stop()

	clientConn, _, err := conn.DefaultUDPDialer.DialUDP(ctx, listenNetwork, c.wgListenAddress)
	if err != nil {
		t.Fatalf("Failed to dial client connection: %v", err)
	}
	defer clientConn.Close()

	// Set read/write deadlines to make the test fail fast.
	deadline := time.Now().Add(3 * time.Second)
	if err = clientConn.SetDeadline(deadline); err != nil {
		t.Fatalf("Failed to set client connection deadline: %v", err)
	}
	if err = serverConn.SetDeadline(deadline); err != nil {
		t.Fatalf("Failed to set server connection deadline: %v", err)
	}

	f(clientConn, serverConn)
}

func testClientServerHandshake(t *testing.T, clientConn, serverConn *net.UDPConn) {
	// Make packets.
	handshakeInitiationPacket := make([]byte, packet.WireGuardMessageLengthHandshakeInitiation)
	handshakeInitiationPacket[0] = packet.WireGuardMessageTypeHandshakeInitiation
	rand.Read(handshakeInitiationPacket[1:])
	expectedHandshakeInitiationPacket := slices.Clone(handshakeInitiationPacket)
	receivedHandshakeInitiationPacket := make([]byte, packet.WireGuardMessageLengthHandshakeInitiation+1)

	handshakeResponsePacket := make([]byte, packet.WireGuardMessageLengthHandshakeResponse)
	handshakeResponsePacket[0] = packet.WireGuardMessageTypeHandshakeResponse
	rand.Read(handshakeResponsePacket[1:])
	expectedHandshakeResponsePacket := slices.Clone(handshakeResponsePacket)
	receivedHandshakeResponsePacket := make([]byte, packet.WireGuardMessageLengthHandshakeResponse+1)

	// Client sends handshake initiation.
	if _, err := clientConn.Write(handshakeInitiationPacket); err != nil {
		t.Fatalf("Failed to write handshake initiation packet: %v", err)
	}

	// Server receives handshake initiation.
	n, addr, err := serverConn.ReadFromUDPAddrPort(receivedHandshakeInitiationPacket)
	if err != nil {
		t.Fatalf("Failed to read handshake initiation packet: %v", err)
	}
	receivedHandshakeInitiationPacket = receivedHandshakeInitiationPacket[:n]

	// Server verifies handshake initiation.
	if !bytes.Equal(receivedHandshakeInitiationPacket, expectedHandshakeInitiationPacket) {
		t.Errorf("receivedHandshakeInitiationPacket = %v, want %v", receivedHandshakeInitiationPacket, expectedHandshakeInitiationPacket)
	}

	// Server sends handshake response.
	_, err = serverConn.WriteToUDPAddrPort(handshakeResponsePacket, addr)
	if err != nil {
		t.Fatalf("Failed to write handshake response packet: %v", err)
	}

	// Client receives handshake response.
	n, err = clientConn.Read(receivedHandshakeResponsePacket)
	if err != nil {
		t.Fatalf("Failed to read handshake response packet: %v", err)
	}
	receivedHandshakeResponsePacket = receivedHandshakeResponsePacket[:n]

	// Client verifies handshake response.
	if !bytes.Equal(receivedHandshakeResponsePacket, expectedHandshakeResponsePacket) {
		t.Errorf("receivedHandshakeResponsePacket = %v, want %v", receivedHandshakeResponsePacket, expectedHandshakeResponsePacket)
	}
}

func testClientServerDataPackets(t *testing.T, clientConn, serverConn *net.UDPConn) {
	// Make packets.
	smallDataPacket := make([]byte, 1024)
	smallDataPacket[0] = packet.WireGuardMessageTypeData
	rand.Read(smallDataPacket[1:])
	expectedSmallDataPacket := slices.Clone(smallDataPacket)
	receivedSmallDataPacket := make([]byte, 1024+1)

	// Client sends small data packet.
	if _, err := clientConn.Write(smallDataPacket); err != nil {
		t.Fatalf("Failed to write small data packet: %v", err)
	}

	// Server receives small data packet.
	n, addr, err := serverConn.ReadFromUDPAddrPort(receivedSmallDataPacket)
	if err != nil {
		t.Fatalf("Failed to read small data packet: %v", err)
	}
	receivedSmallDataPacket = receivedSmallDataPacket[:n]

	// Server verifies small data packet.
	if !bytes.Equal(receivedSmallDataPacket, expectedSmallDataPacket) {
		t.Errorf("receivedSmallDataPacket = %v, want %v", receivedSmallDataPacket, expectedSmallDataPacket)
	}

	// Server sends small data packet.
	_, err = serverConn.WriteToUDPAddrPort(smallDataPacket, addr)
	if err != nil {
		t.Fatalf("Failed to write small data packet: %v", err)
	}

	// Client receives small data packet.
	n, err = clientConn.Read(receivedSmallDataPacket)
	if err != nil {
		t.Fatalf("Failed to read small data packet: %v", err)
	}
	receivedSmallDataPacket = receivedSmallDataPacket[:n]

	// Client verifies small data packet.
	if !bytes.Equal(receivedSmallDataPacket, expectedSmallDataPacket) {
		t.Errorf("receivedSmallDataPacket = %v, want %v", receivedSmallDataPacket, expectedSmallDataPacket)
	}
}
