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

var cases = []struct {
	name         string
	serverConfig ServerConfig
	clientConfig ClientConfig
}{
	{
		name: "ZeroOverhead",
		serverConfig: ServerConfig{
			Name:               "wg0",
			ProxyListenAddress: "[::1]:",
			ProxyMode:          "zero-overhead",
			WgEndpointAddress:  conn.AddrFromIPAndPort(netip.IPv6Loopback(), 0),
			MTU:                1500,
		},
		clientConfig: ClientConfig{
			Name:                 "wg0",
			WgListenAddress:      "[::1]:",
			ProxyEndpointAddress: conn.AddrFromIPAndPort(netip.IPv6Loopback(), 0),
			ProxyMode:            "zero-overhead",
			MTU:                  1500,
		},
	},
	{
		name: "Paranoid",
		serverConfig: ServerConfig{
			Name:               "wg0",
			ProxyListenAddress: "[::1]:",
			ProxyMode:          "paranoid",
			WgEndpointAddress:  conn.AddrFromIPAndPort(netip.IPv6Loopback(), 0),
			MTU:                1500,
		},
		clientConfig: ClientConfig{
			Name:                 "wg0",
			WgListenAddress:      "[::1]:",
			ProxyEndpointAddress: conn.AddrFromIPAndPort(netip.IPv6Loopback(), 0),
			ProxyMode:            "paranoid",
			MTU:                  1500,
		},
	},
}

func testClientServerConn(
	t *testing.T,
	logger *tslog.Logger,
	serverConfig ServerConfig,
	clientConfig ClientConfig,
	f func(t *testing.T, clientConn, serverConn *net.UDPConn),
) {
	psk := make([]byte, 32)
	rand.Read(psk)
	serverConfig.ProxyPSK = psk
	clientConfig.ProxyPSK = psk

	listenConfigCache := conn.NewListenConfigCache()
	ctx := t.Context()

	s, err := serverConfig.Server(logger, listenConfigCache)
	if err != nil {
		t.Fatalf("Failed to create server service %q: %v", serverConfig.Name, err)
	}
	if err = s.Start(ctx); err != nil {
		t.Fatalf("Failed to start server service %q: %v", serverConfig.Name, err)
	}
	defer s.Stop()

	proxyAddrPort := s.proxyConn.LocalAddr().(*net.UDPAddr).AddrPort()
	clientConfig.ProxyEndpointAddress = conn.AddrFromIPPort(proxyAddrPort)

	c, err := clientConfig.Client(logger, listenConfigCache)
	if err != nil {
		t.Fatalf("Failed to create client service %q: %v", clientConfig.Name, err)
	}
	if err = c.Start(ctx); err != nil {
		t.Fatalf("Failed to start client service %q: %v", clientConfig.Name, err)
	}
	defer c.Stop()

	clientConn, err := net.Dial("udp", c.wgListenAddress)
	if err != nil {
		t.Fatalf("Failed to dial client connection: %v", err)
	}
	defer clientConn.Close()

	serverConn, _, err := conn.DefaultUDPClientListenConfig.ListenUDP(ctx, "udp", "[::1]:")
	if err != nil {
		t.Fatalf("Failed to listen server connection: %v", err)
	}
	defer serverConn.Close()

	serverWgAddrPort := serverConn.LocalAddr().(*net.UDPAddr).AddrPort()
	s.wgAddr = conn.AddrFromIPPort(serverWgAddrPort)

	// Set read/write deadlines to make the test fail fast.
	deadline := time.Now().Add(3 * time.Second)
	if err = clientConn.SetDeadline(deadline); err != nil {
		t.Fatalf("Failed to set client connection deadline: %v", err)
	}
	if err = serverConn.SetDeadline(deadline); err != nil {
		t.Fatalf("Failed to set server connection deadline: %v", err)
	}

	f(t, clientConn.(*net.UDPConn), serverConn)
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

func TestClientServerHandshake(t *testing.T) {
	logCfg := tslogtest.Config{Level: slog.LevelDebug}
	logger := logCfg.NewTestLogger(t)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testClientServerConn(t, logger, c.serverConfig, c.clientConfig, testClientServerHandshake)
		})
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

func TestClientServerDataPackets(t *testing.T) {
	logCfg := tslogtest.Config{Level: slog.LevelDebug}
	logger := logCfg.NewTestLogger(t)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testClientServerConn(t, logger, c.serverConfig, c.clientConfig, testClientServerDataPackets)
		})
	}
}
