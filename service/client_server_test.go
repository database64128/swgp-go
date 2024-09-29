package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/packet"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
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
			ProxyListenAddress: ":20200",
			ProxyMode:          "zero-overhead",
			WgEndpointAddress:  conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Loopback(), 20201)),
			MTU:                1500,
		},
		clientConfig: ClientConfig{
			Name:                 "wg0",
			WgListenAddress:      ":20202",
			ProxyEndpointAddress: conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Loopback(), 20200)),
			ProxyMode:            "zero-overhead",
			MTU:                  1500,
		},
	},
	{
		name: "Paranoid",
		serverConfig: ServerConfig{
			Name:               "wg0",
			ProxyListenAddress: ":20200",
			ProxyMode:          "paranoid",
			WgEndpointAddress:  conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Loopback(), 20201)),
			MTU:                1500,
		},
		clientConfig: ClientConfig{
			Name:                 "wg0",
			WgListenAddress:      ":20202",
			ProxyEndpointAddress: conn.AddrFromIPPort(netip.AddrPortFrom(netip.IPv6Loopback(), 20200)),
			ProxyMode:            "paranoid",
			MTU:                  1500,
		},
	},
}

func init() {
	for i := range cases {
		psk := generateTestPSK()
		cases[i].serverConfig.ProxyPSK = psk
		cases[i].clientConfig.ProxyPSK = psk
	}
}

func generateTestPSK() []byte {
	psk := make([]byte, 32)
	_, err := rand.Read(psk)
	if err != nil {
		panic(err)
	}
	return psk
}

func testClientServerHandshake(t *testing.T, ctx context.Context, logger *zap.Logger, serverConfig ServerConfig, clientConfig ClientConfig) {
	sc := Config{
		Servers: []ServerConfig{serverConfig},
		Clients: []ClientConfig{clientConfig},
	}
	m, err := sc.Manager(logger)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	// Make packets.
	handshakeInitiationPacket := make([]byte, packet.WireGuardMessageLengthHandshakeInitiation)
	handshakeInitiationPacket[0] = packet.WireGuardMessageTypeHandshakeInitiation
	if _, err = rand.Read(handshakeInitiationPacket[1:]); err != nil {
		t.Fatal(err)
	}
	expectedHandshakeInitiationPacket := make([]byte, packet.WireGuardMessageLengthHandshakeInitiation)
	copy(expectedHandshakeInitiationPacket, handshakeInitiationPacket)
	receivedHandshakeInitiationPacket := make([]byte, packet.WireGuardMessageLengthHandshakeInitiation+1)

	handshakeResponsePacket := make([]byte, packet.WireGuardMessageLengthHandshakeResponse)
	handshakeResponsePacket[0] = packet.WireGuardMessageTypeHandshakeResponse
	if _, err = rand.Read(handshakeResponsePacket[1:]); err != nil {
		t.Fatal(err)
	}
	expectedHandshakeResponsePacket := make([]byte, packet.WireGuardMessageLengthHandshakeResponse)
	copy(expectedHandshakeResponsePacket, handshakeResponsePacket)
	receivedHandshakeResponsePacket := make([]byte, packet.WireGuardMessageLengthHandshakeResponse+1)

	// Start client and server conns.
	clientConn, err := net.Dial("udp", clientConfig.WgListenAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	serverConn, _, err := conn.DefaultUDPClientListenConfig.ListenUDP(ctx, "udp", serverConfig.WgEndpointAddress.String())
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	// Client sends handshake initiation.
	_, err = clientConn.Write(handshakeInitiationPacket)
	if err != nil {
		t.Fatal(err)
	}

	// Server receives handshake initiation.
	n, addr, err := serverConn.ReadFromUDPAddrPort(receivedHandshakeInitiationPacket)
	if err != nil {
		t.Fatal(err)
	}

	// Server verifies handshake initiation.
	if !bytes.Equal(receivedHandshakeInitiationPacket[:n], expectedHandshakeInitiationPacket) {
		t.Error("Received handshake initiation packet does not match expectation.")
	}

	// Server sends handshake response.
	_, err = serverConn.WriteToUDPAddrPort(handshakeResponsePacket, addr)
	if err != nil {
		t.Fatal(err)
	}

	// Client receives handshake response.
	n, err = clientConn.Read(receivedHandshakeResponsePacket)
	if err != nil {
		t.Fatal(err)
	}

	// Client verifies handshake response.
	if !bytes.Equal(receivedHandshakeResponsePacket[:n], expectedHandshakeResponsePacket) {
		t.Error("Received handshake response packet does not match expectation.")
	}
}

func TestClientServerHandshake(t *testing.T) {
	ctx := context.Background()
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testClientServerHandshake(t, ctx, logger, c.serverConfig, c.clientConfig)
		})
	}
}

func testClientServerDataPackets(t *testing.T, ctx context.Context, logger *zap.Logger, serverConfig ServerConfig, clientConfig ClientConfig) {
	sc := Config{
		Servers: []ServerConfig{serverConfig},
		Clients: []ClientConfig{clientConfig},
	}
	m, err := sc.Manager(logger)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	// Make packets.
	smallDataPacket := make([]byte, 1024)
	smallDataPacket[0] = packet.WireGuardMessageTypeData
	if _, err = rand.Read(smallDataPacket[1:]); err != nil {
		t.Fatal(err)
	}
	expectedSmallDataPacket := make([]byte, 1024)
	copy(expectedSmallDataPacket, smallDataPacket)
	receivedSmallDataPacket := make([]byte, 1024+1)

	bigDataPacket := make([]byte, 2048)
	bigDataPacket[0] = packet.WireGuardMessageTypeData
	if _, err = rand.Read(bigDataPacket[1:]); err != nil {
		t.Fatal(err)
	}

	// Start client and server conns.
	clientConn, err := net.Dial("udp", clientConfig.WgListenAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	serverConn, _, err := conn.DefaultUDPClientListenConfig.ListenUDP(ctx, "udp", serverConfig.WgEndpointAddress.String())
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	// Client sends big data packet.
	_, err = clientConn.Write(bigDataPacket)
	if err != nil {
		t.Fatal(err)
	}

	// Client sends small data packet.
	_, err = clientConn.Write(smallDataPacket)
	if err != nil {
		t.Fatal(err)
	}

	// Server receives small data packet.
	n, addr, err := serverConn.ReadFromUDPAddrPort(receivedSmallDataPacket)
	if err != nil {
		t.Fatal(err)
	}

	// Server verifies small data packet.
	if !bytes.Equal(receivedSmallDataPacket[:n], expectedSmallDataPacket) {
		t.Error("Received small data packet does not match expectation.")
	}

	// Server sends big data packet.
	_, err = serverConn.WriteToUDPAddrPort(bigDataPacket, addr)
	if err != nil {
		t.Fatal(err)
	}

	// Server sends small data packet.
	_, err = serverConn.WriteToUDPAddrPort(smallDataPacket, addr)
	if err != nil {
		t.Fatal(err)
	}

	// Client receives small data packet.
	n, err = clientConn.Read(receivedSmallDataPacket)
	if err != nil {
		t.Fatal(err)
	}

	// Client verifies small data packet.
	if !bytes.Equal(receivedSmallDataPacket[:n], expectedSmallDataPacket) {
		t.Error("Received small data packet does not match expectation.")
	}
}

func TestClientServerDataPackets(t *testing.T) {
	ctx := context.Background()
	logger := zaptest.NewLogger(t)
	defer logger.Sync()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			testClientServerDataPackets(t, ctx, logger, c.serverConfig, c.clientConfig)
		})
	}
}
