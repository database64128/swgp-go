package service

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"

	"github.com/database64128/swgp-go/logging"
	"github.com/database64128/swgp-go/packet"
)

func generateTestPSK(t *testing.T) []byte {
	psk := make([]byte, 32)
	_, err := rand.Read(psk)
	if err != nil {
		t.Fatal(err)
	}
	return psk
}

func testClientServerHandshake(t *testing.T, serverConfig ServerConfig, clientConfig ClientConfig) {
	logger, err := logging.NewProductionConsole(false, "debug")
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Sync()

	sc := ServiceConfig{
		Interfaces: []ServerConfig{serverConfig},
		Peers:      []ClientConfig{clientConfig},
	}
	err = sc.Start(logger)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Stop()

	// Make packets.
	handshakeInitiationPacket := make([]byte, packet.WireGuardMessageLengthHandshakeInitiation)
	handshakeInitiationPacket[0] = packet.WireGuardMessageTypeHandshakeInitiation
	_, err = rand.Read(handshakeInitiationPacket[1:])
	if err != nil {
		t.Fatal(err)
	}
	expectedHandshakeInitiationPacket := make([]byte, packet.WireGuardMessageLengthHandshakeInitiation)
	copy(expectedHandshakeInitiationPacket, handshakeInitiationPacket)
	receivedHandshakeInitiationPacket := make([]byte, packet.WireGuardMessageLengthHandshakeInitiation+1)

	handshakeResponsePacket := make([]byte, packet.WireGuardMessageLengthHandshakeResponse)
	handshakeResponsePacket[0] = packet.WireGuardMessageTypeHandshakeResponse
	_, err = rand.Read(handshakeResponsePacket[1:])
	if err != nil {
		t.Fatal(err)
	}
	expectedHandshakeResponsePacket := make([]byte, packet.WireGuardMessageLengthHandshakeResponse)
	copy(expectedHandshakeResponsePacket, handshakeResponsePacket)
	receivedHandshakeResponsePacket := make([]byte, packet.WireGuardMessageLengthHandshakeResponse+1)

	// Start client and server conns.
	clientConn, err := net.Dial("udp", clientConfig.WgListen)
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenPacket("udp", serverConfig.WgEndpoint)
	if err != nil {
		t.Fatal(err)
	}

	// Client sends handshake initiation.
	_, err = clientConn.Write(handshakeInitiationPacket)
	if err != nil {
		t.Fatal(err)
	}

	// Server receives handshake initiation.
	n, addr, err := serverConn.ReadFrom(receivedHandshakeInitiationPacket)
	if err != nil {
		t.Fatal(err)
	}

	// Server verifies handshake initiation.
	if !bytes.Equal(receivedHandshakeInitiationPacket[:n], expectedHandshakeInitiationPacket) {
		t.Error("Received handshake initiation packet does not match expectation.")
	}

	// Server sends handshake response.
	_, err = serverConn.WriteTo(handshakeResponsePacket, addr)
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

func TestClientServerHandshakeZeroOverhead(t *testing.T) {
	psk := generateTestPSK(t)

	serverConfig := ServerConfig{
		Name:        "wg0",
		ProxyListen: ":20220",
		ProxyMode:   "zero-overhead",
		ProxyPSK:    psk,
		WgEndpoint:  "[::1]:20221",
		MTU:         1500,
	}

	clientConfig := ClientConfig{
		Name:          "wg0",
		WgListen:      ":20222",
		ProxyEndpoint: "[::1]:20220",
		ProxyMode:     "zero-overhead",
		ProxyPSK:      psk,
		MTU:           1500,
	}

	testClientServerHandshake(t, serverConfig, clientConfig)
}

func TestClientServerHandshakeParanoid(t *testing.T) {
	psk := generateTestPSK(t)

	serverConfig := ServerConfig{
		Name:        "wg0",
		ProxyListen: ":20223",
		ProxyMode:   "paranoid",
		ProxyPSK:    psk,
		WgEndpoint:  "[::1]:20224",
		MTU:         1500,
	}

	clientConfig := ClientConfig{
		Name:          "wg0",
		WgListen:      ":20225",
		ProxyEndpoint: "[::1]:20223",
		ProxyMode:     "paranoid",
		ProxyPSK:      psk,
		MTU:           1500,
	}

	testClientServerHandshake(t, serverConfig, clientConfig)
}

func testClientServerDataPackets(t *testing.T, serverConfig ServerConfig, clientConfig ClientConfig) {
	logger, err := logging.NewProductionConsole(false, "debug")
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Sync()

	sc := ServiceConfig{
		Interfaces: []ServerConfig{serverConfig},
		Peers:      []ClientConfig{clientConfig},
	}
	err = sc.Start(logger)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Stop()

	// Make packets.
	smallDataPacket := make([]byte, 1024)
	smallDataPacket[0] = packet.WireGuardMessageTypeData
	_, err = rand.Read(smallDataPacket[1:])
	if err != nil {
		t.Fatal(err)
	}
	expectedSmallDataPacket := make([]byte, 1024)
	copy(expectedSmallDataPacket, smallDataPacket)
	receivedSmallDataPacket := make([]byte, 1024+1)

	bigDataPacket := make([]byte, 2048)
	bigDataPacket[0] = packet.WireGuardMessageTypeData
	_, err = rand.Read(bigDataPacket[1:])
	if err != nil {
		t.Fatal(err)
	}

	// Start client and server conns.
	clientConn, err := net.Dial("udp", clientConfig.WgListen)
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenPacket("udp", serverConfig.WgEndpoint)
	if err != nil {
		t.Fatal(err)
	}

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
	n, addr, err := serverConn.ReadFrom(receivedSmallDataPacket)
	if err != nil {
		t.Fatal(err)
	}

	// Server verifies small data packet.
	if !bytes.Equal(receivedSmallDataPacket[:n], expectedSmallDataPacket) {
		t.Error("Received small data packet does not match expectation.")
	}

	// Server sends big data packet.
	_, err = serverConn.WriteTo(bigDataPacket, addr)
	if err != nil {
		t.Fatal(err)
	}

	// Server sends small data packet.
	_, err = serverConn.WriteTo(smallDataPacket, addr)
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

func TestClientServerDataPacketsZeroOverhead(t *testing.T) {
	psk := generateTestPSK(t)

	serverConfig := ServerConfig{
		Name:        "wg0",
		ProxyListen: ":20230",
		ProxyMode:   "zero-overhead",
		ProxyPSK:    psk,
		WgEndpoint:  "[::1]:20231",
		MTU:         1500,
	}

	clientConfig := ClientConfig{
		Name:          "wg0",
		WgListen:      ":20232",
		ProxyEndpoint: "[::1]:20230",
		ProxyMode:     "zero-overhead",
		ProxyPSK:      psk,
		MTU:           1500,
	}

	testClientServerDataPackets(t, serverConfig, clientConfig)
}

func TestClientServerDataPacketsParanoid(t *testing.T) {
	psk := generateTestPSK(t)

	serverConfig := ServerConfig{
		Name:        "wg0",
		ProxyListen: ":20233",
		ProxyMode:   "paranoid",
		ProxyPSK:    psk,
		WgEndpoint:  "[::1]:20234",
		MTU:         1500,
	}

	clientConfig := ClientConfig{
		Name:          "wg0",
		WgListen:      ":20235",
		ProxyEndpoint: "[::1]:20233",
		ProxyMode:     "paranoid",
		ProxyPSK:      psk,
		MTU:           1500,
	}

	testClientServerDataPackets(t, serverConfig, clientConfig)
}
