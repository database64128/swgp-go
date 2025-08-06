package service

import (
	"bytes"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/packet"
	"github.com/database64128/swgp-go/service/internal/packetseq"
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

var loMTU = firstLoopbackInterfaceMTU()

func firstLoopbackInterfaceMTU() int {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			return iface.MTU
		}
	}

	return 0
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
							if mtuCase.mtu > loMTU {
								t.Skipf("MTU %d is larger than loopback interface MTU %d", mtuCase.mtu, loMTU)
							}

							t.Parallel()

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
								PerfConfig{},
								5*time.Second,
								false,
								func(
									t *testing.T,
									_ *tslog.Logger,
									clientConn, serverConn *net.UDPConn,
									_, _ conn.SocketInfo,
									client *client, _ *server,
								) {
									t.Run("Handshake", func(t *testing.T) {
										testClientServerHandshake(t, clientConn, serverConn)
									})

									t.Run("DataPackets", func(t *testing.T) {
										testClientServerDataPackets(t, clientConn, serverConn, client)
									})
								},
							)
						})
					}
				})
			}
		})
	}
}

func testClientServerConn(
	t *testing.T,
	logger *tslog.Logger,
	proxyMode string,
	generatePSK func() []byte,
	listenNetwork string,
	listenAddress string,
	endpointNetwork string,
	connectLocalAddress conn.Addr,
	mtu int,
	perfConfig PerfConfig,
	timeout time.Duration,
	clientConnNoDial bool,
	f func(
		t *testing.T,
		logger *tslog.Logger,
		clientConn, serverConn *net.UDPConn,
		clientConnInfo, serverConnInfo conn.SocketInfo,
		client *client, server *server,
	),
) {
	ctx := t.Context()
	listenConfigCache := conn.NewUDPSocketConfigCache()

	serverConn, serverConnInfo, err := conn.DefaultUDPServerSocketConfig.Listen(ctx, listenNetwork, listenAddress)
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
		PerfConfig:          perfConfig,
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
		PerfConfig:             perfConfig,
	}

	c, err := clientConfig.Client(logger, listenConfigCache)
	if err != nil {
		t.Fatalf("Failed to create client service %q: %v", clientConfig.Name, err)
	}
	if err = c.Start(ctx); err != nil {
		t.Fatalf("Failed to start client service %q: %v", clientConfig.Name, err)
	}
	defer c.Stop()

	var (
		clientConn     *net.UDPConn
		clientConnInfo conn.SocketInfo
	)
	if !clientConnNoDial {
		clientConn, clientConnInfo, err = conn.DefaultUDPClientSocketConfig.Dial(ctx, conn.Addr{}, listenNetwork, c.wgListenAddress)
	} else {
		clientConn, clientConnInfo, err = conn.DefaultUDPClientSocketConfig.Listen(ctx, listenNetwork, listenAddress)
	}
	if err != nil {
		t.Fatalf("Failed to dial client connection: %v", err)
	}
	defer clientConn.Close()

	// Set read/write deadlines to make the test fail fast.
	deadline := time.Now().Add(timeout)
	if err = clientConn.SetDeadline(deadline); err != nil {
		t.Fatalf("Failed to set client connection deadline: %v", err)
	}
	if err = serverConn.SetDeadline(deadline); err != nil {
		t.Fatalf("Failed to set server connection deadline: %v", err)
	}

	f(t, logger, clientConn, serverConn, clientConnInfo, serverConnInfo, c, s)
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

func testClientServerDataPackets(t *testing.T, clientConn, serverConn *net.UDPConn, client *client) {
	// Make packets.
	dataPacketLen := client.wgTunnelMTUv6 + WireGuardDataPacketOverhead
	dataPacket := make([]byte, dataPacketLen, 65535)
	dataPacket[0] = packet.WireGuardMessageTypeData
	rand.Read(dataPacket[1:])
	expectedDataPacket := slices.Clone(dataPacket)
	receivedDataPacket := make([]byte, dataPacketLen+1)

	// Client sends data packet.
	if _, err := clientConn.Write(dataPacket); err != nil {
		t.Fatalf("Failed to write data packet: %v", err)
	}

	// Server receives data packet.
	n, addr, err := serverConn.ReadFromUDPAddrPort(receivedDataPacket)
	if err != nil {
		t.Fatalf("Failed to read data packet: %v", err)
	}
	receivedDataPacket = receivedDataPacket[:n]

	// Server verifies data packet.
	if !bytes.Equal(receivedDataPacket, expectedDataPacket) {
		t.Errorf("receivedDataPacket = %v, want %v", receivedDataPacket, expectedDataPacket)
	}

	// Server sends data packet.
	_, err = serverConn.WriteToUDPAddrPort(dataPacket, addr)
	if err != nil {
		t.Fatalf("Failed to write data packet: %v", err)
	}

	// Client receives data packet.
	n, err = clientConn.Read(receivedDataPacket)
	if err != nil {
		t.Fatalf("Failed to read data packet: %v", err)
	}
	receivedDataPacket = receivedDataPacket[:n]

	// Client verifies data packet.
	if !bytes.Equal(receivedDataPacket, expectedDataPacket) {
		t.Errorf("receivedDataPacket = %v, want %v", receivedDataPacket, expectedDataPacket)
	}
}

func TestClientServerSendDrain(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping client-server send/drain test in short mode")
	}

	logCfg := tslogtest.Config{Level: slog.LevelInfo}
	logger := logCfg.NewTestLogger(t)

	for _, proxyModeCase := range proxyModeCases {
		t.Run(proxyModeCase.name, func(t *testing.T) {
			for _, afCase := range addressFamilyCases[1:2] { // No point in testing other cases.
				t.Run(afCase.name, func(t *testing.T) {
					for _, mtuCase := range mtuCases[1:] { // Skip 1492, which should perform similarly to 1500.
						t.Run(mtuCase.name, func(t *testing.T) {
							if mtuCase.mtu > loMTU {
								t.Skipf("MTU %d is larger than loopback interface MTU %d", mtuCase.mtu, loMTU)
							}

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
								PerfConfig{},
								time.Minute,
								true, // To work around https://github.com/golang/go/issues/74841, use ListenUDP for now.
								testClientServerSendDrain,
							)
						})
					}
				})
			}
		})
	}
}

func testClientServerSendDrain(
	t *testing.T,
	logger *tslog.Logger,
	clientConn, serverConn *net.UDPConn,
	clientConnInfo, serverConnInfo conn.SocketInfo,
	client *client, _ *server,
) {
	var serverConnPeer netip.AddrPort
	clientConnPeer := client.wgConn.LocalAddr().(*net.UDPAddr).AddrPort()
	segmentSize := client.wgTunnelMTUv6 + WireGuardDataPacketOverhead

	t.Run("C->S", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			serverConnPeer = testDrainConn(t, logger, serverConn)
			wg.Done()
		}()
		testSendConn(t, logger, clientConn, clientConnInfo, clientConnPeer, segmentSize)
		wg.Wait()
	})

	if !serverConnPeer.IsValid() {
		t.Fatalf("serverConnPeer is unknown")
	}

	t.Run("S->C", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			_ = testDrainConn(t, logger, clientConn)
			wg.Done()
		}()
		testSendConn(t, logger, serverConn, serverConnInfo, serverConnPeer, segmentSize)
		wg.Wait()
	})
}

func testDrainConn(t *testing.T, logger *tslog.Logger, drainConn *net.UDPConn) (from netip.AddrPort) {
	var (
		recvmsgCount          uint
		bytesReceived         uint64
		packetsReceived       uint
		burstRecvSegmentCount uint
		receiver              packetseq.Receiver
	)

	packetBuf := make([]byte, 65535)
	cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)

	for {
		n, cmsgn, flags, clientAddrPort, err := drainConn.ReadMsgUDPAddrPort(packetBuf, cmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			t.Errorf("drainConn.ReadMsgUDPAddrPort failed: %v", err)
			return from
		}
		if err = conn.ParseFlagsForError(flags); err != nil {
			t.Errorf("drainConn.ReadMsgUDPAddrPort flags error: %v", err)
			return from
		}

		scm, err := conn.ParseSocketControlMessage(cmsgBuf[:cmsgn])
		if err != nil {
			t.Errorf("Failed to parse socket control message from drainConn: %v", err)
			return from
		}

		recvmsgCount++
		bytesReceived += uint64(n)

		segmentSize := int(scm.SegmentSize)
		if segmentSize == 0 {
			segmentSize = n
		}

		var recvSegmentCount uint

		for buf := packetBuf[:n]; len(buf) > 0; {
			segmentLength := min(len(buf), segmentSize)
			segment := buf[:segmentLength]
			buf = buf[segmentLength:]
			recvSegmentCount++

			if err := receiver.Validate(segment); err != nil {
				t.Logf("receiver.Validate failed: %v", err)
			} else {
				from = clientAddrPort
			}
		}

		packetsReceived += recvSegmentCount
		burstRecvSegmentCount = max(burstRecvSegmentCount, recvSegmentCount)

		// After the initial read, the next read should return quickly, until all packets are drained.
		// Therefore, we set a short read deadline to detect completion.
		if err := drainConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Errorf("drainConn.SetReadDeadline failed: %v", err)
			return from
		}
	}

	logger.Info("Drained packets",
		tslog.Uint("recvmsgCount", recvmsgCount),
		tslog.Uint("bytesReceived", bytesReceived),
		tslog.Uint("packetsReceived", packetsReceived),
		tslog.Uint("burstRecvSegmentCount", burstRecvSegmentCount),
		tslog.Uint("lastPacketID", receiver.LastID()),
		tslog.Uint("uniquePacketCount", receiver.Count()),
	)

	return from
}

func testSendConn(
	t *testing.T,
	logger *tslog.Logger,
	sendConn *net.UDPConn,
	sendConnInfo conn.SocketInfo,
	sendAddrPort netip.AddrPort,
	segmentSize int,
) {
	packetBuf := make([]byte, 0, 65535)
	rand.Read(packetBuf[:cap(packetBuf)])

	var segmentCount uint

	for segmentsRemaining := sendConnInfo.MaxUDPGSOSegments; segmentsRemaining > 0 && cap(packetBuf)-len(packetBuf) >= segmentSize; segmentsRemaining-- {
		packetBufLen := len(packetBuf)
		packetBuf = packetBuf[:packetBufLen+segmentSize]
		segment := packetBuf[packetBufLen:]
		segment[0] = packet.WireGuardMessageTypeData
		segmentCount++
	}

	var scm conn.SocketControlMessage
	if segmentCount > 1 {
		scm.SegmentSize = uint32(segmentSize)
	}
	cmsgBuf := make([]byte, 0, conn.SocketControlMessageBufferSize)
	cmsgBuf = scm.AppendTo(cmsgBuf)

	var sender packetseq.Sender
	ctxDone := t.Context().Done()

	for range 4096 {
		for buf := packetBuf; len(buf) >= segmentSize; buf = buf[segmentSize:] {
			sender.Stamp(buf[:segmentSize])
		}

		if _, _, err := sendConn.WriteMsgUDPAddrPort(packetBuf, cmsgBuf, sendAddrPort); err != nil {
			t.Errorf("sendConn.WriteMsgUDPAddrPort failed: %v", err)
			return
		}

		select {
		case <-ctxDone:
		case <-time.After(50 * time.Microsecond):
		}
	}

	logger.Info("Sent packets",
		tslog.Int("segmentSize", segmentSize),
		tslog.Uint("segmentCount", segmentCount),
		tslog.Uint("packetCount", sender.Count()),
	)
}
