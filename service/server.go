package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/packet"
	"go.uber.org/zap"
)

// ServerConfig stores configurations for a swgp server service.
// It may be marshaled as or unmarshaled from JSON.
type ServerConfig struct {
	Name                string    `json:"name"`
	ProxyListenNetwork  string    `json:"proxyListenNetwork"`
	ProxyListenAddress  string    `json:"proxyListen"`
	ProxyMode           string    `json:"proxyMode"`
	ProxyPSK            []byte    `json:"proxyPSK"`
	ProxyFwmark         int       `json:"proxyFwmark"`
	ProxyTrafficClass   int       `json:"proxyTrafficClass"`
	WgEndpointNetwork   string    `json:"wgEndpointNetwork"`
	WgEndpointAddress   conn.Addr `json:"wgEndpoint"`
	WgConnListenNetwork string    `json:"wgConnListenNetwork"`
	WgConnListenAddress string    `json:"wgConnListenAddress"`
	WgFwmark            int       `json:"wgFwmark"`
	WgTrafficClass      int       `json:"wgTrafficClass"`
	MTU                 int       `json:"mtu"`
	PerfConfig
}

type serverNatEntry struct {
	// state synchronizes session initialization and shutdown.
	//
	//  - Swap the wgConn in to signal initialization completion.
	//  - Swap the proxyConn in to signal shutdown.
	//
	// Callers must check the swapped-out value to determine the next action.
	//
	//  - During initialization, if the swapped-out value is non-nil,
	//    initialization must not proceed.
	//  - During shutdown, if the swapped-out value is nil, preceed to the next entry.
	state              atomic.Pointer[net.UDPConn]
	clientPktinfo      atomic.Pointer[[]byte]
	clientPktinfoCache []byte
	wgConnSendCh       chan<- queuedPacket
}

type serverNatUplinkGeneric struct {
	clientAddrPort netip.AddrPort
	wgAddrPort     netip.AddrPort
	wgConn         *net.UDPConn
	wgConnSendCh   <-chan queuedPacket
}

type serverNatDownlinkGeneric struct {
	clientAddrPort     netip.AddrPort
	clientPktinfo      *atomic.Pointer[[]byte]
	wgAddrPort         netip.AddrPort
	wgConn             *net.UDPConn
	proxyConn          *net.UDPConn
	maxProxyPacketSize int
}

type server struct {
	name                  string
	proxyListenNetwork    string
	proxyListenAddress    string
	wgConnListenNetwork   string
	wgConnListenAddress   string
	relayBatchSize        int
	mainRecvBatchSize     int
	sendChannelCapacity   int
	maxProxyPacketSizev4  int
	maxProxyPacketSizev6  int
	wgTunnelMTUv4         int
	wgTunnelMTUv6         int
	wgNetwork             string
	wgAddr                conn.Addr
	handler               packet.Handler
	logger                *zap.Logger
	proxyConn             *net.UDPConn
	proxyConnListenConfig conn.ListenConfig
	wgConnListenConfig    conn.ListenConfig
	packetBufPool         sync.Pool
	mu                    sync.Mutex
	wg                    sync.WaitGroup
	mwg                   sync.WaitGroup
	table                 map[netip.AddrPort]*serverNatEntry
	startFunc             func(context.Context) error
}

// Server creates a swgp server service from the server config.
// Call the Start method on the returned service to start it.
func (sc *ServerConfig) Server(logger *zap.Logger, listenConfigCache conn.ListenConfigCache) (*server, error) {
	// Require MTU to be at least 1280.
	if sc.MTU < minimumMTU {
		return nil, ErrMTUTooSmall
	}

	// Check ProxyListenNetwork.
	switch sc.ProxyListenNetwork {
	case "":
		sc.ProxyListenNetwork = "udp"
	case "udp", "udp4", "udp6":
	default:
		return nil, fmt.Errorf("invalid proxyListenNetwork: %s", sc.ProxyListenNetwork)
	}

	// Check WgEndpointNetwork.
	switch sc.WgEndpointNetwork {
	case "":
		sc.WgEndpointNetwork = "ip"
	case "ip", "ip4", "ip6":
	default:
		return nil, fmt.Errorf("invalid wgEndpointNetwork: %s", sc.WgEndpointNetwork)
	}

	// Check WgConnListenNetwork.
	switch sc.WgConnListenNetwork {
	case "":
		sc.WgConnListenNetwork = "udp"
	case "udp", "udp4", "udp6":
	default:
		return nil, fmt.Errorf("invalid wgConnListenNetwork: %s", sc.WgConnListenNetwork)
	}

	// Check and apply PerfConfig defaults.
	if err := sc.CheckAndApplyDefaults(); err != nil {
		return nil, err
	}

	// Create packet handler for user-specified proxy mode.
	handler, err := getPacketHandlerForProxyMode(sc.ProxyMode, sc.ProxyPSK)
	if err != nil {
		return nil, err
	}

	// maxProxyPacketSize = MTU - IP header length - UDP header length
	maxProxyPacketSizev4 := sc.MTU - IPv4HeaderLength - UDPHeaderLength
	maxProxyPacketSizev6 := sc.MTU - IPv6HeaderLength - UDPHeaderLength
	wgTunnelMTUv4 := getWgTunnelMTUForHandler(handler, maxProxyPacketSizev4)
	wgTunnelMTUv6 := getWgTunnelMTUForHandler(handler, maxProxyPacketSizev6)

	s := server{
		name:                 sc.Name,
		proxyListenNetwork:   sc.ProxyListenNetwork,
		proxyListenAddress:   sc.ProxyListenAddress,
		wgConnListenNetwork:  sc.WgConnListenNetwork,
		wgConnListenAddress:  sc.WgConnListenAddress,
		relayBatchSize:       sc.RelayBatchSize,
		mainRecvBatchSize:    sc.MainRecvBatchSize,
		sendChannelCapacity:  sc.SendChannelCapacity,
		maxProxyPacketSizev4: maxProxyPacketSizev4,
		maxProxyPacketSizev6: maxProxyPacketSizev6,
		wgTunnelMTUv4:        wgTunnelMTUv4,
		wgTunnelMTUv6:        wgTunnelMTUv6,
		wgNetwork:            sc.WgEndpointNetwork,
		wgAddr:               sc.WgEndpointAddress,
		handler:              handler,
		logger:               logger,
		proxyConnListenConfig: listenConfigCache.Get(conn.ListenerSocketOptions{
			Fwmark:            sc.ProxyFwmark,
			TrafficClass:      sc.ProxyTrafficClass,
			PathMTUDiscovery:  true,
			ReceivePacketInfo: true,
		}),
		wgConnListenConfig: listenConfigCache.Get(conn.ListenerSocketOptions{
			Fwmark:           sc.WgFwmark,
			TrafficClass:     sc.WgTrafficClass,
			PathMTUDiscovery: true,
		}),
		packetBufPool: sync.Pool{
			New: func() any {
				b := make([]byte, maxProxyPacketSizev4)
				return unsafe.SliceData(b)
			},
		},
		table: make(map[netip.AddrPort]*serverNatEntry),
	}
	s.setStartFunc(sc.BatchMode)
	return &s, nil
}

// String implements the Service String method.
func (s *server) String() string {
	return s.name + " swgp server service"
}

// Start implements the Service Start method.
func (s *server) Start(ctx context.Context) (err error) {
	return s.startFunc(ctx)
}

func (s *server) startGeneric(ctx context.Context) error {
	proxyConn, err := s.proxyConnListenConfig.ListenUDP(ctx, s.proxyListenNetwork, s.proxyListenAddress)
	if err != nil {
		return err
	}
	s.proxyConn = proxyConn

	s.mwg.Add(1)

	go func() {
		s.recvFromProxyConnGeneric(ctx, proxyConn)
		s.mwg.Done()
	}()

	s.logger.Info("Started service",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListenAddress),
		zap.Stringer("wgAddress", &s.wgAddr),
		zap.Int("wgTunnelMTUv4", s.wgTunnelMTUv4),
		zap.Int("wgTunnelMTUv6", s.wgTunnelMTUv6),
	)
	return nil
}

func (s *server) recvFromProxyConnGeneric(ctx context.Context, proxyConn *net.UDPConn) {
	cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)

	var (
		packetsReceived uint64
		wgBytesReceived uint64
	)

	for {
		packetBuf := s.getPacketBuf()

		n, cmsgn, flags, clientAddrPort, err := proxyConn.ReadMsgUDPAddrPort(packetBuf, cmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				s.putPacketBuf(packetBuf)
				break
			}
			s.logger.Warn("Failed to read from proxyConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			s.putPacketBuf(packetBuf)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			s.logger.Warn("Failed to read from proxyConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			s.putPacketBuf(packetBuf)
			continue
		}

		wgPacketStart, wgPacketLength, err := s.handler.DecryptZeroCopy(packetBuf, 0, n)
		if err != nil {
			s.logger.Warn("Failed to decrypt swgpPacket",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			s.putPacketBuf(packetBuf)
			continue
		}

		packetsReceived++
		wgBytesReceived += uint64(wgPacketLength)

		s.mu.Lock()

		natEntry, ok := s.table[clientAddrPort]
		if !ok {
			natEntry = &serverNatEntry{}
		}

		cmsg := cmsgBuf[:cmsgn]

		if !bytes.Equal(natEntry.clientPktinfoCache, cmsg) {
			m, err := conn.ParseSocketControlMessage(cmsg)
			if err != nil {
				s.logger.Warn("Failed to parse pktinfo control message from proxyConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Error(err),
				)
				s.putPacketBuf(packetBuf)
				s.mu.Unlock()
				continue
			}

			clientPktinfoCache := make([]byte, len(cmsg))
			copy(clientPktinfoCache, cmsg)
			natEntry.clientPktinfo.Store(&clientPktinfoCache)
			natEntry.clientPktinfoCache = clientPktinfoCache

			if ce := s.logger.Check(zap.DebugLevel, "Updated client pktinfo"); ce != nil {
				ce.Write(
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("clientPktinfoAddr", m.PktinfoAddr),
					zap.Uint32("clientPktinfoIfindex", m.PktinfoIfindex),
				)
			}
		}

		if !ok {
			wgConnSendCh := make(chan queuedPacket, s.sendChannelCapacity)
			natEntry.wgConnSendCh = wgConnSendCh
			s.table[clientAddrPort] = natEntry
			s.wg.Add(1)

			go func() {
				var sendChClean bool

				defer func() {
					s.mu.Lock()
					close(wgConnSendCh)
					delete(s.table, clientAddrPort)
					s.mu.Unlock()

					if !sendChClean {
						for queuedPacket := range wgConnSendCh {
							s.putPacketBuf(queuedPacket.buf)
						}
					}

					s.wg.Done()
				}()

				wgAddrPort, err := s.wgAddr.ResolveIPPort(ctx, s.wgNetwork)
				if err != nil {
					s.logger.Warn("Failed to resolve wg address for new session",
						zap.String("server", s.name),
						zap.String("listenAddress", s.proxyListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Error(err),
					)
					return
				}

				wgConn, err := s.wgConnListenConfig.ListenUDP(ctx, s.wgConnListenNetwork, s.wgConnListenAddress)
				if err != nil {
					s.logger.Warn("Failed to create UDP socket for new session",
						zap.String("server", s.name),
						zap.String("listenAddress", s.proxyListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Error(err),
					)
					return
				}

				err = wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
				if err != nil {
					s.logger.Warn("Failed to SetReadDeadline on wgConn",
						zap.String("server", s.name),
						zap.String("listenAddress", s.proxyListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Error(err),
					)
					wgConn.Close()
					return
				}

				oldState := natEntry.state.Swap(wgConn)
				if oldState != nil {
					wgConn.Close()
					return
				}

				// No more early returns!
				sendChClean = true

				var (
					maxProxyPacketSize int
					wgTunnelMTU        int
				)

				if addr := clientAddrPort.Addr(); addr.Is4() || addr.Is4In6() {
					maxProxyPacketSize = s.maxProxyPacketSizev4
					wgTunnelMTU = s.wgTunnelMTUv4
				} else {
					maxProxyPacketSize = s.maxProxyPacketSizev6
					wgTunnelMTU = s.wgTunnelMTUv6
				}

				s.logger.Info("Server relay started",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("wgAddress", wgAddrPort),
					zap.Int("wgTunnelMTU", wgTunnelMTU),
				)

				s.wg.Add(1)

				go func() {
					s.relayProxyToWgGeneric(serverNatUplinkGeneric{
						clientAddrPort: clientAddrPort,
						wgAddrPort:     wgAddrPort,
						wgConn:         wgConn,
						wgConnSendCh:   wgConnSendCh,
					})
					wgConn.Close()
					s.wg.Done()
				}()

				s.relayWgToProxyGeneric(serverNatDownlinkGeneric{
					clientAddrPort:     clientAddrPort,
					clientPktinfo:      &natEntry.clientPktinfo,
					wgAddrPort:         wgAddrPort,
					wgConn:             wgConn,
					proxyConn:          proxyConn,
					maxProxyPacketSize: maxProxyPacketSize,
				})
			}()

			if ce := s.logger.Check(zap.DebugLevel, "New server session"); ce != nil {
				ce.Write(
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("wgAddress", &s.wgAddr),
				)
			}
		}

		select {
		case natEntry.wgConnSendCh <- queuedPacket{packetBuf, wgPacketStart, wgPacketLength}:
		default:
			if ce := s.logger.Check(zap.DebugLevel, "wgPacket dropped due to full send channel"); ce != nil {
				ce.Write(
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("wgAddress", &s.wgAddr),
				)
			}
			s.putPacketBuf(packetBuf)
		}

		s.mu.Unlock()
	}

	s.logger.Info("Finished receiving from proxyConn",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListenAddress),
		zap.Stringer("wgAddress", &s.wgAddr),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("wgBytesReceived", wgBytesReceived),
	)
}

func (s *server) relayProxyToWgGeneric(uplink serverNatUplinkGeneric) {
	var (
		packetsSent uint64
		wgBytesSent uint64
	)

	for queuedPacket := range uplink.wgConnSendCh {
		wgPacket := queuedPacket.buf[queuedPacket.start : queuedPacket.start+queuedPacket.length]

		if _, err := uplink.wgConn.WriteToUDPAddrPort(wgPacket, uplink.wgAddrPort); err != nil {
			s.logger.Warn("Failed to write wgPacket to wgConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", uplink.clientAddrPort),
				zap.Stringer("wgAddress", uplink.wgAddrPort),
				zap.Int("wgPacketLength", queuedPacket.length),
				zap.Error(err),
			)
		}

		// Update wgConn read deadline when a handshake initiation/response message is received.
		switch wgPacket[0] {
		case packet.WireGuardMessageTypeHandshakeInitiation, packet.WireGuardMessageTypeHandshakeResponse:
			if err := uplink.wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
				s.logger.Warn("Failed to SetReadDeadline on wgConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Stringer("wgAddress", uplink.wgAddrPort),
					zap.Error(err),
				)
			}
		}

		s.putPacketBuf(queuedPacket.buf)
		packetsSent++
		wgBytesSent += uint64(queuedPacket.length)
	}

	s.logger.Info("Finished relay proxyConn -> wgConn",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListenAddress),
		zap.Stringer("clientAddress", uplink.clientAddrPort),
		zap.Stringer("wgAddress", uplink.wgAddrPort),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (s *server) relayWgToProxyGeneric(downlink serverNatDownlinkGeneric) {
	var (
		clientPktinfop *[]byte
		clientPktinfo  []byte
		packetsSent    uint64
		wgBytesSent    uint64
	)

	packetBuf := make([]byte, downlink.maxProxyPacketSize)

	headroom := s.handler.Headroom()
	plaintextBuf := packetBuf[headroom.Front : downlink.maxProxyPacketSize-headroom.Rear]

	for {
		n, _, flags, packetSourceAddrPort, err := downlink.wgConn.ReadMsgUDPAddrPort(plaintextBuf, nil)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			s.logger.Warn("Failed to read from wgConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("wgAddress", downlink.wgAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			s.logger.Warn("Failed to read from wgConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("wgAddress", downlink.wgAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		if !conn.AddrPortMappedEqual(packetSourceAddrPort, downlink.wgAddrPort) {
			s.logger.Warn("Ignoring packet from non-wg address",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("wgAddress", downlink.wgAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}

		swgpPacketStart, swgpPacketLength, err := s.handler.EncryptZeroCopy(packetBuf, headroom.Front, n)
		if err != nil {
			s.logger.Warn("Failed to encrypt WireGuard packet",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("wgAddress", downlink.wgAddrPort),
				zap.Error(err),
			)
			continue
		}
		swgpPacket := packetBuf[swgpPacketStart : swgpPacketStart+swgpPacketLength]

		if cpp := downlink.clientPktinfo.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp
		}

		_, _, err = downlink.proxyConn.WriteMsgUDPAddrPort(swgpPacket, clientPktinfo, downlink.clientAddrPort)
		if err != nil {
			s.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("wgAddress", downlink.wgAddrPort),
				zap.Int("swgpPacketLength", swgpPacketLength),
				zap.Error(err),
			)
		}

		packetsSent++
		wgBytesSent += uint64(n)
	}

	s.logger.Info("Finished relay wgConn -> proxyConn",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListenAddress),
		zap.Stringer("clientAddress", downlink.clientAddrPort),
		zap.Stringer("wgAddress", downlink.wgAddrPort),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

// getPacketBuf retrieves a packet buffer from the pool.
func (s *server) getPacketBuf() []byte {
	return unsafe.Slice(s.packetBufPool.Get().(*byte), s.maxProxyPacketSizev4)
}

// putPacketBuf puts the packet buffer back into the pool.
func (s *server) putPacketBuf(packetBuf []byte) {
	s.packetBufPool.Put(unsafe.SliceData(packetBuf))
}

// Stop implements the Service Stop method.
func (s *server) Stop() error {
	if err := s.proxyConn.SetReadDeadline(conn.ALongTimeAgo); err != nil {
		return err
	}

	// Wait for proxyConn receive goroutines to exit,
	// so there won't be any new sessions added to the table.
	s.mwg.Wait()

	s.mu.Lock()
	for clientAddrPort, entry := range s.table {
		wgConn := entry.state.Swap(s.proxyConn)
		if wgConn == nil {
			continue
		}

		if err := wgConn.SetReadDeadline(conn.ALongTimeAgo); err != nil {
			s.logger.Warn("Failed to SetReadDeadline on wgConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("wgAddress", &s.wgAddr),
				zap.Error(err),
			)
		}
	}
	s.mu.Unlock()

	// Wait for all relay goroutines to exit before closing proxyConn,
	// so in-flight packets can be written out.
	s.wg.Wait()

	return s.proxyConn.Close()
}
