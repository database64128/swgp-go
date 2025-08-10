package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/internal/wireguard"
	"github.com/database64128/swgp-go/packet"
	"github.com/database64128/swgp-go/tslog"
)

// ServerConfig is the configuration for a swgp server service.
type ServerConfig struct {
	// Name specifies the name of the server.
	Name string `json:"name"`

	// ProxyListenNetwork controls the address family of the server socket.
	//
	//  - "udp": Determine from system capabilities and listen address.
	//  - "udp4": AF_INET
	//  - "udp6": AF_INET6
	//
	// If unspecified, "udp" is used.
	ProxyListenNetwork string `json:"proxyListenNetwork,omitzero"`

	// ProxyListenAddress specifies the address to bind the server socket to.
	ProxyListenAddress string `json:"proxyListen"`

	// ProxyMode specifies the proxy protocol.
	//
	//  - "zero-overhead": Lightweight protocol with minimal overhead.
	//  - "paranoid": Full-packet AEAD.
	//
	// See README for more information on the protocols.
	ProxyMode string `json:"proxyMode"`

	// ProxyPSK specifies the pre-shared key for the proxy.
	ProxyPSK []byte `json:"proxyPSK"`

	// ProxyFwmark optionally specifies the server socket's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	ProxyFwmark int `json:"proxyFwmark,omitzero"`

	// ProxyTrafficClass optionally specifies the server socket's traffic class.
	//
	// Available on most platforms except Windows.
	ProxyTrafficClass int `json:"proxyTrafficClass,omitzero"`

	// WgEndpointNetwork controls the address family of the resolved IP address
	// when [WgEndpointAddress] is a domain name.
	//
	//  - "ip": System default
	//  - "ip4": IPv4
	//  - "ip6": IPv6
	//
	// If unspecified, "ip" is used.
	WgEndpointNetwork string `json:"wgEndpointNetwork,omitzero"`

	// WgEndpointAddress specifies the address of the WireGuard endpoint.
	// It can be either an IP address or a domain name.
	// Domain names are resolved on session establishment.
	WgEndpointAddress conn.Addr `json:"wgEndpoint"`

	// WgConnListenAddress optionally specifies the address to bind the WireGuard-facing socket to.
	WgConnListenAddress conn.Addr `json:"wgConnListenAddress,omitzero"`

	// WgFwmark optionally specifies the WireGuard-facing socket's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	WgFwmark int `json:"wgFwmark,omitzero"`

	// WgTrafficClass optionally specifies the WireGuard-facing socket's traffic class.
	//
	// Available on most platforms except Windows.
	WgTrafficClass int `json:"wgTrafficClass,omitzero"`

	// MTU specifies the maximum transmission unit of the server's designated network path.
	MTU int `json:"mtu"`

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
	clientPktinfo      atomic.Pointer[pktinfo]
	clientPktinfoCache pktinfo
	wgConnSendCh       chan<- queuedPacket
}

type server struct {
	name                 string
	proxyListenNetwork   string
	proxyListenAddress   string
	relayBatchSize       int
	mainRecvBatchSize    int
	sendChannelCapacity  int
	packetBufSize        int
	maxProxyPacketSizev4 int
	maxProxyPacketSizev6 int
	wgTunnelMTUv4        int
	wgTunnelMTUv6        int
	disableMmsg          bool
	wgNetwork            string
	wgAddr               conn.Addr
	wgConnListenAddress  conn.Addr
	handler4             packet.Handler
	handler6             packet.Handler
	logger               *tslog.Logger
	proxyConn            *net.UDPConn
	proxyConnConfig      conn.UDPSocketConfig
	wgConnConfig         conn.UDPSocketConfig
	packetBufPool        sync.Pool
	mu                   sync.Mutex
	wg                   sync.WaitGroup
	mwg                  sync.WaitGroup
	table                map[netip.AddrPort]*serverNatEntry
}

// Server creates a swgp server service from the server config.
// Call the Start method on the returned service to start it.
func (sc *ServerConfig) Server(logger *tslog.Logger, socketConfigCache conn.UDPSocketConfigCache) (*server, error) {
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
		return nil, fmt.Errorf("invalid proxyListenNetwork %q: not one of [udp udp4 udp6]", sc.ProxyListenNetwork)
	}

	// Check WgEndpointNetwork.
	switch sc.WgEndpointNetwork {
	case "":
		sc.WgEndpointNetwork = "ip"
	case "ip", "ip4", "ip6":
	default:
		return nil, fmt.Errorf("invalid wgEndpointNetwork %q: not one of [ip ip4 ip6]", sc.WgEndpointNetwork)
	}

	// Check and apply PerfConfig defaults.
	if err := sc.CheckAndApplyDefaults(); err != nil {
		return nil, err
	}

	// maxProxyPacketSize = MTU - IP header length - UDP header length
	maxProxyPacketSizev4 := maxProxyPacketSizev4FromPathMTU(sc.MTU)
	maxProxyPacketSizev6 := maxProxyPacketSizev6FromPathMTU(sc.MTU)

	// Create packet handler for user-specified proxy mode.
	handler4, handlerOverhead, err := newPacketHandler(sc.ProxyMode, sc.ProxyPSK, maxProxyPacketSizev4)
	if err != nil {
		return nil, err
	}
	handler6 := handler4.WithMaxPacketSize(maxProxyPacketSizev6)

	wgTunnelMTUv4 := wgTunnelMTUFromMaxPacketSize(maxProxyPacketSizev4 - handlerOverhead)
	wgTunnelMTUv6 := wgTunnelMTUFromMaxPacketSize(maxProxyPacketSizev6 - handlerOverhead)

	s := server{
		name:                 sc.Name,
		proxyListenNetwork:   sc.ProxyListenNetwork,
		proxyListenAddress:   sc.ProxyListenAddress,
		relayBatchSize:       sc.RelayBatchSize,
		mainRecvBatchSize:    sc.MainRecvBatchSize,
		sendChannelCapacity:  sc.SendChannelCapacity,
		maxProxyPacketSizev4: maxProxyPacketSizev4,
		maxProxyPacketSizev6: maxProxyPacketSizev6,
		wgTunnelMTUv4:        wgTunnelMTUv4,
		wgTunnelMTUv6:        wgTunnelMTUv6,
		disableMmsg:          sc.DisableMmsg,
		wgNetwork:            sc.WgEndpointNetwork,
		wgAddr:               sc.WgEndpointAddress,
		wgConnListenAddress:  sc.WgConnListenAddress,
		handler4:             handler4,
		handler6:             handler6,
		logger:               logger,
		proxyConnConfig: socketConfigCache.Get(conn.UDPSocketOptions{
			SendBufferSize:           conn.DefaultUDPSocketBufferSize,
			ReceiveBufferSize:        conn.DefaultUDPSocketBufferSize,
			Fwmark:                   sc.ProxyFwmark,
			TrafficClass:             sc.ProxyTrafficClass,
			PathMTUDiscovery:         true,
			ProbeUDPGSOSupport:       !sc.DisableUDPGSO,
			UDPGenericReceiveOffload: !sc.DisableUDPGRO,
			ReceivePacketInfo:        true,
		}),
		wgConnConfig: socketConfigCache.Get(conn.UDPSocketOptions{
			SendBufferSize:           conn.DefaultUDPSocketBufferSize,
			ReceiveBufferSize:        conn.DefaultUDPSocketBufferSize,
			Fwmark:                   sc.WgFwmark,
			TrafficClass:             sc.WgTrafficClass,
			PathMTUDiscovery:         true,
			ProbeUDPGSOSupport:       !sc.DisableUDPGSO,
			UDPGenericReceiveOffload: !sc.DisableUDPGRO,
		}),
		table: make(map[netip.AddrPort]*serverNatEntry),
	}
	s.packetBufPool.New = func() any {
		b := make([]byte, s.packetBufSize)
		return unsafe.SliceData(b)
	}
	return &s, nil
}

// SlogAttr implements [Service.SlogAttr].
func (s *server) SlogAttr() slog.Attr {
	return slog.String("server", s.name)
}

// Start implements [Service.Start].
func (s *server) Start(ctx context.Context) (err error) {
	return s.start(ctx)
}

func (s *server) startGeneric(ctx context.Context) error {
	proxyConn, proxyConnInfo, err := s.proxyConnConfig.Listen(ctx, s.proxyListenNetwork, s.proxyListenAddress)
	if err != nil {
		return err
	}
	s.proxyConn = proxyConn
	s.proxyListenAddress = proxyConn.LocalAddr().String()

	if proxyConnInfo.UDPGenericReceiveOffload {
		s.packetBufSize = 65535
	} else {
		s.packetBufSize = s.maxProxyPacketSizev4
	}

	logger := s.logger.WithAttrs(
		slog.String("server", s.name),
		slog.String("listenAddress", s.proxyListenAddress),
	)

	s.mwg.Add(1)

	go func() {
		s.recvFromProxyConnGeneric(ctx, logger, proxyConn, proxyConnInfo)
		s.mwg.Done()
	}()

	logger.Info("Started service",
		tslog.ConnAddrp("wgAddress", &s.wgAddr),
		slog.Int("wgTunnelMTUv4", s.wgTunnelMTUv4),
		slog.Int("wgTunnelMTUv6", s.wgTunnelMTUv6),
		tslog.Uint("maxUDPGSOSegments", proxyConnInfo.MaxUDPGSOSegments),
		slog.Bool("udpGRO", proxyConnInfo.UDPGenericReceiveOffload),
	)
	return nil
}

func (s *server) recvFromProxyConnGeneric(ctx context.Context, logger *tslog.Logger, proxyConn *net.UDPConn, proxyConnInfo conn.SocketInfo) {
	packetBuf := make([]byte, s.packetBufSize)
	cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)
	qp := queuedPacket{
		buf: s.getPacketBuf(),
	}

	var (
		queuedPackets     []queuedPacket
		recvmsgCount      uint64
		packetsReceived   uint64
		swgpBytesReceived uint64
		burstSegmentCount uint32
	)

	for {
		n, cmsgn, flags, clientAddrPort, err := proxyConn.ReadMsgUDPAddrPort(packetBuf, cmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			logger.Warn("Failed to read from proxyConn",
				tslog.AddrPort("clientAddress", clientAddrPort),
				slog.Int("packetLength", n),
				slog.Int("cmsgLength", cmsgn),
				tslog.Err(err),
			)
			continue
		}
		if err = conn.ParseFlagsForError(flags); err != nil {
			logger.Warn("Failed to read from proxyConn",
				tslog.AddrPort("clientAddress", clientAddrPort),
				slog.Int("packetLength", n),
				slog.Int("cmsgLength", cmsgn),
				tslog.Err(err),
			)
			continue
		}

		rscm, err := conn.ParseSocketControlMessage(cmsgBuf[:cmsgn])
		if err != nil {
			logger.Error("Failed to parse socket control message from proxyConn",
				tslog.AddrPort("clientAddress", clientAddrPort),
				slog.Int("cmsgLength", cmsgn),
				tslog.Err(err),
			)
			continue
		}

		recvmsgCount++
		swgpBytesReceived += uint64(n)

		// For future consideration: To preserve zero-length packets,
		// append an empty qp to queuedPackets if n == 0.

		swgpPacketBuf := packetBuf[:n]

		recvSegmentSize := int(rscm.SegmentSize)
		if recvSegmentSize == 0 {
			recvSegmentSize = len(swgpPacketBuf)
		}

		var (
			segmentCount uint32
			handler      packet.Handler
		)

		clientAddr := clientAddrPort.Addr()
		isClientAddr4 := clientAddr.Is4() || clientAddr.Is4In6()
		if isClientAddr4 {
			handler = s.handler4
		} else {
			handler = s.handler6
		}

		for len(swgpPacketBuf) > 0 {
			swgpPacketLength := min(len(swgpPacketBuf), recvSegmentSize)
			swgpPacket := swgpPacketBuf[:swgpPacketLength]
			swgpPacketBuf = swgpPacketBuf[swgpPacketLength:]
			segmentCount++

			dst, err := handler.Decrypt(qp.buf, swgpPacket)
			if err != nil {
				logger.Warn("Failed to decrypt swgpPacket",
					tslog.AddrPort("clientAddress", clientAddrPort),
					slog.Int("packetLength", swgpPacketLength),
					tslog.Err(err),
				)
				continue
			}

			segmentSize := uint32(len(dst) - len(qp.buf))

			switch {
			case qp.segmentSize == 0:
				qp = queuedPacket{
					buf:          dst,
					segmentSize:  segmentSize,
					segmentCount: 1,
				}
			case qp.segmentSize < segmentSize:
				// Move segment to a new wgPacket.
				segment := dst[len(qp.buf):]
				queuedPackets = append(queuedPackets, qp)
				qp = queuedPacket{
					buf:          append(s.getPacketBuf(), segment...),
					segmentSize:  segmentSize,
					segmentCount: 1,
				}
			case qp.segmentSize == segmentSize:
				// Keep segment.
				qp.buf = dst
				qp.segmentCount++
			case qp.segmentSize > segmentSize:
				// Segment is the last short segment.
				qp.buf = dst
				qp.segmentCount++
				queuedPackets = append(queuedPackets, qp)
				qp = queuedPacket{
					buf: s.getPacketBuf(),
				}
			default:
				panic("unreachable")
			}
		}

		packetsReceived += uint64(segmentCount)
		burstSegmentCount = max(burstSegmentCount, segmentCount)

		if len(qp.buf) > 0 {
			queuedPackets = append(queuedPackets, qp)
			qp = queuedPacket{
				buf: s.getPacketBuf(),
			}
		}

		if len(queuedPackets) == 0 {
			continue
		}

		s.mu.Lock()

		natEntry, ok := s.table[clientAddrPort]
		if !ok {
			natEntry = &serverNatEntry{}
		}

		clientPktinfo := pktinfo{
			addr:    rscm.PktinfoAddr,
			ifindex: rscm.PktinfoIfindex,
		}

		var clientPktinfop *pktinfo

		if clientPktinfo != natEntry.clientPktinfoCache {
			clientPktinfoCache := clientPktinfo
			clientPktinfop = &clientPktinfoCache
			natEntry.clientPktinfo.Store(clientPktinfop)
			natEntry.clientPktinfoCache = clientPktinfoCache

			if logger.Enabled(slog.LevelDebug) {
				logger.Debug("Updated client pktinfo",
					tslog.AddrPort("clientAddress", clientAddrPort),
					tslog.Addrp("clientPktinfoAddr", &clientPktinfop.addr),
					tslog.Uint("clientPktinfoIfindex", clientPktinfoCache.ifindex),
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
					logger.Warn("Failed to resolve wg address for new session",
						tslog.AddrPort("clientAddress", clientAddrPort),
						tslog.Err(err),
					)
					return
				}

				// Unmapping wgAddrPort aligns its address family with wgConn,
				// which enables direct equality comparison with the address returned by ReadMsgUDPAddrPort.
				if wgAddrPort.Addr().Is4In6() {
					wgAddrPort = netip.AddrPortFrom(wgAddrPort.Addr().Unmap(), wgAddrPort.Port())
				}

				wgConnListenNetwork := listenUDPNetworkForUnmappedRemoteAddr(wgAddrPort.Addr())
				wgConnListenAddress := s.wgConnListenAddress.String()

				wgConn, wgConnInfo, err := s.wgConnConfig.Listen(ctx, wgConnListenNetwork, wgConnListenAddress)
				if err != nil {
					logger.Warn("Failed to create UDP socket for new session",
						tslog.AddrPort("clientAddress", clientAddrPort),
						slog.String("wgConnListenNetwork", wgConnListenNetwork),
						slog.String("wgConnListenAddress", wgConnListenAddress),
						tslog.Err(err),
					)
					return
				}

				wgConnListenAddrPort := wgConn.LocalAddr().(*net.UDPAddr).AddrPort()

				if err = wgConn.SetReadDeadline(time.Now().Add(wireguard.RejectAfterTime)); err != nil {
					logger.Error("Failed to SetReadDeadline on wgConn",
						tslog.AddrPort("clientAddress", clientAddrPort),
						tslog.AddrPort("wgConnListenAddress", wgConnListenAddrPort),
						tslog.Err(err),
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

				if isClientAddr4 {
					maxProxyPacketSize = s.maxProxyPacketSizev4
					wgTunnelMTU = s.wgTunnelMTUv4
				} else {
					maxProxyPacketSize = s.maxProxyPacketSizev6
					wgTunnelMTU = s.wgTunnelMTUv6
				}

				if wgConnInfo.UDPGenericReceiveOffload {
					maxProxyPacketSize = 65535
				}

				sesLogger := logger.WithAttrs(
					tslog.AddrPort("clientAddress", clientAddrPort),
					tslog.AddrPort("wgConnListenAddress", wgConnListenAddrPort),
					tslog.AddrPort("wgAddress", wgAddrPort),
				)

				sesLogger.Info("Server relay started",
					slog.Int("wgTunnelMTU", wgTunnelMTU),
					tslog.Uint("maxUDPGSOSegments", wgConnInfo.MaxUDPGSOSegments),
					slog.Bool("udpGRO", wgConnInfo.UDPGenericReceiveOffload),
				)

				s.wg.Add(1)

				go func() {
					s.relayProxyToWgGeneric(
						wgAddrPort,
						wgConn,
						wgConnInfo,
						wgConnSendCh,
						sesLogger,
					)
					wgConn.Close()
					s.wg.Done()
				}()

				s.relayWgToProxyGeneric(
					clientAddrPort,
					clientPktinfop,
					&natEntry.clientPktinfo,
					wgAddrPort,
					wgConn,
					proxyConn,
					proxyConnInfo,
					handler,
					maxProxyPacketSize,
					sesLogger,
				)
			}()

			if logger.Enabled(slog.LevelDebug) {
				logger.Debug("New server session",
					tslog.AddrPort("clientAddress", clientAddrPort),
					tslog.ConnAddrp("wgAddress", &s.wgAddr),
				)
			}
		}

		for _, qp := range queuedPackets {
			select {
			case natEntry.wgConnSendCh <- qp:
			default:
				if logger.Enabled(slog.LevelDebug) {
					logger.Debug("wgPacket dropped due to full send channel",
						tslog.AddrPort("clientAddress", clientAddrPort),
						tslog.ConnAddrp("wgAddress", &s.wgAddr),
					)
				}
				s.putPacketBuf(qp.buf)
			}
		}

		s.mu.Unlock()

		queuedPackets = queuedPackets[:0]
	}

	s.putPacketBuf(qp.buf)

	logger.Info("Finished receiving from proxyConn",
		tslog.ConnAddrp("wgAddress", &s.wgAddr),
		tslog.Uint("recvmsgCount", recvmsgCount),
		tslog.Uint("packetsReceived", packetsReceived),
		tslog.Uint("swgpBytesReceived", swgpBytesReceived),
		tslog.Uint("burstSegmentCount", burstSegmentCount),
	)
}

func (s *server) relayProxyToWgGeneric(
	wgAddrPort netip.AddrPort,
	wgConn *net.UDPConn,
	wgConnInfo conn.SocketInfo,
	wgConnSendCh <-chan queuedPacket,
	logger *tslog.Logger,
) {
	cmsgBuf := make([]byte, 0, conn.SocketControlMessageBufferSize)

	var (
		sendmsgCount      uint64
		packetsSent       uint64
		wgBytesSent       uint64
		burstSegmentCount uint32
	)

	for qp := range wgConnSendCh {
		// Update wgConn read deadline when qp contains a WireGuard handshake initiation message.
		if qp.isWireGuardHandshakeInitiationMessage() {
			if err := wgConn.SetReadDeadline(time.Now().Add(wireguard.RejectAfterTime)); err != nil {
				logger.Error("Failed to SetReadDeadline on wgConn", tslog.Err(err))
			}
		}

		b := qp.buf
		segmentsRemaining := qp.segmentCount

		maxUDPGSOSegments := wgConnInfo.MaxUDPGSOSegments
		if maxUDPGSOSegments > 1 {
			// Cap each coalesced message to 65535 bytes to prevent -EMSGSIZE.
			maxUDPGSOSegments = max(1, 65535/qp.segmentSize)
		}

		for segmentsRemaining > 0 {
			sendSegmentCount := min(segmentsRemaining, maxUDPGSOSegments)
			segmentsRemaining -= sendSegmentCount

			sendBufSize := min(len(b), int(qp.segmentSize*sendSegmentCount))
			sendBuf := b[:sendBufSize]
			b = b[sendBufSize:]

			var cmsg []byte
			if sendSegmentCount > 1 {
				scm := conn.SocketControlMessage{
					SegmentSize: qp.segmentSize,
				}
				cmsg = scm.AppendTo(cmsgBuf)
			}

			n, _, err := wgConn.WriteMsgUDPAddrPort(sendBuf, cmsg, wgAddrPort)
			if err != nil {
				logger.Warn("Failed to write wgPacket to wgConn",
					slog.Int("wgPacketLength", sendBufSize),
					tslog.Uint("segmentSize", qp.segmentSize),
					tslog.Err(err),
				)
				continue
			}

			sendmsgCount++
			packetsSent += uint64(sendSegmentCount)
			wgBytesSent += uint64(n)
			burstSegmentCount = max(burstSegmentCount, uint32(sendSegmentCount))
		}

		s.putPacketBuf(qp.buf)
	}

	logger.Info("Finished relay proxyConn -> wgConn",
		tslog.Uint("sendmsgCount", sendmsgCount),
		tslog.Uint("packetsSent", packetsSent),
		tslog.Uint("wgBytesSent", wgBytesSent),
		tslog.Uint("burstSegmentCount", burstSegmentCount),
	)
}

func (s *server) relayWgToProxyGeneric(
	clientAddrPort netip.AddrPort,
	clientPktinfop *pktinfo,
	atomicClientPktinfop *atomic.Pointer[pktinfo],
	wgAddrPort netip.AddrPort,
	wgConn *net.UDPConn,
	proxyConn *net.UDPConn,
	proxyConnInfo conn.SocketInfo,
	handler packet.Handler,
	maxProxyPacketSize int,
	logger *tslog.Logger,
) {
	var (
		clientPktinfo         pktinfo
		queuedPackets         []queuedPacket
		recvmsgCount          uint64
		packetsReceived       uint64
		wgBytesReceived       uint64
		sendmsgCount          uint64
		packetsSent           uint64
		swgpBytesSent         uint64
		burstRecvSegmentCount uint32
		burstSendSegmentCount uint32
	)

	if clientPktinfop != nil {
		clientPktinfo = *clientPktinfop
	}

	recvPacketBuf := make([]byte, maxProxyPacketSize)
	recvCmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)
	sendPacketBuf := make([]byte, 0, maxProxyPacketSize)
	sendCmsgBuf := make([]byte, 0, conn.SocketControlMessageBufferSize)

	for {
		n, cmsgn, flags, packetSourceAddrPort, err := wgConn.ReadMsgUDPAddrPort(recvPacketBuf, recvCmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			logger.Warn("Failed to read from wgConn",
				tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
				slog.Int("packetLength", n),
				slog.Int("cmsgLength", cmsgn),
				tslog.Err(err),
			)
			continue
		}
		if err = conn.ParseFlagsForError(flags); err != nil {
			logger.Warn("Failed to read from wgConn",
				tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
				slog.Int("packetLength", n),
				slog.Int("cmsgLength", cmsgn),
				tslog.Err(err),
			)
			continue
		}

		if packetSourceAddrPort != wgAddrPort {
			logger.Warn("Ignoring packet from non-wg address",
				tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
				slog.Int("packetLength", n),
				tslog.Err(err),
			)
			continue
		}

		rscm, err := conn.ParseSocketControlMessage(recvCmsgBuf[:cmsgn])
		if err != nil {
			logger.Error("Failed to parse socket control message from wgConn",
				tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
				slog.Int("cmsgLength", cmsgn),
				tslog.Err(err),
			)
			continue
		}

		recvmsgCount++
		wgBytesReceived += uint64(n)

		wgPacketBuf := recvPacketBuf[:n]

		recvSegmentSize := int(rscm.SegmentSize)
		if recvSegmentSize == 0 {
			recvSegmentSize = len(wgPacketBuf)
		}

		var (
			recvSegmentCount uint32
			qpLength         uint32
			qpSegmentSize    uint32
			qpSegmentCount   uint32
		)

		for len(wgPacketBuf) > 0 {
			wgPacketLength := min(len(wgPacketBuf), recvSegmentSize)
			wgPacket := wgPacketBuf[:wgPacketLength]
			wgPacketBuf = wgPacketBuf[wgPacketLength:]
			recvSegmentCount++

			dst, err := handler.Encrypt(sendPacketBuf, wgPacket)
			if err != nil {
				logger.Warn("Failed to encrypt wgPacket",
					slog.Int("packetLength", wgPacketLength),
					tslog.Err(err),
				)
				continue
			}

			segmentSize := uint32(len(dst) - len(sendPacketBuf))

			switch {
			case qpLength == 0:
				qpLength = segmentSize
				qpSegmentSize = segmentSize
				qpSegmentCount = 1
			case qpSegmentSize < segmentSize:
				// Save existing qp and start a new one with the current segment.
				queuedPackets = append(queuedPackets, queuedPacket{
					buf:          sendPacketBuf[len(sendPacketBuf)-int(qpLength):],
					segmentSize:  qpSegmentSize,
					segmentCount: qpSegmentCount,
				})
				qpLength = segmentSize
				qpSegmentSize = segmentSize
				qpSegmentCount = 1
			case qpSegmentSize == segmentSize:
				// Keep segment.
				qpLength += segmentSize
				qpSegmentCount++
			case qpSegmentSize > segmentSize:
				// Segment is the last short segment.
				queuedPackets = append(queuedPackets, queuedPacket{
					buf:          dst[len(sendPacketBuf)-int(qpLength):],
					segmentSize:  qpSegmentSize,
					segmentCount: qpSegmentCount + 1,
				})
				qpLength = 0
			default:
				panic("unreachable")
			}

			sendPacketBuf = dst
		}

		packetsReceived += uint64(recvSegmentCount)
		burstRecvSegmentCount = max(burstRecvSegmentCount, recvSegmentCount)

		if qpLength > 0 {
			queuedPackets = append(queuedPackets, queuedPacket{
				buf:          sendPacketBuf[len(sendPacketBuf)-int(qpLength):],
				segmentSize:  qpSegmentSize,
				segmentCount: qpSegmentCount,
			})
		}

		if len(queuedPackets) == 0 {
			continue
		}

		if cpp := atomicClientPktinfop.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp
		}

		for _, qp := range queuedPackets {
			b := qp.buf
			segmentsRemaining := qp.segmentCount

			maxUDPGSOSegments := proxyConnInfo.MaxUDPGSOSegments
			if maxUDPGSOSegments > 1 {
				// Cap each coalesced message to 65535 bytes to prevent -EMSGSIZE.
				maxUDPGSOSegments = max(1, 65535/qp.segmentSize)
			}

			for segmentsRemaining > 0 {
				sendSegmentCount := min(segmentsRemaining, maxUDPGSOSegments)
				segmentsRemaining -= sendSegmentCount

				sendBufSize := min(len(b), int(qp.segmentSize*sendSegmentCount))
				sendBuf := b[:sendBufSize]
				b = b[sendBufSize:]

				sscm := conn.SocketControlMessage{
					PktinfoAddr:    clientPktinfo.addr,
					PktinfoIfindex: clientPktinfo.ifindex,
				}
				if sendSegmentCount > 1 {
					sscm.SegmentSize = qp.segmentSize
				}
				cmsg := sscm.AppendTo(sendCmsgBuf)

				n, _, err := proxyConn.WriteMsgUDPAddrPort(sendBuf, cmsg, clientAddrPort)
				if err != nil {
					logger.Warn("Failed to write swgpPacket to proxyConn",
						slog.Int("swgpPacketLength", len(sendBuf)),
						tslog.Uint("segmentSize", qp.segmentSize),
						tslog.Uint("segmentCount", sendSegmentCount),
						tslog.Err(err),
					)
					continue
				}

				sendmsgCount++
				packetsSent += uint64(sendSegmentCount)
				swgpBytesSent += uint64(n)
				burstSendSegmentCount = max(burstSendSegmentCount, sendSegmentCount)
			}
		}

		queuedPackets = queuedPackets[:0]
		sendPacketBuf = sendPacketBuf[:0]
	}

	logger.Info("Finished relay wgConn -> proxyConn",
		tslog.Uint("recvmsgCount", recvmsgCount),
		tslog.Uint("packetsReceived", packetsReceived),
		tslog.Uint("wgBytesReceived", wgBytesReceived),
		tslog.Uint("sendmsgCount", sendmsgCount),
		tslog.Uint("packetsSent", packetsSent),
		tslog.Uint("swgpBytesSent", swgpBytesSent),
		tslog.Uint("burstRecvSegmentCount", burstRecvSegmentCount),
		tslog.Uint("burstSendSegmentCount", burstSendSegmentCount),
	)
}

// getPacketBuf retrieves a packet buffer from the pool.
func (s *server) getPacketBuf() []byte {
	return unsafe.Slice(s.packetBufPool.Get().(*byte), s.packetBufSize)[:0]
}

// putPacketBuf puts the packet buffer back into the pool.
func (s *server) putPacketBuf(packetBuf []byte) {
	if cap(packetBuf) < s.packetBufSize {
		panic(fmt.Sprintf("putPacketBuf: packetBuf capacity %d, expected at least %d", cap(packetBuf), s.packetBufSize))
	}
	s.packetBufPool.Put(unsafe.SliceData(packetBuf))
}

// Stop implements [Service.Stop].
func (s *server) Stop() error {
	if err := s.proxyConn.SetReadDeadline(conn.ALongTimeAgo); err != nil {
		return fmt.Errorf("failed to SetReadDeadline on proxyConn: %w", err)
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
			s.logger.Error("Failed to SetReadDeadline on wgConn",
				slog.String("server", s.name),
				slog.String("listenAddress", s.proxyListenAddress),
				tslog.AddrPort("clientAddress", clientAddrPort),
				tslog.ConnAddrp("wgAddress", &s.wgAddr),
				tslog.Err(err),
			)
		}
	}
	s.mu.Unlock()

	// Wait for all relay goroutines to exit before closing proxyConn,
	// so in-flight packets can be written out.
	s.wg.Wait()

	if err := s.proxyConn.Close(); err != nil {
		return fmt.Errorf("failed to close proxyConn: %w", err)
	}

	s.logger.Info("Stopped service", slog.String("server", s.name))
	return nil
}
