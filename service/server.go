package service

import (
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
	clientPktinfo      atomic.Pointer[pktinfo]
	clientPktinfoCache pktinfo
	wgConnSendCh       chan<- queuedPacket
}

type serverNatUplinkGeneric struct {
	clientAddrPort netip.AddrPort
	wgAddrPort     netip.AddrPort
	wgConn         *net.UDPConn
	wgConnInfo     conn.SocketInfo
	wgConnSendCh   <-chan queuedPacket
}

type serverNatDownlinkGeneric struct {
	clientAddrPort     netip.AddrPort
	clientPktinfop     *pktinfo
	clientPktinfo      *atomic.Pointer[pktinfo]
	wgAddrPort         netip.AddrPort
	wgConn             *net.UDPConn
	proxyConn          *net.UDPConn
	proxyConnInfo      conn.SocketInfo
	handler            packet.Handler
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
	packetBufSize         int
	maxProxyPacketSizev4  int
	maxProxyPacketSizev6  int
	wgTunnelMTUv4         int
	wgTunnelMTUv6         int
	wgNetwork             string
	wgAddr                conn.Addr
	handler4              packet.Handler
	handler6              packet.Handler
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

	// maxProxyPacketSize = MTU - IP header length - UDP header length
	maxProxyPacketSizev4 := sc.MTU - IPv4HeaderLength - UDPHeaderLength
	maxProxyPacketSizev6 := sc.MTU - IPv6HeaderLength - UDPHeaderLength
	wgTunnelMTUv4 := wgTunnelMTUFromMaxPacketSize(maxProxyPacketSizev4)
	wgTunnelMTUv6 := wgTunnelMTUFromMaxPacketSize(maxProxyPacketSizev6)

	// Create packet handler for user-specified proxy mode.
	handler4, err := newPacketHandler(sc.ProxyMode, sc.ProxyPSK, maxProxyPacketSizev4)
	if err != nil {
		return nil, err
	}
	handler6 := handler4.WithMaxPacketSize(maxProxyPacketSizev6)

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
		handler4:             handler4,
		handler6:             handler6,
		logger:               logger,
		proxyConnListenConfig: listenConfigCache.Get(conn.ListenerSocketOptions{
			SendBufferSize:           conn.DefaultUDPSocketBufferSize,
			ReceiveBufferSize:        conn.DefaultUDPSocketBufferSize,
			Fwmark:                   sc.ProxyFwmark,
			TrafficClass:             sc.ProxyTrafficClass,
			PathMTUDiscovery:         true,
			ProbeUDPGSOSupport:       !sc.DisableUDPGSO,
			UDPGenericReceiveOffload: !sc.DisableUDPGRO,
			ReceivePacketInfo:        true,
		}),
		wgConnListenConfig: listenConfigCache.Get(conn.ListenerSocketOptions{
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
	proxyConn, proxyConnInfo, err := s.proxyConnListenConfig.ListenUDP(ctx, s.proxyListenNetwork, s.proxyListenAddress)
	if err != nil {
		return err
	}
	s.proxyConn = proxyConn

	if proxyConnInfo.UDPGenericReceiveOffload {
		s.packetBufSize = 65535
	} else {
		s.packetBufSize = s.maxProxyPacketSizev4
	}

	s.mwg.Add(1)

	go func() {
		s.recvFromProxyConnGeneric(ctx, proxyConn, proxyConnInfo)
		s.mwg.Done()
	}()

	s.logger.Info("Started service",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListenAddress),
		zap.Stringer("wgAddress", &s.wgAddr),
		zap.Int("wgTunnelMTUv4", s.wgTunnelMTUv4),
		zap.Int("wgTunnelMTUv6", s.wgTunnelMTUv6),
		zap.Uint32("maxUDPGSOSegments", proxyConnInfo.MaxUDPGSOSegments),
		zap.Bool("udpGRO", proxyConnInfo.UDPGenericReceiveOffload),
	)
	return nil
}

func (s *server) recvFromProxyConnGeneric(ctx context.Context, proxyConn *net.UDPConn, proxyConnInfo conn.SocketInfo) {
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
			s.logger.Warn("Failed to read from proxyConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Int("cmsgLength", cmsgn),
				zap.Error(err),
			)
			continue
		}
		if err = conn.ParseFlagsForError(flags); err != nil {
			s.logger.Warn("Failed to read from proxyConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Int("cmsgLength", cmsgn),
				zap.Error(err),
			)
			continue
		}

		rscm, err := conn.ParseSocketControlMessage(cmsgBuf[:cmsgn])
		if err != nil {
			s.logger.Warn("Failed to parse socket control message from proxyConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("cmsgLength", cmsgn),
				zap.Error(err),
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
				s.logger.Warn("Failed to decrypt swgpPacket",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Int("packetLength", swgpPacketLength),
					zap.Error(err),
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

			if ce := s.logger.Check(zap.DebugLevel, "Updated client pktinfo"); ce != nil {
				ce.Write(
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("clientPktinfoAddr", &clientPktinfop.addr),
					zap.Uint32("clientPktinfoIfindex", clientPktinfoCache.ifindex),
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

				wgConn, wgConnInfo, err := s.wgConnListenConfig.ListenUDP(ctx, s.wgConnListenNetwork, s.wgConnListenAddress)
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

				s.logger.Info("Server relay started",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("wgAddress", wgAddrPort),
					zap.Int("wgTunnelMTU", wgTunnelMTU),
					zap.Uint32("maxUDPGSOSegments", wgConnInfo.MaxUDPGSOSegments),
					zap.Bool("udpGRO", wgConnInfo.UDPGenericReceiveOffload),
				)

				s.wg.Add(1)

				go func() {
					s.relayProxyToWgGeneric(serverNatUplinkGeneric{
						clientAddrPort: clientAddrPort,
						wgAddrPort:     wgAddrPort,
						wgConn:         wgConn,
						wgConnInfo:     wgConnInfo,
						wgConnSendCh:   wgConnSendCh,
					})
					wgConn.Close()
					s.wg.Done()
				}()

				s.relayWgToProxyGeneric(serverNatDownlinkGeneric{
					clientAddrPort:     clientAddrPort,
					clientPktinfop:     clientPktinfop,
					clientPktinfo:      &natEntry.clientPktinfo,
					wgAddrPort:         wgAddrPort,
					wgConn:             wgConn,
					proxyConn:          proxyConn,
					proxyConnInfo:      proxyConnInfo,
					handler:            handler,
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

		for _, qp := range queuedPackets {
			select {
			case natEntry.wgConnSendCh <- qp:
			default:
				if ce := s.logger.Check(zap.DebugLevel, "wgPacket dropped due to full send channel"); ce != nil {
					ce.Write(
						zap.String("server", s.name),
						zap.String("listenAddress", s.proxyListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("wgAddress", &s.wgAddr),
					)
				}
				s.putPacketBuf(qp.buf)
			}
		}

		s.mu.Unlock()

		queuedPackets = queuedPackets[:0]
	}

	s.putPacketBuf(qp.buf)

	s.logger.Info("Finished receiving from proxyConn",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListenAddress),
		zap.Stringer("wgAddress", &s.wgAddr),
		zap.Uint64("recvmsgCount", recvmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("swgpBytesReceived", swgpBytesReceived),
		zap.Uint32("burstSegmentCount", burstSegmentCount),
	)
}

func (s *server) relayProxyToWgGeneric(uplink serverNatUplinkGeneric) {
	cmsgBuf := make([]byte, 0, conn.SocketControlMessageBufferSize)

	var (
		sendmsgCount      uint64
		packetsSent       uint64
		wgBytesSent       uint64
		burstSegmentCount uint32
	)

	for qp := range uplink.wgConnSendCh {
		// Update wgConn read deadline when qp contains a WireGuard handshake initiation message.
		if qp.isWireGuardHandshakeInitiationMessage() { // TODO: merge into the loop below as an optimization
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

		b := qp.buf
		segmentsRemaining := qp.segmentCount

		for segmentsRemaining > 0 {
			sendSegmentCount := min(segmentsRemaining, uplink.wgConnInfo.MaxUDPGSOSegments)
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

			n, _, err := uplink.wgConn.WriteMsgUDPAddrPort(sendBuf, cmsg, uplink.wgAddrPort)
			if err != nil {
				s.logger.Warn("Failed to write wgPacket to wgConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Stringer("wgAddress", uplink.wgAddrPort),
					zap.Int("wgPacketLength", sendBufSize),
					zap.Uint32("segmentSize", qp.segmentSize),
					zap.Error(err),
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

	s.logger.Info("Finished relay proxyConn -> wgConn",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListenAddress),
		zap.Stringer("clientAddress", uplink.clientAddrPort),
		zap.Stringer("wgAddress", uplink.wgAddrPort),
		zap.Uint64("sendmsgCount", sendmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
		zap.Uint32("burstSegmentCount", burstSegmentCount),
	)
}

func (s *server) relayWgToProxyGeneric(downlink serverNatDownlinkGeneric) {
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

	if downlink.clientPktinfop != nil {
		clientPktinfo = *downlink.clientPktinfop
	}

	recvPacketBuf := make([]byte, downlink.maxProxyPacketSize)
	recvCmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)
	sendPacketBuf := make([]byte, 0, downlink.maxProxyPacketSize)
	sendCmsgBuf := make([]byte, 0, conn.SocketControlMessageBufferSize)

	for {
		n, cmsgn, flags, packetSourceAddrPort, err := downlink.wgConn.ReadMsgUDPAddrPort(recvPacketBuf, recvCmsgBuf)
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
				zap.Int("cmsgLength", cmsgn),
				zap.Error(err),
			)
			continue
		}
		if err = conn.ParseFlagsForError(flags); err != nil {
			s.logger.Warn("Failed to read from wgConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("wgAddress", downlink.wgAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Int("packetLength", n),
				zap.Int("cmsgLength", cmsgn),
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

		rscm, err := conn.ParseSocketControlMessage(recvCmsgBuf[:cmsgn])
		if err != nil {
			s.logger.Warn("Failed to parse socket control message from wgConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("wgAddress", downlink.wgAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Int("cmsgLength", cmsgn),
				zap.Error(err),
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

			dst, err := downlink.handler.Encrypt(sendPacketBuf, wgPacket)
			if err != nil {
				s.logger.Warn("Failed to encrypt wgPacket",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("wgAddress", downlink.wgAddrPort),
					zap.Int("packetLength", wgPacketLength),
					zap.Error(err),
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

		if cpp := downlink.clientPktinfo.Load(); cpp != downlink.clientPktinfop {
			clientPktinfo = *cpp
			downlink.clientPktinfop = cpp
		}

		for _, qp := range queuedPackets {
			b := qp.buf
			segmentsRemaining := qp.segmentCount

			for segmentsRemaining > 0 {
				sendSegmentCount := min(segmentsRemaining, downlink.proxyConnInfo.MaxUDPGSOSegments)
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

				n, _, err := downlink.proxyConn.WriteMsgUDPAddrPort(sendBuf, cmsg, downlink.clientAddrPort)
				if err != nil {
					s.logger.Warn("Failed to write swgpPacket to proxyConn",
						zap.String("server", s.name),
						zap.String("listenAddress", s.proxyListenAddress),
						zap.Stringer("clientAddress", downlink.clientAddrPort),
						zap.Stringer("wgAddress", downlink.wgAddrPort),
						zap.Int("swgpPacketLength", len(sendBuf)),
						zap.Uint32("segmentSize", qp.segmentSize),
						zap.Uint32("segmentCount", sendSegmentCount),
						zap.Error(err),
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

	s.logger.Info("Finished relay wgConn -> proxyConn",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListenAddress),
		zap.Stringer("clientAddress", downlink.clientAddrPort),
		zap.Stringer("wgAddress", downlink.wgAddrPort),
		zap.Uint64("recvmsgCount", recvmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("wgBytesReceived", wgBytesReceived),
		zap.Uint64("sendmsgCount", sendmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("swgpBytesSent", swgpBytesSent),
		zap.Uint32("burstRecvSegmentCount", burstRecvSegmentCount),
		zap.Uint32("burstSendSegmentCount", burstSendSegmentCount),
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
