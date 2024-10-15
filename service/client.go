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

// ClientConfig stores configurations for a swgp client service.
// It may be marshaled as or unmarshaled from JSON.
type ClientConfig struct {
	Name                   string    `json:"name"`
	WgListenNetwork        string    `json:"wgListenNetwork"`
	WgListenAddress        string    `json:"wgListen"`
	WgFwmark               int       `json:"wgFwmark"`
	WgTrafficClass         int       `json:"wgTrafficClass"`
	ProxyEndpointNetwork   string    `json:"proxyEndpointNetwork"`
	ProxyEndpointAddress   conn.Addr `json:"proxyEndpoint"`
	ProxyConnListenNetwork string    `json:"proxyConnListenNetwork"`
	ProxyConnListenAddress string    `json:"proxyConnListenAddress"`
	ProxyMode              string    `json:"proxyMode"`
	ProxyPSK               []byte    `json:"proxyPSK"`
	ProxyFwmark            int       `json:"proxyFwmark"`
	ProxyTrafficClass      int       `json:"proxyTrafficClass"`
	MTU                    int       `json:"mtu"`
	PerfConfig
}

type clientNatEntry struct {
	// state synchronizes session initialization and shutdown.
	//
	//  - Swap the proxyConn in to signal initialization completion.
	//  - Swap the wgConn in to signal shutdown.
	//
	// Callers must check the swapped-out value to determine the next action.
	//
	//  - During initialization, if the swapped-out value is non-nil,
	//    initialization must not proceed.
	//  - During shutdown, if the swapped-out value is nil, preceed to the next entry.
	state              atomic.Pointer[net.UDPConn]
	clientPktinfo      atomic.Pointer[pktinfo]
	clientPktinfoCache pktinfo
	proxyConnSendCh    chan<- queuedPacket
}

type clientNatUplinkGeneric struct {
	clientAddrPort  netip.AddrPort
	proxyAddrPort   netip.AddrPort
	proxyConn       *net.UDPConn
	proxyConnInfo   conn.SocketInfo
	proxyConnSendCh <-chan queuedPacket
	handler         packet.Handler
}

type clientNatDownlinkGeneric struct {
	clientAddrPort     netip.AddrPort
	clientPktinfop     *pktinfo
	clientPktinfo      *atomic.Pointer[pktinfo]
	proxyAddrPort      netip.AddrPort
	proxyConn          *net.UDPConn
	wgConn             *net.UDPConn
	wgConnInfo         conn.SocketInfo
	handler            packet.Handler
	maxProxyPacketSize int
}

type client struct {
	name                   string
	wgListenNetwork        string
	wgListenAddress        string
	proxyConnListenNetwork string
	proxyConnListenAddress string
	relayBatchSize         int
	mainRecvBatchSize      int
	sendChannelCapacity    int
	packetBufSize          int
	maxProxyPacketSize     int
	maxProxyPacketSizev6   int
	wgTunnelMTU            int
	wgTunnelMTUv6          int
	proxyNetwork           string
	proxyAddr              conn.Addr
	handler                packet.Handler
	handler6               packet.Handler
	logger                 *zap.Logger
	wgConn                 *net.UDPConn
	wgConnListenConfig     conn.ListenConfig
	proxyConnListenConfig  conn.ListenConfig
	packetBufPool          sync.Pool
	mu                     sync.Mutex
	wg                     sync.WaitGroup
	mwg                    sync.WaitGroup
	table                  map[netip.AddrPort]*clientNatEntry
	startFunc              func(context.Context) error
}

// Client creates a swgp client service from the client config.
// Call the Start method on the returned service to start it.
func (cc *ClientConfig) Client(logger *zap.Logger, listenConfigCache conn.ListenConfigCache) (*client, error) {
	// Require MTU to be at least 1280.
	if cc.MTU < minimumMTU {
		return nil, ErrMTUTooSmall
	}

	// Check WgListenNetwork.
	switch cc.WgListenNetwork {
	case "":
		cc.WgListenNetwork = "udp"
	case "udp", "udp4", "udp6":
	default:
		return nil, fmt.Errorf("invalid wgListenNetwork: %s", cc.WgListenNetwork)
	}

	// Check ProxyEndpointNetwork.
	switch cc.ProxyEndpointNetwork {
	case "":
		cc.ProxyEndpointNetwork = "ip"
	case "ip", "ip4", "ip6":
	default:
		return nil, fmt.Errorf("invalid proxyEndpointNetwork: %s", cc.ProxyEndpointNetwork)
	}

	// Check ProxyConnListenNetwork.
	switch cc.ProxyConnListenNetwork {
	case "":
		cc.ProxyConnListenNetwork = "udp"
	case "udp", "udp4", "udp6":
	default:
		return nil, fmt.Errorf("invalid proxyConnListenNetwork: %s", cc.ProxyConnListenNetwork)
	}

	// Check and apply PerfConfig defaults.
	if err := cc.CheckAndApplyDefaults(); err != nil {
		return nil, err
	}

	// maxProxyPacketSize = MTU - IP header length - UDP header length
	maxProxyPacketSize := cc.MTU - IPv4HeaderLength - UDPHeaderLength
	maxProxyPacketSizev6 := cc.MTU - IPv6HeaderLength - UDPHeaderLength
	wgTunnelMTU := wgTunnelMTUFromMaxPacketSize(maxProxyPacketSize)
	wgTunnelMTUv6 := wgTunnelMTUFromMaxPacketSize(maxProxyPacketSizev6)

	// Create packet handler for user-specified proxy mode.
	handler, err := newPacketHandler(cc.ProxyMode, cc.ProxyPSK, maxProxyPacketSize)
	if err != nil {
		return nil, err
	}
	handler6 := handler.WithMaxPacketSize(maxProxyPacketSizev6)

	// Use IPv6 values if the proxy endpoint is an IPv6 address.
	if cc.ProxyEndpointAddress.IsIP() {
		if ip := cc.ProxyEndpointAddress.IP(); !ip.Is4() && !ip.Is4In6() {
			maxProxyPacketSize = maxProxyPacketSizev6
			wgTunnelMTU = wgTunnelMTUv6
			handler = handler6
		}
	}

	c := client{
		name:                   cc.Name,
		wgListenNetwork:        cc.WgListenNetwork,
		wgListenAddress:        cc.WgListenAddress,
		proxyConnListenNetwork: cc.ProxyConnListenNetwork,
		proxyConnListenAddress: cc.ProxyConnListenAddress,
		relayBatchSize:         cc.RelayBatchSize,
		mainRecvBatchSize:      cc.MainRecvBatchSize,
		sendChannelCapacity:    cc.SendChannelCapacity,
		maxProxyPacketSize:     maxProxyPacketSize,
		maxProxyPacketSizev6:   maxProxyPacketSizev6,
		wgTunnelMTU:            wgTunnelMTU,
		wgTunnelMTUv6:          wgTunnelMTUv6,
		proxyNetwork:           cc.ProxyEndpointNetwork,
		proxyAddr:              cc.ProxyEndpointAddress,
		handler:                handler,
		handler6:               handler6,
		logger:                 logger,
		wgConnListenConfig: listenConfigCache.Get(conn.ListenerSocketOptions{
			SendBufferSize:           conn.DefaultUDPSocketBufferSize,
			ReceiveBufferSize:        conn.DefaultUDPSocketBufferSize,
			Fwmark:                   cc.WgFwmark,
			TrafficClass:             cc.WgTrafficClass,
			PathMTUDiscovery:         true,
			ProbeUDPGSOSupport:       !cc.DisableUDPGSO,
			UDPGenericReceiveOffload: !cc.DisableUDPGRO,
			ReceivePacketInfo:        true,
		}),
		proxyConnListenConfig: listenConfigCache.Get(conn.ListenerSocketOptions{
			SendBufferSize:           conn.DefaultUDPSocketBufferSize,
			ReceiveBufferSize:        conn.DefaultUDPSocketBufferSize,
			Fwmark:                   cc.ProxyFwmark,
			TrafficClass:             cc.ProxyTrafficClass,
			PathMTUDiscovery:         true,
			ProbeUDPGSOSupport:       !cc.DisableUDPGSO,
			UDPGenericReceiveOffload: !cc.DisableUDPGRO,
		}),
		table: make(map[netip.AddrPort]*clientNatEntry),
	}
	c.packetBufPool.New = func() any {
		b := make([]byte, c.packetBufSize)
		return unsafe.SliceData(b)
	}
	c.setStartFunc(cc.BatchMode)
	return &c, nil
}

// String implements the Service String method.
func (c *client) String() string {
	return c.name + " swgp client service"
}

// Start implements the Service Start method.
func (c *client) Start(ctx context.Context) (err error) {
	return c.startFunc(ctx)
}

func (c *client) startGeneric(ctx context.Context) error {
	wgConn, wgConnInfo, err := c.wgConnListenConfig.ListenUDP(ctx, c.wgListenNetwork, c.wgListenAddress)
	if err != nil {
		return err
	}
	c.wgConn = wgConn

	if wgConnInfo.UDPGenericReceiveOffload {
		c.packetBufSize = 65535
	} else {
		c.packetBufSize = c.maxProxyPacketSize
	}

	c.mwg.Add(1)

	go func() {
		c.recvFromWgConnGeneric(ctx, wgConn, wgConnInfo)
		c.mwg.Done()
	}()

	if ce := c.logger.Check(zap.InfoLevel, "Started service"); ce != nil {
		fields := make([]zap.Field, 0, 7)

		fields = append(fields,
			zap.String("client", c.name),
			zap.String("listenAddress", c.wgListenAddress),
			zap.Stringer("proxyAddress", &c.proxyAddr),
		)

		if c.proxyAddr.IsIP() {
			fields = append(fields, zap.Int("wgTunnelMTU", c.wgTunnelMTU))
		} else {
			fields = append(fields,
				zap.Int("wgTunnelMTUv4", c.wgTunnelMTU),
				zap.Int("wgTunnelMTUv6", c.wgTunnelMTUv6),
			)
		}

		fields = append(fields,
			zap.Uint32("maxUDPGSOSegments", wgConnInfo.MaxUDPGSOSegments),
			zap.Bool("udpGRO", wgConnInfo.UDPGenericReceiveOffload),
		)

		ce.Write(fields...)
	}
	return nil
}

func (c *client) recvFromWgConnGeneric(ctx context.Context, wgConn *net.UDPConn, wgConnInfo conn.SocketInfo) {
	packetBuf := c.getPacketBuf()
	cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)

	var (
		recvmsgCount      uint64
		packetsReceived   uint64
		wgBytesReceived   uint64
		burstSegmentCount uint32
	)

	for {
		n, cmsgn, flags, clientAddrPort, err := wgConn.ReadMsgUDPAddrPort(packetBuf, cmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			c.logger.Warn("Failed to read from wgConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Int("cmsgLength", cmsgn),
				zap.Error(err),
			)
			continue
		}
		if err = conn.ParseFlagsForError(flags); err != nil {
			c.logger.Warn("Failed to read from wgConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Int("cmsgLength", cmsgn),
				zap.Error(err),
			)
			continue
		}

		rscm, err := conn.ParseSocketControlMessage(cmsgBuf[:cmsgn])
		if err != nil {
			c.logger.Warn("Failed to parse socket control message from wgConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("cmsgLength", cmsgn),
				zap.Error(err),
			)
			continue
		}

		qp := queuedPacket{
			buf:          packetBuf[:n],
			segmentSize:  uint32(n),
			segmentCount: 1,
		}

		if rscm.SegmentSize > 0 {
			qp.segmentSize = rscm.SegmentSize
			qp.segmentCount = (uint32(n) + rscm.SegmentSize - 1) / rscm.SegmentSize
		}

		recvmsgCount++
		packetsReceived += uint64(qp.segmentCount)
		wgBytesReceived += uint64(n)
		burstSegmentCount = max(burstSegmentCount, qp.segmentCount)

		c.mu.Lock()

		natEntry, ok := c.table[clientAddrPort]
		if !ok {
			natEntry = &clientNatEntry{}
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

			if ce := c.logger.Check(zap.DebugLevel, "Updated client pktinfo"); ce != nil {
				ce.Write(
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("clientPktinfoAddr", &clientPktinfop.addr),
					zap.Uint32("clientPktinfoIfindex", clientPktinfoCache.ifindex),
				)
			}
		}

		if !ok {
			proxyConnSendCh := make(chan queuedPacket, c.sendChannelCapacity)
			natEntry.proxyConnSendCh = proxyConnSendCh
			c.table[clientAddrPort] = natEntry
			c.wg.Add(1)

			go func() {
				var sendChClean bool

				defer func() {
					c.mu.Lock()
					close(proxyConnSendCh)
					delete(c.table, clientAddrPort)
					c.mu.Unlock()

					if !sendChClean {
						for queuedPacket := range proxyConnSendCh {
							c.putPacketBuf(queuedPacket.buf)
						}
					}

					c.wg.Done()
				}()

				proxyAddrPort, err := c.proxyAddr.ResolveIPPort(ctx, c.proxyNetwork)
				if err != nil {
					c.logger.Warn("Failed to resolve proxy address for new session",
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Error(err),
					)
					return
				}

				proxyConn, proxyConnInfo, err := c.proxyConnListenConfig.ListenUDP(ctx, c.proxyConnListenNetwork, c.proxyConnListenAddress)
				if err != nil {
					c.logger.Warn("Failed to create UDP socket for new session",
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Error(err),
					)
					return
				}

				err = proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
				if err != nil {
					c.logger.Warn("Failed to SetReadDeadline on proxyConn",
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Error(err),
					)
					proxyConn.Close()
					return
				}

				oldState := natEntry.state.Swap(proxyConn)
				if oldState != nil {
					proxyConn.Close()
					return
				}

				// No more early returns!
				sendChClean = true

				maxProxyPacketSize := c.maxProxyPacketSize
				wgTunnelMTU := c.wgTunnelMTU
				handler := c.handler

				if c.proxyAddr.IsDomain() {
					if addr := proxyAddrPort.Addr(); !addr.Is4() && !addr.Is4In6() {
						maxProxyPacketSize = c.maxProxyPacketSizev6
						wgTunnelMTU = c.wgTunnelMTUv6
						handler = c.handler6
					}
				}

				if proxyConnInfo.UDPGenericReceiveOffload {
					maxProxyPacketSize = 65535
				}

				c.logger.Info("Client relay started",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("proxyAddress", proxyAddrPort),
					zap.Int("wgTunnelMTU", wgTunnelMTU),
					zap.Uint32("maxUDPGSOSegments", proxyConnInfo.MaxUDPGSOSegments),
					zap.Bool("udpGRO", proxyConnInfo.UDPGenericReceiveOffload),
				)

				c.wg.Add(1)

				go func() {
					c.relayWgToProxyGeneric(clientNatUplinkGeneric{
						clientAddrPort:  clientAddrPort,
						proxyAddrPort:   proxyAddrPort,
						proxyConn:       proxyConn,
						proxyConnInfo:   proxyConnInfo,
						proxyConnSendCh: proxyConnSendCh,
						handler:         handler,
					})
					proxyConn.Close()
					c.wg.Done()
				}()

				c.relayProxyToWgGeneric(clientNatDownlinkGeneric{
					clientAddrPort:     clientAddrPort,
					clientPktinfop:     clientPktinfop,
					clientPktinfo:      &natEntry.clientPktinfo,
					proxyAddrPort:      proxyAddrPort,
					proxyConn:          proxyConn,
					wgConn:             wgConn,
					wgConnInfo:         wgConnInfo,
					handler:            handler,
					maxProxyPacketSize: maxProxyPacketSize,
				})
			}()

			if ce := c.logger.Check(zap.DebugLevel, "New client session"); ce != nil {
				ce.Write(
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("proxyAddress", &c.proxyAddr),
				)
			}
		}

		select {
		case natEntry.proxyConnSendCh <- qp:
			packetBuf = c.getPacketBuf()
		default:
			if ce := c.logger.Check(zap.DebugLevel, "swgpPacket dropped due to full send channel"); ce != nil {
				ce.Write(
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("proxyAddress", &c.proxyAddr),
				)
			}
		}

		c.mu.Unlock()
	}

	c.putPacketBuf(packetBuf)

	c.logger.Info("Finished receiving from wgConn",
		zap.String("client", c.name),
		zap.String("listenAddress", c.wgListenAddress),
		zap.Stringer("proxyAddress", &c.proxyAddr),
		zap.Uint64("recvmsgCount", recvmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("wgBytesReceived", wgBytesReceived),
		zap.Uint32("burstSegmentCount", burstSegmentCount),
	)
}

func (c *client) relayWgToProxyGeneric(uplink clientNatUplinkGeneric) {
	packetBuf := make([]byte, 0, c.packetBufSize)
	cmsgBuf := make([]byte, 0, conn.SocketControlMessageBufferSize)

	var (
		sendQueuedPackets []queuedPacket
		sendmsgCount      uint64
		packetsSent       uint64
		swgpBytesSent     uint64
		burstSegmentCount uint32
	)

	for rqp := range uplink.proxyConnSendCh {
		// Update proxyConn read deadline when rqp contains a WireGuard handshake initiation message.
		if rqp.isWireGuardHandshakeInitiationMessage() { // TODO: merge into the loop below as an optimization
			if err := uplink.proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
				c.logger.Warn("Failed to SetReadDeadline on proxyConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Stringer("proxyAddress", uplink.proxyAddrPort),
					zap.Error(err),
				)
			}
		}

		wgPacketBuf := rqp.buf
		sqp := queuedPacket{
			buf: packetBuf,
		}

		for len(wgPacketBuf) > 0 {
			wgPacketLength := min(len(wgPacketBuf), int(rqp.segmentSize))
			wgPacket := wgPacketBuf[:wgPacketLength]
			wgPacketBuf = wgPacketBuf[wgPacketLength:]

			dst, err := uplink.handler.Encrypt(sqp.buf, wgPacket)
			if err != nil {
				c.logger.Warn("Failed to encrypt wgPacket",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Int("packetLength", wgPacketLength),
					zap.Error(err),
				)
				continue
			}

			segmentSize := uint32(len(dst) - len(sqp.buf))

			switch {
			case sqp.segmentSize == 0:
				sqp = queuedPacket{
					buf:          dst,
					segmentSize:  segmentSize,
					segmentCount: 1,
				}
			case sqp.segmentSize < segmentSize:
				// Save existing sqp and start a new one with the current segment.
				segment := dst[len(sqp.buf):]
				sendQueuedPackets = append(sendQueuedPackets, sqp)
				sqp = queuedPacket{
					buf:          segment,
					segmentSize:  segmentSize,
					segmentCount: 1,
				}
			case sqp.segmentSize == segmentSize:
				// Keep segment.
				sqp.buf = dst
				sqp.segmentCount++
			case sqp.segmentSize > segmentSize:
				// Segment is the last short segment.
				sqp.buf = dst
				sqp.segmentCount++
				sendQueuedPackets = append(sendQueuedPackets, sqp)
				sqp = queuedPacket{
					buf: dst[len(dst):],
				}
			default:
				panic("unreachable")
			}
		}

		if len(sqp.buf) > 0 {
			sendQueuedPackets = append(sendQueuedPackets, sqp)
		}

		for _, sqp := range sendQueuedPackets {
			b := sqp.buf
			segmentsRemaining := sqp.segmentCount

			for segmentsRemaining > 0 {
				sendSegmentCount := min(segmentsRemaining, uplink.proxyConnInfo.MaxUDPGSOSegments)
				segmentsRemaining -= sendSegmentCount

				sendBufSize := min(len(b), int(sqp.segmentSize*sendSegmentCount))
				sendBuf := b[:sendBufSize]
				b = b[sendBufSize:]

				var cmsg []byte
				if sendSegmentCount > 1 {
					scm := conn.SocketControlMessage{
						SegmentSize: sqp.segmentSize,
					}
					cmsg = scm.AppendTo(cmsgBuf)
				}

				n, _, err := uplink.proxyConn.WriteMsgUDPAddrPort(sendBuf, cmsg, uplink.proxyAddrPort)
				if err != nil {
					c.logger.Warn("Failed to write swgpPacket to proxyConn",
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListenAddress),
						zap.Stringer("clientAddress", uplink.clientAddrPort),
						zap.Stringer("proxyAddress", uplink.proxyAddrPort),
						zap.Int("swgpPacketLength", sendBufSize),
						zap.Uint32("segmentSize", sqp.segmentSize),
						zap.Error(err),
					)
					continue
				}

				sendmsgCount++
				packetsSent += uint64(sendSegmentCount)
				swgpBytesSent += uint64(n)
				burstSegmentCount = max(burstSegmentCount, uint32(sendSegmentCount))
			}
		}

		sendQueuedPackets = sendQueuedPackets[:0]

		c.putPacketBuf(rqp.buf)
	}

	c.logger.Info("Finished relay wgConn -> proxyConn",
		zap.String("client", c.name),
		zap.String("listenAddress", c.wgListenAddress),
		zap.Stringer("clientAddress", uplink.clientAddrPort),
		zap.Stringer("proxyAddress", uplink.proxyAddrPort),
		zap.Uint64("sendmsgCount", sendmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("swgpBytesSent", swgpBytesSent),
		zap.Uint32("burstSegmentCount", burstSegmentCount),
	)
}

func (c *client) relayProxyToWgGeneric(downlink clientNatDownlinkGeneric) {
	var (
		clientPktinfo         pktinfo
		queuedPackets         []queuedPacket
		recvmsgCount          uint64
		packetsReceived       uint64
		swgpBytesReceived     uint64
		sendmsgCount          uint64
		packetsSent           uint64
		wgBytesSent           uint64
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
		n, cmsgn, flags, packetSourceAddrPort, err := downlink.proxyConn.ReadMsgUDPAddrPort(recvPacketBuf, recvCmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			c.logger.Warn("Failed to read from proxyConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("proxyAddress", downlink.proxyAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Int("packetLength", n),
				zap.Int("cmsgLength", cmsgn),
				zap.Error(err),
			)
			continue
		}
		if err = conn.ParseFlagsForError(flags); err != nil {
			c.logger.Warn("Failed to read from proxyConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("proxyAddress", downlink.proxyAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Int("packetLength", n),
				zap.Int("cmsgLength", cmsgn),
				zap.Error(err),
			)
			continue
		}

		if !conn.AddrPortMappedEqual(packetSourceAddrPort, downlink.proxyAddrPort) {
			c.logger.Warn("Ignoring packet from non-proxy address",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("proxyAddress", downlink.proxyAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}

		rscm, err := conn.ParseSocketControlMessage(recvCmsgBuf[:cmsgn])
		if err != nil {
			c.logger.Warn("Failed to parse socket control message from proxyConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("proxyAddress", downlink.proxyAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Int("cmsgLength", cmsgn),
				zap.Error(err),
			)
			continue
		}

		recvmsgCount++
		swgpBytesReceived += uint64(n)

		swgpPacketBuf := recvPacketBuf[:n]
		qp := queuedPacket{
			buf: sendPacketBuf,
		}

		recvSegmentSize := int(rscm.SegmentSize)
		if recvSegmentSize == 0 {
			recvSegmentSize = len(swgpPacketBuf)
		}

		var recvSegmentCount uint32

		for len(swgpPacketBuf) > 0 {
			swgpPacketLength := min(len(swgpPacketBuf), recvSegmentSize)
			swgpPacket := swgpPacketBuf[:swgpPacketLength]
			swgpPacketBuf = swgpPacketBuf[swgpPacketLength:]
			recvSegmentCount++

			dst, err := downlink.handler.Decrypt(qp.buf, swgpPacket)
			if err != nil {
				c.logger.Warn("Failed to decrypt swgpPacket",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("proxyAddress", downlink.proxyAddrPort),
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
				// Save existing qp and start a new one with the current segment.
				segment := dst[len(qp.buf):]
				queuedPackets = append(queuedPackets, qp)
				qp = queuedPacket{
					buf:          segment,
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
					buf: dst[len(dst):],
				}
			default:
				panic("unreachable")
			}
		}

		packetsReceived += uint64(recvSegmentCount)
		burstRecvSegmentCount = max(burstRecvSegmentCount, recvSegmentCount)

		if len(qp.buf) > 0 {
			queuedPackets = append(queuedPackets, qp)
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
				sendSegmentCount := min(segmentsRemaining, downlink.wgConnInfo.MaxUDPGSOSegments)
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

				n, _, err := downlink.wgConn.WriteMsgUDPAddrPort(sendBuf, cmsg, downlink.clientAddrPort)
				if err != nil {
					c.logger.Warn("Failed to write wgPacket to wgConn",
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListenAddress),
						zap.Stringer("clientAddress", downlink.clientAddrPort),
						zap.Stringer("proxyAddress", downlink.proxyAddrPort),
						zap.Int("wgPacketLength", sendBufSize),
						zap.Uint32("segmentSize", qp.segmentSize),
						zap.Uint32("segmentCount", sendSegmentCount),
						zap.Error(err),
					)
					continue
				}

				sendmsgCount++
				packetsSent += uint64(sendSegmentCount)
				wgBytesSent += uint64(n)
				burstSendSegmentCount = max(burstSendSegmentCount, sendSegmentCount)
			}
		}

		queuedPackets = queuedPackets[:0]
	}

	c.logger.Info("Finished relay proxyConn -> wgConn",
		zap.String("client", c.name),
		zap.String("listenAddress", c.wgListenAddress),
		zap.Stringer("clientAddress", downlink.clientAddrPort),
		zap.Stringer("proxyAddress", downlink.proxyAddrPort),
		zap.Uint64("recvmsgCount", recvmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("swgpBytesReceived", swgpBytesReceived),
		zap.Uint64("sendmsgCount", sendmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
		zap.Uint32("burstRecvSegmentCount", burstRecvSegmentCount),
		zap.Uint32("burstSendSegmentCount", burstSendSegmentCount),
	)
}

// getPacketBuf retrieves a packet buffer from the pool.
func (c *client) getPacketBuf() []byte {
	return unsafe.Slice(c.packetBufPool.Get().(*byte), c.packetBufSize)
}

// putPacketBuf puts the packet buffer back into the pool.
func (c *client) putPacketBuf(packetBuf []byte) {
	if cap(packetBuf) < c.packetBufSize {
		panic(fmt.Sprintf("putPacketBuf: packetBuf capacity %d, expected at least %d", cap(packetBuf), c.packetBufSize))
	}
	c.packetBufPool.Put(unsafe.SliceData(packetBuf))
}

// Stop implements the Service Stop method.
func (c *client) Stop() error {
	if err := c.wgConn.SetReadDeadline(conn.ALongTimeAgo); err != nil {
		return err
	}

	// Wait for wgConn receive goroutines to exit,
	// so there won't be any new sessions added to the table.
	c.mwg.Wait()

	c.mu.Lock()
	for clientAddrPort, entry := range c.table {
		proxyConn := entry.state.Swap(c.wgConn)
		if proxyConn == nil {
			continue
		}

		if err := proxyConn.SetReadDeadline(conn.ALongTimeAgo); err != nil {
			c.logger.Warn("Failed to SetReadDeadline on proxyConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("proxyAddress", &c.proxyAddr),
				zap.Error(err),
			)
		}
	}
	c.mu.Unlock()

	// Wait for all relay goroutines to exit before closing wgConn,
	// so in-flight packets can be written out.
	c.wg.Wait()

	return c.wgConn.Close()
}
