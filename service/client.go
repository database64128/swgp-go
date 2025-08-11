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
	"github.com/database64128/swgp-go/netiface"
	"github.com/database64128/swgp-go/packet"
	"github.com/database64128/swgp-go/tslog"
)

// ClientConfig is the configuration for a swgp client service.
type ClientConfig struct {
	// Name specifies the name of the client.
	Name string `json:"name"`

	// WgListenNetwork controls the address family of the server socket.
	//
	//  - "udp": Determine from system capabilities and listen address.
	//  - "udp4": AF_INET
	//  - "udp6": AF_INET6
	//
	// If unspecified, "udp" is used.
	WgListenNetwork string `json:"wgListenNetwork,omitzero"`

	// WgListenAddress specifies the address to bind the server socket to.
	WgListenAddress string `json:"wgListen"`

	// WgFwmark optionally specifies the server socket's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	WgFwmark int `json:"wgFwmark,omitzero"`

	// WgTrafficClass optionally specifies the server socket's traffic class.
	//
	// Available on most platforms except Windows.
	WgTrafficClass int `json:"wgTrafficClass,omitzero"`

	// ProxyEndpointNetwork controls the address family of the resolved IP address
	// when [ProxyEndpointAddress] is a domain name.
	//
	//  - "ip": System default
	//  - "ip4": IPv4
	//  - "ip6": IPv6
	//
	// If unspecified, "ip" is used.
	ProxyEndpointNetwork string `json:"proxyEndpointNetwork,omitzero"`

	// ProxyEndpointAddress specifies the address of the proxy server.
	// It can be either an IP address or a domain name.
	// Domain names are resolved on session establishment.
	ProxyEndpointAddress conn.Addr `json:"proxyEndpoint"`

	// ProxyConnListenAddress optionally specifies the address to bind the proxy-facing socket to.
	ProxyConnListenAddress conn.Addr `json:"proxyConnListenAddress,omitzero"`

	// ProxyMode specifies the proxy protocol.
	//
	//  - "zero-overhead": Lightweight protocol with minimal overhead.
	//  - "paranoid": Full-packet AEAD.
	//
	// See README for more information on the protocols.
	ProxyMode string `json:"proxyMode"`

	// ProxyPSK specifies the pre-shared key for the proxy.
	ProxyPSK []byte `json:"proxyPSK"`

	// ProxyFwmark optionally specifies the proxy-facing socket's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	ProxyFwmark int `json:"proxyFwmark,omitzero"`

	// ProxyTrafficClass optionally specifies the proxy-facing socket's traffic class.
	//
	// Available on most platforms except Windows.
	ProxyTrafficClass int `json:"proxyTrafficClass,omitzero"`

	// ProxyAutoPickInterface controls whether to automatically pick the network interface to
	// send proxy packets from.
	//
	// This is useful for preventing routing loops, when the system has a default route to
	// the WireGuard tunnel interface, but does not have a stable IP address to bind the
	// proxy socket to.
	//
	// Do not use this option on Linux or FreeBSD. Use [ProxyFwmark] instead.
	//
	// Available on macOS, Dragonfly BSD, NetBSD, OpenBSD, and Windows.
	ProxyAutoPickInterface bool `json:"proxyAutoPickInterface,omitzero"`

	// MTU specifies the maximum transmission unit of the client's designated network path.
	MTU int `json:"mtu"`

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

type client struct {
	name                   string
	wgListenNetwork        string
	wgListenAddress        string
	relayBatchSize         int
	mainRecvBatchSize      int
	sendChannelCapacity    int
	packetBufSize          int
	maxProxyPacketSize     int
	maxProxyPacketSizev6   int
	wgTunnelMTU            int
	wgTunnelMTUv6          int
	disableMmsg            bool
	proxyNetwork           string
	proxyAddr              conn.Addr
	proxyConnListenAddress conn.Addr
	handler                packet.Handler
	handler6               packet.Handler
	logger                 *tslog.Logger
	proxyIfacePicker       *netiface.Picker
	wgConn                 *net.UDPConn
	wgConnConfig           conn.UDPSocketConfig
	proxyConnConfig        conn.UDPSocketConfig
	packetBufPool          sync.Pool
	mu                     sync.Mutex
	wg                     sync.WaitGroup
	mwg                    sync.WaitGroup
	table                  map[netip.AddrPort]*clientNatEntry
}

// Client creates a swgp client service from the client config.
// Call the Start method on the returned service to start it.
func (cc *ClientConfig) Client(logger *tslog.Logger, socketConfigCache conn.UDPSocketConfigCache, ifacePicker *netiface.Picker) (*client, error) {
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
		return nil, fmt.Errorf("invalid wgListenNetwork %q: not one of [udp udp4 udp6]", cc.WgListenNetwork)
	}

	// Check ProxyEndpointNetwork.
	switch cc.ProxyEndpointNetwork {
	case "":
		cc.ProxyEndpointNetwork = "ip"
	case "ip", "ip4", "ip6":
	default:
		return nil, fmt.Errorf("invalid proxyEndpointNetwork %q: not one of [ip ip4 ip6]", cc.ProxyEndpointNetwork)
	}

	// Check and apply PerfConfig defaults.
	if err := cc.CheckAndApplyDefaults(); err != nil {
		return nil, err
	}

	maxProxyPacketSize := maxProxyPacketSizev4FromPathMTU(cc.MTU)
	maxProxyPacketSizev6 := maxProxyPacketSizev6FromPathMTU(cc.MTU)

	// Create packet handler for user-specified proxy mode.
	handler, handlerOverhead, err := newPacketHandler(cc.ProxyMode, cc.ProxyPSK, maxProxyPacketSize)
	if err != nil {
		return nil, err
	}
	handler6 := handler.WithMaxPacketSize(maxProxyPacketSizev6)

	wgTunnelMTU := wgTunnelMTUFromMaxPacketSize(maxProxyPacketSize - handlerOverhead)
	wgTunnelMTUv6 := wgTunnelMTUFromMaxPacketSize(maxProxyPacketSizev6 - handlerOverhead)

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
		relayBatchSize:         cc.RelayBatchSize,
		mainRecvBatchSize:      cc.MainRecvBatchSize,
		sendChannelCapacity:    cc.SendChannelCapacity,
		maxProxyPacketSize:     maxProxyPacketSize,
		maxProxyPacketSizev6:   maxProxyPacketSizev6,
		wgTunnelMTU:            wgTunnelMTU,
		wgTunnelMTUv6:          wgTunnelMTUv6,
		disableMmsg:            cc.DisableMmsg,
		proxyNetwork:           cc.ProxyEndpointNetwork,
		proxyAddr:              cc.ProxyEndpointAddress,
		proxyConnListenAddress: cc.ProxyConnListenAddress,
		handler:                handler,
		handler6:               handler6,
		logger:                 logger,
		proxyIfacePicker:       ifacePicker,
		wgConnConfig: socketConfigCache.Get(conn.UDPSocketOptions{
			SendBufferSize:           conn.DefaultUDPSocketBufferSize,
			ReceiveBufferSize:        conn.DefaultUDPSocketBufferSize,
			Fwmark:                   cc.WgFwmark,
			TrafficClass:             cc.WgTrafficClass,
			PathMTUDiscovery:         true,
			ProbeUDPGSOSupport:       !cc.DisableUDPGSO,
			UDPGenericReceiveOffload: !cc.DisableUDPGRO,
			ReceivePacketInfo:        true,
		}),
		proxyConnConfig: socketConfigCache.Get(conn.UDPSocketOptions{
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
	return &c, nil
}

// SlogAttr implements [Service.SlogAttr].
func (c *client) SlogAttr() slog.Attr {
	return slog.String("client", c.name)
}

// Start implements [Service.Start].
func (c *client) Start(ctx context.Context) (err error) {
	return c.start(ctx)
}

func (c *client) startGeneric(ctx context.Context) error {
	wgConn, wgConnInfo, err := c.wgConnConfig.Listen(ctx, c.wgListenNetwork, c.wgListenAddress)
	if err != nil {
		return err
	}
	c.wgConn = wgConn
	c.wgListenAddress = wgConn.LocalAddr().String()

	if wgConnInfo.UDPGenericReceiveOffload {
		c.packetBufSize = 65535
	} else {
		c.packetBufSize = c.maxProxyPacketSize
	}

	logger := c.logger.WithAttrs(
		slog.String("client", c.name),
		slog.String("listenAddress", c.wgListenAddress),
	)

	c.mwg.Add(1)

	go func() {
		c.recvFromWgConnGeneric(ctx, logger, wgConn, wgConnInfo)
		c.mwg.Done()
	}()

	if logger.Enabled(slog.LevelInfo) {
		fields := make([]slog.Attr, 0, 5)
		fields = append(fields, tslog.ConnAddrp("proxyAddress", &c.proxyAddr))

		if c.proxyAddr.IsIP() {
			fields = append(fields, slog.Int("wgTunnelMTU", c.wgTunnelMTU))
		} else {
			fields = append(fields,
				slog.Int("wgTunnelMTUv4", c.wgTunnelMTU),
				slog.Int("wgTunnelMTUv6", c.wgTunnelMTUv6),
			)
		}

		fields = append(fields,
			tslog.Uint("maxUDPGSOSegments", wgConnInfo.MaxUDPGSOSegments),
			slog.Bool("udpGRO", wgConnInfo.UDPGenericReceiveOffload),
		)

		logger.Info("Started service", fields...)
	}
	return nil
}

func (c *client) recvFromWgConnGeneric(ctx context.Context, logger *tslog.Logger, wgConn *net.UDPConn, wgConnInfo conn.SocketInfo) {
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
			logger.Warn("Failed to read from wgConn",
				tslog.AddrPort("clientAddress", clientAddrPort),
				slog.Int("packetLength", n),
				slog.Int("cmsgLength", cmsgn),
				tslog.Err(err),
			)
			continue
		}
		if err = conn.ParseFlagsForError(flags); err != nil {
			logger.Warn("Failed to read from wgConn",
				tslog.AddrPort("clientAddress", clientAddrPort),
				slog.Int("packetLength", n),
				slog.Int("cmsgLength", cmsgn),
				tslog.Err(err),
			)
			continue
		}

		rscm, err := conn.ParseSocketControlMessage(cmsgBuf[:cmsgn])
		if err != nil {
			logger.Error("Failed to parse socket control message from wgConn",
				tslog.AddrPort("clientAddress", clientAddrPort),
				slog.Int("cmsgLength", cmsgn),
				tslog.Err(err),
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

			if logger.Enabled(slog.LevelDebug) {
				logger.Debug("Updated client pktinfo",
					tslog.AddrPort("clientAddress", clientAddrPort),
					tslog.Addrp("clientPktinfoAddr", &clientPktinfop.addr),
					tslog.Uint("clientPktinfoIfindex", clientPktinfoCache.ifindex),
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
					logger.Warn("Failed to resolve proxy address for new session",
						tslog.AddrPort("clientAddress", clientAddrPort),
						tslog.Err(err),
					)
					return
				}

				// Unmapping proxyAddrPort aligns its address family with proxyConn,
				// which enables direct equality comparison with the address returned by ReadMsgUDPAddrPort.
				if proxyAddrPort.Addr().Is4In6() {
					proxyAddrPort = netip.AddrPortFrom(proxyAddrPort.Addr().Unmap(), proxyAddrPort.Port())
				}

				var proxyPktinfop *atomic.Pointer[conn.Pktinfo]
				if c.proxyIfacePicker != nil {
					c.proxyIfacePicker.RequestPoll()
					if proxyAddrPort.Addr().Is4() {
						proxyPktinfop = c.proxyIfacePicker.Default4()
					} else {
						proxyPktinfop = c.proxyIfacePicker.Default6()
					}
				}

				proxyConnListenNetwork := listenUDPNetworkForUnmappedRemoteAddr(proxyAddrPort.Addr())
				proxyConnListenAddress := c.proxyConnListenAddress.String()

				proxyConn, proxyConnInfo, err := c.proxyConnConfig.Listen(ctx, proxyConnListenNetwork, proxyConnListenAddress)
				if err != nil {
					logger.Warn("Failed to create UDP socket for new session",
						tslog.AddrPort("clientAddress", clientAddrPort),
						slog.String("proxyConnListenNetwork", proxyConnListenNetwork),
						slog.String("proxyConnListenAddress", proxyConnListenAddress),
						tslog.Err(err),
					)
					return
				}

				proxyConnListenAddrPort := proxyConn.LocalAddr().(*net.UDPAddr).AddrPort()

				if err = proxyConn.SetReadDeadline(time.Now().Add(wireguard.RejectAfterTime)); err != nil {
					logger.Error("Failed to SetReadDeadline on proxyConn",
						tslog.AddrPort("clientAddress", clientAddrPort),
						tslog.AddrPort("proxyConnListenAddress", proxyConnListenAddrPort),
						tslog.Err(err),
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

				sesLogger := logger.WithAttrs(
					tslog.AddrPort("clientAddress", clientAddrPort),
					tslog.AddrPort("proxyConnListenAddress", proxyConnListenAddrPort),
					tslog.AddrPort("proxyAddress", proxyAddrPort),
				)

				sesLogger.Info("Client relay started",
					slog.Int("wgTunnelMTU", wgTunnelMTU),
					tslog.Uint("maxUDPGSOSegments", proxyConnInfo.MaxUDPGSOSegments),
					slog.Bool("udpGRO", proxyConnInfo.UDPGenericReceiveOffload),
				)

				c.wg.Add(1)

				go func() {
					c.relayWgToProxyGeneric(
						proxyAddrPort,
						proxyPktinfop,
						proxyConn,
						proxyConnInfo,
						proxyConnSendCh,
						handler,
						sesLogger,
					)
					proxyConn.Close()
					c.wg.Done()
				}()

				c.relayProxyToWgGeneric(
					clientAddrPort,
					clientPktinfop,
					&natEntry.clientPktinfo,
					proxyAddrPort,
					proxyConn,
					wgConn,
					wgConnInfo,
					handler,
					maxProxyPacketSize,
					sesLogger,
				)
			}()

			if logger.Enabled(slog.LevelDebug) {
				logger.Debug("New client session",
					tslog.AddrPort("clientAddress", clientAddrPort),
					tslog.ConnAddrp("proxyAddress", &c.proxyAddr),
				)
			}
		}

		select {
		case natEntry.proxyConnSendCh <- qp:
			packetBuf = c.getPacketBuf()
		default:
			if logger.Enabled(slog.LevelDebug) {
				logger.Debug("swgpPacket dropped due to full send channel",
					tslog.AddrPort("clientAddress", clientAddrPort),
					tslog.ConnAddrp("proxyAddress", &c.proxyAddr),
				)
			}
		}

		c.mu.Unlock()
	}

	c.putPacketBuf(packetBuf)

	logger.Info("Finished receiving from wgConn",
		tslog.ConnAddrp("proxyAddress", &c.proxyAddr),
		tslog.Uint("recvmsgCount", recvmsgCount),
		tslog.Uint("packetsReceived", packetsReceived),
		tslog.Uint("wgBytesReceived", wgBytesReceived),
		tslog.Uint("burstSegmentCount", burstSegmentCount),
	)
}

func (c *client) relayWgToProxyGeneric(
	proxyAddrPort netip.AddrPort,
	proxyPktinfop *atomic.Pointer[conn.Pktinfo],
	proxyConn *net.UDPConn,
	proxyConnInfo conn.SocketInfo,
	proxyConnSendCh <-chan queuedPacket,
	handler packet.Handler,
	logger *tslog.Logger,
) {
	packetBuf := make([]byte, 0, c.packetBufSize)
	cmsgBuf := make([]byte, 0, conn.SocketControlMessageBufferSize)

	var (
		sendQueuedPackets []queuedPacket
		sendmsgCount      uint64
		packetsSent       uint64
		swgpBytesSent     uint64
		burstSegmentCount uint32
	)

	for rqp := range proxyConnSendCh {
		var (
			isHandshake     bool
			sqpLength       uint32
			sqpSegmentSize  uint32
			sqpSegmentCount uint32
		)

		for wgPacketBuf := rqp.buf; len(wgPacketBuf) > 0; {
			wgPacketLength := min(len(wgPacketBuf), int(rqp.segmentSize))
			wgPacket := wgPacketBuf[:wgPacketLength]
			wgPacketBuf = wgPacketBuf[wgPacketLength:]

			// Update proxyConn read deadline when rqp contains a WireGuard handshake initiation message.
			if wgPacket[0] == wireguard.MessageTypeHandshakeInitiation {
				isHandshake = true
			}

			dst, err := handler.Encrypt(packetBuf, wgPacket)
			if err != nil {
				logger.Warn("Failed to encrypt wgPacket",
					slog.Int("packetLength", wgPacketLength),
					tslog.Err(err),
				)
				continue
			}

			segmentSize := uint32(len(dst) - len(packetBuf))

			switch {
			case sqpLength == 0:
				sqpLength = segmentSize
				sqpSegmentSize = segmentSize
				sqpSegmentCount = 1
			case sqpSegmentSize < segmentSize:
				// Save existing sqp and start a new one with the current segment.
				sendQueuedPackets = append(sendQueuedPackets, queuedPacket{
					buf:          packetBuf[len(packetBuf)-int(sqpLength):],
					segmentSize:  sqpSegmentSize,
					segmentCount: sqpSegmentCount,
				})
				sqpLength = segmentSize
				sqpSegmentSize = segmentSize
				sqpSegmentCount = 1
			case sqpSegmentSize == segmentSize:
				// Keep segment.
				sqpLength += segmentSize
				sqpSegmentCount++
			case sqpSegmentSize > segmentSize:
				// Segment is the last short segment.
				sendQueuedPackets = append(sendQueuedPackets, queuedPacket{
					buf:          dst[len(packetBuf)-int(sqpLength):],
					segmentSize:  sqpSegmentSize,
					segmentCount: sqpSegmentCount + 1,
				})
				sqpLength = 0
			default:
				panic("unreachable")
			}

			packetBuf = dst
		}

		if sqpLength > 0 {
			sendQueuedPackets = append(sendQueuedPackets, queuedPacket{
				buf:          packetBuf[len(packetBuf)-int(sqpLength):],
				segmentSize:  sqpSegmentSize,
				segmentCount: sqpSegmentCount,
			})
		}

		c.putPacketBuf(rqp.buf)

		if len(sendQueuedPackets) == 0 {
			continue
		}

		var proxyPktinfo conn.Pktinfo

		if proxyPktinfop != nil {
			if isHandshake {
				c.proxyIfacePicker.RequestPoll()
			}

			proxyPktinfo = *proxyPktinfop.Load()
			if !proxyPktinfo.Addr.IsValid() {
				logger.Debug("swgpPacket dropped: no suitable interface")
				sendQueuedPackets = sendQueuedPackets[:0]
			}
		}

		for _, sqp := range sendQueuedPackets {
			b := sqp.buf
			segmentsRemaining := sqp.segmentCount

			maxUDPGSOSegments := proxyConnInfo.MaxUDPGSOSegments
			if maxUDPGSOSegments > 1 {
				// Cap each coalesced message to 65535 bytes to prevent -EMSGSIZE.
				maxUDPGSOSegments = max(1, 65535/sqp.segmentSize)
			}

			for segmentsRemaining > 0 {
				sendSegmentCount := min(segmentsRemaining, maxUDPGSOSegments)
				segmentsRemaining -= sendSegmentCount

				sendBufSize := min(len(b), int(sqp.segmentSize*sendSegmentCount))
				sendBuf := b[:sendBufSize]
				b = b[sendBufSize:]

				scm := conn.SocketControlMessage{
					PktinfoAddr:    proxyPktinfo.Addr,
					PktinfoIfindex: proxyPktinfo.Ifindex,
				}
				if sendSegmentCount > 1 {
					scm.SegmentSize = sqp.segmentSize
				}
				cmsg := scm.AppendTo(cmsgBuf)

				n, _, err := proxyConn.WriteMsgUDPAddrPort(sendBuf, cmsg, proxyAddrPort)
				if err != nil {
					logger.Warn("Failed to write swgpPacket to proxyConn",
						slog.Int("swgpPacketLength", sendBufSize),
						tslog.Uint("segmentSize", sqp.segmentSize),
						tslog.Err(err),
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
		packetBuf = packetBuf[:0]

		if isHandshake {
			if err := proxyConn.SetReadDeadline(time.Now().Add(wireguard.RejectAfterTime)); err != nil {
				logger.Error("Failed to SetReadDeadline on proxyConn", tslog.Err(err))
			}
		}
	}

	logger.Info("Finished relay wgConn -> proxyConn",
		tslog.Uint("sendmsgCount", sendmsgCount),
		tslog.Uint("packetsSent", packetsSent),
		tslog.Uint("swgpBytesSent", swgpBytesSent),
		tslog.Uint("burstSegmentCount", burstSegmentCount),
	)
}

func (c *client) relayProxyToWgGeneric(
	clientAddrPort netip.AddrPort,
	clientPktinfop *pktinfo,
	atomicClientPktinfop *atomic.Pointer[pktinfo],
	proxyAddrPort netip.AddrPort,
	proxyConn *net.UDPConn,
	wgConn *net.UDPConn,
	wgConnInfo conn.SocketInfo,
	handler packet.Handler,
	maxProxyPacketSize int,
	logger *tslog.Logger,
) {
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

	if clientPktinfop != nil {
		clientPktinfo = *clientPktinfop
	}

	recvPacketBuf := make([]byte, maxProxyPacketSize)
	recvCmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)
	sendPacketBuf := make([]byte, 0, maxProxyPacketSize)
	sendCmsgBuf := make([]byte, 0, conn.SocketControlMessageBufferSize)

	for {
		n, cmsgn, flags, packetSourceAddrPort, err := proxyConn.ReadMsgUDPAddrPort(recvPacketBuf, recvCmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			logger.Warn("Failed to read from proxyConn",
				tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
				slog.Int("packetLength", n),
				slog.Int("cmsgLength", cmsgn),
				tslog.Err(err),
			)
			continue
		}
		if err = conn.ParseFlagsForError(flags); err != nil {
			logger.Warn("Failed to read from proxyConn",
				tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
				slog.Int("packetLength", n),
				slog.Int("cmsgLength", cmsgn),
				tslog.Err(err),
			)
			continue
		}

		if packetSourceAddrPort != proxyAddrPort {
			logger.Warn("Ignoring packet from non-proxy address",
				tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
				slog.Int("packetLength", n),
				tslog.Err(err),
			)
			continue
		}

		rscm, err := conn.ParseSocketControlMessage(recvCmsgBuf[:cmsgn])
		if err != nil {
			logger.Error("Failed to parse socket control message from proxyConn",
				tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
				slog.Int("cmsgLength", cmsgn),
				tslog.Err(err),
			)
			continue
		}

		recvmsgCount++
		swgpBytesReceived += uint64(n)

		swgpPacketBuf := recvPacketBuf[:n]

		recvSegmentSize := int(rscm.SegmentSize)
		if recvSegmentSize == 0 {
			recvSegmentSize = len(swgpPacketBuf)
		}

		var (
			recvSegmentCount uint32
			qpLength         uint32
			qpSegmentSize    uint32
			qpSegmentCount   uint32
		)

		for len(swgpPacketBuf) > 0 {
			swgpPacketLength := min(len(swgpPacketBuf), recvSegmentSize)
			swgpPacket := swgpPacketBuf[:swgpPacketLength]
			swgpPacketBuf = swgpPacketBuf[swgpPacketLength:]
			recvSegmentCount++

			dst, err := handler.Decrypt(sendPacketBuf, swgpPacket)
			if err != nil {
				logger.Warn("Failed to decrypt swgpPacket",
					slog.Int("packetLength", swgpPacketLength),
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

				sscm := conn.SocketControlMessage{
					PktinfoAddr:    clientPktinfo.addr,
					PktinfoIfindex: clientPktinfo.ifindex,
				}
				if sendSegmentCount > 1 {
					sscm.SegmentSize = qp.segmentSize
				}
				cmsg := sscm.AppendTo(sendCmsgBuf)

				n, _, err := wgConn.WriteMsgUDPAddrPort(sendBuf, cmsg, clientAddrPort)
				if err != nil {
					logger.Warn("Failed to write wgPacket to wgConn",
						slog.Int("wgPacketLength", sendBufSize),
						tslog.Uint("segmentSize", qp.segmentSize),
						tslog.Uint("segmentCount", sendSegmentCount),
						tslog.Err(err),
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
		sendPacketBuf = sendPacketBuf[:0]
	}

	logger.Info("Finished relay proxyConn -> wgConn",
		tslog.Uint("recvmsgCount", recvmsgCount),
		tslog.Uint("packetsReceived", packetsReceived),
		tslog.Uint("swgpBytesReceived", swgpBytesReceived),
		tslog.Uint("sendmsgCount", sendmsgCount),
		tslog.Uint("packetsSent", packetsSent),
		tslog.Uint("wgBytesSent", wgBytesSent),
		tslog.Uint("burstRecvSegmentCount", burstRecvSegmentCount),
		tslog.Uint("burstSendSegmentCount", burstSendSegmentCount),
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

// Stop implements [Service.Stop].
func (c *client) Stop() error {
	if err := c.wgConn.SetReadDeadline(conn.ALongTimeAgo); err != nil {
		return fmt.Errorf("failed to SetReadDeadline on wgConn: %w", err)
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
			c.logger.Error("Failed to SetReadDeadline on proxyConn",
				slog.String("client", c.name),
				slog.String("listenAddress", c.wgListenAddress),
				tslog.AddrPort("clientAddress", clientAddrPort),
				tslog.ConnAddrp("proxyAddress", &c.proxyAddr),
				tslog.Err(err),
			)
		}
	}
	c.mu.Unlock()

	// Wait for all relay goroutines to exit before closing wgConn,
	// so in-flight packets can be written out.
	c.wg.Wait()

	if err := c.wgConn.Close(); err != nil {
		return fmt.Errorf("failed to close wgConn: %w", err)
	}

	c.logger.Info("Stopped service", slog.String("client", c.name))
	return nil
}
