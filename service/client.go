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
	clientPktinfo      atomic.Pointer[[]byte]
	clientPktinfoCache []byte
	proxyConnSendCh    chan<- queuedPacket
}

type clientNatUplinkGeneric struct {
	clientAddrPort  netip.AddrPort
	proxyAddrPort   netip.AddrPort
	proxyConn       *net.UDPConn
	proxyConnSendCh <-chan queuedPacket
}

type clientNatDownlinkGeneric struct {
	clientAddrPort     netip.AddrPort
	clientPktinfo      *atomic.Pointer[[]byte]
	proxyAddrPort      netip.AddrPort
	proxyConn          *net.UDPConn
	wgConn             *net.UDPConn
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
	maxProxyPacketSize     int
	maxProxyPacketSizev6   int
	wgTunnelMTU            int
	wgTunnelMTUv6          int
	proxyNetwork           string
	proxyAddr              conn.Addr
	handler                packet.Handler
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

	// Create packet handler for user-specified proxy mode.
	handler, err := getPacketHandlerForProxyMode(cc.ProxyMode, cc.ProxyPSK)
	if err != nil {
		return nil, err
	}

	// maxProxyPacketSize = MTU - IP header length - UDP header length
	maxProxyPacketSize := cc.MTU - IPv4HeaderLength - UDPHeaderLength
	maxProxyPacketSizev6 := cc.MTU - IPv6HeaderLength - UDPHeaderLength
	wgTunnelMTU := getWgTunnelMTUForHandler(handler, maxProxyPacketSize)
	wgTunnelMTUv6 := getWgTunnelMTUForHandler(handler, maxProxyPacketSizev6)

	// Use IPv6 values if the proxy endpoint is an IPv6 address.
	if cc.ProxyEndpointAddress.IsIP() {
		if ip := cc.ProxyEndpointAddress.IP(); !ip.Is4() && !ip.Is4In6() {
			maxProxyPacketSize = maxProxyPacketSizev6
			wgTunnelMTU = wgTunnelMTUv6
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
		logger:                 logger,
		wgConnListenConfig: listenConfigCache.Get(conn.ListenerSocketOptions{
			Fwmark:            cc.WgFwmark,
			TrafficClass:      cc.WgTrafficClass,
			PathMTUDiscovery:  true,
			ReceivePacketInfo: true,
		}),
		proxyConnListenConfig: listenConfigCache.Get(conn.ListenerSocketOptions{
			Fwmark:           cc.ProxyFwmark,
			TrafficClass:     cc.ProxyTrafficClass,
			PathMTUDiscovery: true,
		}),
		packetBufPool: sync.Pool{
			New: func() any {
				b := make([]byte, maxProxyPacketSize)
				return unsafe.SliceData(b)
			},
		},
		table: make(map[netip.AddrPort]*clientNatEntry),
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
	wgConn, err := c.wgConnListenConfig.ListenUDP(ctx, c.wgListenNetwork, c.wgListenAddress)
	if err != nil {
		return err
	}
	c.wgConn = wgConn

	c.mwg.Add(1)

	go func() {
		c.recvFromWgConnGeneric(ctx, wgConn)
		c.mwg.Done()
	}()

	if ce := c.logger.Check(zap.InfoLevel, "Started service"); ce != nil {
		fields := []zap.Field{
			zap.String("client", c.name),
			zap.String("listenAddress", c.wgListenAddress),
			zap.Stringer("proxyAddress", &c.proxyAddr),
			{},
			{},
		}

		if c.proxyAddr.IsIP() {
			fields[3] = zap.Int("wgTunnelMTU", c.wgTunnelMTU)
			fields = fields[:4]
		} else {
			fields[3] = zap.Int("wgTunnelMTUv4", c.wgTunnelMTU)
			fields[4] = zap.Int("wgTunnelMTUv6", c.wgTunnelMTUv6)
		}

		ce.Write(fields...)
	}
	return nil
}

func (c *client) recvFromWgConnGeneric(ctx context.Context, wgConn *net.UDPConn) {
	headroom := c.handler.Headroom()

	cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)

	var (
		packetsReceived uint64
		wgBytesReceived uint64
	)

	for {
		packetBuf := c.getPacketBuf()
		plaintextBuf := packetBuf[headroom.Front : c.maxProxyPacketSize-headroom.Rear]

		n, cmsgn, flags, clientAddrPort, err := wgConn.ReadMsgUDPAddrPort(plaintextBuf, cmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				c.putPacketBuf(packetBuf)
				break
			}
			c.logger.Warn("Failed to read from wgConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			c.putPacketBuf(packetBuf)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			c.logger.Warn("Failed to read from wgConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			c.putPacketBuf(packetBuf)
			continue
		}

		packetsReceived++
		wgBytesReceived += uint64(n)

		c.mu.Lock()

		natEntry, ok := c.table[clientAddrPort]
		if !ok {
			natEntry = &clientNatEntry{}
		}

		cmsg := cmsgBuf[:cmsgn]

		if !bytes.Equal(natEntry.clientPktinfoCache, cmsg) {
			clientPktinfoAddr, clientPktinfoIfindex, err := conn.ParsePktinfoCmsg(cmsg)
			if err != nil {
				c.logger.Warn("Failed to parse pktinfo control message from wgConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Error(err),
				)
				c.putPacketBuf(packetBuf)
				c.mu.Unlock()
				continue
			}

			clientPktinfoCache := make([]byte, len(cmsg))
			copy(clientPktinfoCache, cmsg)
			natEntry.clientPktinfo.Store(&clientPktinfoCache)
			natEntry.clientPktinfoCache = clientPktinfoCache

			if ce := c.logger.Check(zap.DebugLevel, "Updated client pktinfo"); ce != nil {
				ce.Write(
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
					zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
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

				proxyConn, err := c.proxyConnListenConfig.ListenUDP(ctx, c.proxyConnListenNetwork, c.proxyConnListenAddress)
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

				if c.proxyAddr.IsDomain() {
					if addr := proxyAddrPort.Addr(); !addr.Is4() && !addr.Is4In6() {
						maxProxyPacketSize = c.maxProxyPacketSizev6
						wgTunnelMTU = c.wgTunnelMTUv6
					}
				}

				c.logger.Info("Client relay started",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("proxyAddress", proxyAddrPort),
					zap.Int("wgTunnelMTU", wgTunnelMTU),
				)

				c.wg.Add(1)

				go func() {
					c.relayWgToProxyGeneric(clientNatUplinkGeneric{
						clientAddrPort:  clientAddrPort,
						proxyAddrPort:   proxyAddrPort,
						proxyConn:       proxyConn,
						proxyConnSendCh: proxyConnSendCh,
					})
					proxyConn.Close()
					c.wg.Done()
				}()

				c.relayProxyToWgGeneric(clientNatDownlinkGeneric{
					clientAddrPort:     clientAddrPort,
					clientPktinfo:      &natEntry.clientPktinfo,
					proxyAddrPort:      proxyAddrPort,
					proxyConn:          proxyConn,
					wgConn:             wgConn,
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
		case natEntry.proxyConnSendCh <- queuedPacket{packetBuf, headroom.Front, n}:
		default:
			if ce := c.logger.Check(zap.DebugLevel, "swgpPacket dropped due to full send channel"); ce != nil {
				ce.Write(
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("proxyAddress", &c.proxyAddr),
				)
			}
			c.putPacketBuf(packetBuf)
		}

		c.mu.Unlock()
	}

	c.logger.Info("Finished receiving from wgConn",
		zap.String("client", c.name),
		zap.String("listenAddress", c.wgListenAddress),
		zap.Stringer("proxyAddress", &c.proxyAddr),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("wgBytesReceived", wgBytesReceived),
	)
}

func (c *client) relayWgToProxyGeneric(uplink clientNatUplinkGeneric) {
	var (
		packetsSent uint64
		wgBytesSent uint64
	)

	for queuedPacket := range uplink.proxyConnSendCh {
		// Update proxyConn read deadline when a handshake initiation/response message is received.
		switch queuedPacket.buf[queuedPacket.start] {
		case packet.WireGuardMessageTypeHandshakeInitiation, packet.WireGuardMessageTypeHandshakeResponse:
			if err := uplink.proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
				c.logger.Warn("Failed to SetReadDeadline on proxyConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Stringer("proxyAddress", uplink.proxyAddrPort),
					zap.Error(err),
				)
				c.putPacketBuf(queuedPacket.buf)
				continue
			}
		}

		swgpPacketStart, swgpPacketLength, err := c.handler.EncryptZeroCopy(queuedPacket.buf, queuedPacket.start, queuedPacket.length)
		if err != nil {
			c.logger.Warn("Failed to encrypt WireGuard packet",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", uplink.clientAddrPort),
				zap.Error(err),
			)
			c.putPacketBuf(queuedPacket.buf)
			continue
		}
		swgpPacket := queuedPacket.buf[swgpPacketStart : swgpPacketStart+swgpPacketLength]

		_, err = uplink.proxyConn.WriteToUDPAddrPort(swgpPacket, uplink.proxyAddrPort)
		if err != nil {
			c.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", uplink.clientAddrPort),
				zap.Stringer("proxyAddress", uplink.proxyAddrPort),
				zap.Int("swgpPacketLength", swgpPacketLength),
				zap.Error(err),
			)
		}

		c.putPacketBuf(queuedPacket.buf)
		packetsSent++
		wgBytesSent += uint64(queuedPacket.length)
	}

	c.logger.Info("Finished relay wgConn -> proxyConn",
		zap.String("client", c.name),
		zap.String("listenAddress", c.wgListenAddress),
		zap.Stringer("clientAddress", uplink.clientAddrPort),
		zap.Stringer("proxyAddress", uplink.proxyAddrPort),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (c *client) relayProxyToWgGeneric(downlink clientNatDownlinkGeneric) {
	var (
		clientPktinfop *[]byte
		clientPktinfo  []byte
		packetsSent    uint64
		wgBytesSent    uint64
	)

	packetBuf := make([]byte, downlink.maxProxyPacketSize)

	for {
		n, _, flags, packetSourceAddrPort, err := downlink.proxyConn.ReadMsgUDPAddrPort(packetBuf, nil)
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
				zap.Error(err),
			)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			c.logger.Warn("Failed to read from proxyConn",
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

		wgPacketStart, wgPacketLength, err := c.handler.DecryptZeroCopy(packetBuf, 0, n)
		if err != nil {
			c.logger.Warn("Failed to decrypt swgpPacket",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("proxyAddress", downlink.proxyAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		wgPacket := packetBuf[wgPacketStart : wgPacketStart+wgPacketLength]

		if cpp := downlink.clientPktinfo.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp
		}

		_, _, err = downlink.wgConn.WriteMsgUDPAddrPort(wgPacket, clientPktinfo, downlink.clientAddrPort)
		if err != nil {
			c.logger.Warn("Failed to write wgPacket to wgConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("proxyAddress", downlink.proxyAddrPort),
				zap.Int("wgPacketLength", wgPacketLength),
				zap.Error(err),
			)
		}

		packetsSent++
		wgBytesSent += uint64(wgPacketLength)
	}

	c.logger.Info("Finished relay proxyConn -> wgConn",
		zap.String("client", c.name),
		zap.String("listenAddress", c.wgListenAddress),
		zap.Stringer("clientAddress", downlink.clientAddrPort),
		zap.Stringer("proxyAddress", downlink.proxyAddrPort),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

// getPacketBuf retrieves a packet buffer from the pool.
func (c *client) getPacketBuf() []byte {
	return unsafe.Slice(c.packetBufPool.Get().(*byte), c.maxProxyPacketSize)
}

// putPacketBuf puts the packet buffer back into the pool.
func (c *client) putPacketBuf(packetBuf []byte) {
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
