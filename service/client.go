package service

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/packet"
	"go.uber.org/zap"
)

// ClientConfig stores configurations for a swgp client service.
// It may be marshaled as or unmarshaled from JSON.
type ClientConfig struct {
	Name          string `json:"name"`
	WgListen      string `json:"wgListen"`
	WgFwmark      int    `json:"wgFwmark"`
	ProxyEndpoint string `json:"proxyEndpoint"`
	ProxyMode     string `json:"proxyMode"`
	ProxyPSK      []byte `json:"proxyPSK"`
	ProxyFwmark   int    `json:"proxyFwmark"`
	MTU           int    `json:"mtu"`
	BatchMode     string `json:"batchMode"`
}

type clientNatEntry struct {
	clientPktinfo      atomic.Pointer[[]byte]
	clientPktinfoCache []byte
	proxyConn          *net.UDPConn
	proxyConnSendCh    chan queuedPacket
}

type client struct {
	name               string
	wgListen           string
	wgFwmark           int
	proxyFwmark        int
	maxProxyPacketSize int
	proxyAddrPort      netip.AddrPort
	handler            packet.Handler
	wgConn             *net.UDPConn
	logger             *zap.Logger
	packetBufPool      sync.Pool
	mu                 sync.Mutex
	wg                 sync.WaitGroup
	mwg                sync.WaitGroup
	table              map[netip.AddrPort]*clientNatEntry
	recvFromWgConn     func()
}

// NewClientService creates a swgp client service from the specified client config.
// Call the Start method on the returned service to start it.
func NewClientService(config ClientConfig, logger *zap.Logger) (Service, error) {
	// Require MTU to be at least 1280.
	if config.MTU < minimumMTU {
		return nil, ErrMTUTooSmall
	}

	// Create packet handler for user-specified proxy mode.
	handler, err := getPacketHandlerForProxyMode(config.ProxyMode, config.ProxyPSK)
	if err != nil {
		return nil, err
	}

	// Resolve endpoint address.
	proxyAddrPort, err := conn.ResolveAddrPort(config.ProxyEndpoint)
	if err != nil {
		return nil, err
	}

	var maxProxyPacketSize int

	// maxProxyPacketSize = MTU - IP header length - UDP header length
	if addr := proxyAddrPort.Addr(); addr.Is4() || addr.Is4In6() {
		maxProxyPacketSize = config.MTU - IPv4HeaderLength - UDPHeaderLength
	} else {
		maxProxyPacketSize = config.MTU - IPv6HeaderLength - UDPHeaderLength
	}

	c := client{
		name:               config.Name,
		wgListen:           config.WgListen,
		wgFwmark:           config.WgFwmark,
		proxyFwmark:        config.ProxyFwmark,
		maxProxyPacketSize: maxProxyPacketSize,
		proxyAddrPort:      proxyAddrPort,
		handler:            handler,
		logger:             logger,
		table:              make(map[netip.AddrPort]*clientNatEntry),
	}
	c.packetBufPool.New = func() any {
		b := make([]byte, maxProxyPacketSize)
		return &b
	}
	c.setRelayFunc(config.BatchMode)
	return &c, nil
}

// String implements the Service String method.
func (c *client) String() string {
	return c.name + " swgp client service"
}

// Start implements the Service Start method.
func (c *client) Start() (err error) {
	c.wgConn, err = conn.ListenUDP("udp", c.wgListen, true, c.wgFwmark)
	if err != nil {
		return
	}

	c.mwg.Add(1)

	go func() {
		c.recvFromWgConn()
		c.mwg.Done()
	}()

	wgTunnelMTU := (c.maxProxyPacketSize - c.handler.FrontOverhead() - c.handler.RearOverhead() - WireGuardDataPacketOverhead) & WireGuardDataPacketLengthMask

	c.logger.Info("Started service",
		zap.String("client", c.name),
		zap.String("wgListen", c.wgListen),
		zap.Stringer("proxyAddress", c.proxyAddrPort),
		zap.Int("wgTunnelMTU", wgTunnelMTU),
	)
	return
}

func (c *client) recvFromWgConnGeneric() {
	frontOverhead := c.handler.FrontOverhead()
	rearOverhead := c.handler.RearOverhead()

	cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)

	var (
		packetsReceived uint64
		wgBytesReceived uint64
	)

	for {
		packetBufp := c.packetBufPool.Get().(*[]byte)
		packetBuf := *packetBufp
		plaintextBuf := packetBuf[frontOverhead : c.maxProxyPacketSize-rearOverhead]

		n, cmsgn, flags, clientAddrPort, err := c.wgConn.ReadMsgUDPAddrPort(plaintextBuf, cmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				c.packetBufPool.Put(packetBufp)
				break
			}
			c.logger.Warn("Failed to read from wgConn",
				zap.String("client", c.name),
				zap.String("wgListen", c.wgListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			c.packetBufPool.Put(packetBufp)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			c.logger.Warn("Failed to read from wgConn",
				zap.String("client", c.name),
				zap.String("wgListen", c.wgListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			c.packetBufPool.Put(packetBufp)
			continue
		}
		cmsg := cmsgBuf[:cmsgn]

		packetsReceived++
		wgBytesReceived += uint64(n)

		c.mu.Lock()

		natEntry, ok := c.table[clientAddrPort]
		if !ok {
			proxyConn, err := conn.ListenUDP("udp", "", false, c.proxyFwmark)
			if err != nil {
				c.logger.Warn("Failed to create UDP socket for new UDP session",
					zap.String("client", c.name),
					zap.String("wgListen", c.wgListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Int("proxyFwmark", c.proxyFwmark),
					zap.Error(err),
				)
				c.packetBufPool.Put(packetBufp)
				c.mu.Unlock()
				continue
			}

			err = proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
			if err != nil {
				c.logger.Warn("Failed to SetReadDeadline on proxyConn",
					zap.String("client", c.name),
					zap.String("wgListen", c.wgListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("proxyAddress", c.proxyAddrPort),
					zap.Error(err),
				)
				c.packetBufPool.Put(packetBufp)
				c.mu.Unlock()
				continue
			}

			natEntry = &clientNatEntry{
				proxyConn:       proxyConn,
				proxyConnSendCh: make(chan queuedPacket, sendChannelCapacity),
			}

			c.table[clientAddrPort] = natEntry
		}

		var clientPktinfop *[]byte

		if !bytes.Equal(natEntry.clientPktinfoCache, cmsg) {
			clientPktinfoAddr, clientPktinfoIfindex, err := conn.ParsePktinfoCmsg(cmsg)
			if err != nil {
				c.logger.Warn("Failed to parse pktinfo control message from wgConn",
					zap.String("client", c.name),
					zap.String("wgListen", c.wgListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Error(err),
				)
				c.packetBufPool.Put(packetBufp)
				c.mu.Unlock()
				continue
			}

			clientPktinfoCache := make([]byte, len(cmsg))
			copy(clientPktinfoCache, cmsg)
			clientPktinfop = &clientPktinfoCache
			natEntry.clientPktinfo.Store(clientPktinfop)
			natEntry.clientPktinfoCache = clientPktinfoCache

			if ce := c.logger.Check(zap.DebugLevel, "Updated client pktinfo"); ce != nil {
				ce.Write(
					zap.String("client", c.name),
					zap.String("wgListen", c.wgListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
					zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
				)
			}
		}

		if !ok {
			c.wg.Add(2)

			go func() {
				c.relayProxyToWgGeneric(clientAddrPort, natEntry, clientPktinfop)

				c.mu.Lock()
				close(natEntry.proxyConnSendCh)
				delete(c.table, clientAddrPort)
				c.mu.Unlock()

				c.wg.Done()
			}()

			go func() {
				c.relayWgToProxyGeneric(clientAddrPort, natEntry)
				natEntry.proxyConn.Close()
				c.wg.Done()
			}()

			c.logger.Info("New UDP session",
				zap.String("client", c.name),
				zap.String("wgListen", c.wgListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("proxyAddress", c.proxyAddrPort),
			)
		}

		select {
		case natEntry.proxyConnSendCh <- queuedPacket{packetBufp, frontOverhead, n}:
		default:
			if ce := c.logger.Check(zap.DebugLevel, "swgpPacket dropped due to full send channel"); ce != nil {
				ce.Write(
					zap.String("client", c.name),
					zap.String("wgListen", c.wgListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("proxyAddress", c.proxyAddrPort),
				)
			}
			c.packetBufPool.Put(packetBufp)
		}

		c.mu.Unlock()
	}

	c.logger.Info("Finished receiving from wgConn",
		zap.String("client", c.name),
		zap.String("wgListen", c.wgListen),
		zap.Stringer("proxyAddress", c.proxyAddrPort),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("wgBytesReceived", wgBytesReceived),
	)
}

func (c *client) relayWgToProxyGeneric(clientAddrPort netip.AddrPort, natEntry *clientNatEntry) {
	var (
		packetsSent uint64
		wgBytesSent uint64
	)

	for queuedPacket := range natEntry.proxyConnSendCh {
		packetBuf := *queuedPacket.bufp

		// Update proxyConn read deadline when a handshake initiation/response message is received.
		switch packetBuf[queuedPacket.start] {
		case packet.WireGuardMessageTypeHandshakeInitiation, packet.WireGuardMessageTypeHandshakeResponse:
			if err := natEntry.proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
				c.logger.Warn("Failed to SetReadDeadline on proxyConn",
					zap.String("client", c.name),
					zap.String("wgListen", c.wgListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("proxyAddress", c.proxyAddrPort),
					zap.Error(err),
				)
				c.packetBufPool.Put(queuedPacket.bufp)
				continue
			}
		}

		swgpPacketStart, swgpPacketLength, err := c.handler.EncryptZeroCopy(packetBuf, queuedPacket.start, queuedPacket.length)
		if err != nil {
			c.logger.Warn("Failed to encrypt WireGuard packet",
				zap.String("client", c.name),
				zap.String("wgListen", c.wgListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Error(err),
			)
			c.packetBufPool.Put(queuedPacket.bufp)
			continue
		}
		swgpPacket := packetBuf[swgpPacketStart : swgpPacketStart+swgpPacketLength]

		_, err = natEntry.proxyConn.WriteToUDPAddrPort(swgpPacket, c.proxyAddrPort)
		if err != nil {
			c.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.String("client", c.name),
				zap.String("wgListen", c.wgListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("proxyAddress", c.proxyAddrPort),
				zap.Error(err),
			)
		}

		c.packetBufPool.Put(queuedPacket.bufp)
		packetsSent++
		wgBytesSent += uint64(queuedPacket.length)
	}

	c.logger.Info("Finished relay wgConn -> proxyConn",
		zap.String("client", c.name),
		zap.String("wgListen", c.wgListen),
		zap.Stringer("clientAddress", clientAddrPort),
		zap.Stringer("proxyAddress", c.proxyAddrPort),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (c *client) relayProxyToWgGeneric(clientAddrPort netip.AddrPort, natEntry *clientNatEntry, clientPktinfop *[]byte) {
	var (
		clientPktinfo []byte
		packetsSent   uint64
		wgBytesSent   uint64
	)

	if clientPktinfop != nil {
		clientPktinfo = *clientPktinfop
	}

	packetBuf := make([]byte, c.maxProxyPacketSize)

	for {
		n, _, flags, packetSourceAddrPort, err := natEntry.proxyConn.ReadMsgUDPAddrPort(packetBuf, nil)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			c.logger.Warn("Failed to read from proxyConn",
				zap.String("client", c.name),
				zap.String("wgListen", c.wgListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("proxyAddress", c.proxyAddrPort),
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
				zap.String("wgListen", c.wgListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("proxyAddress", c.proxyAddrPort),
				zap.Stringer("packetSourceAddress", packetSourceAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		if !conn.AddrPortMappedEqual(packetSourceAddrPort, c.proxyAddrPort) {
			c.logger.Warn("Ignoring packet from non-proxy address",
				zap.String("client", c.name),
				zap.String("wgListen", c.wgListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("proxyAddress", c.proxyAddrPort),
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
				zap.String("wgListen", c.wgListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("proxyAddress", c.proxyAddrPort),
				zap.Int("packetLength", n),
				zap.Error(err),
			)
			continue
		}
		wgPacket := packetBuf[wgPacketStart : wgPacketStart+wgPacketLength]

		if cpp := natEntry.clientPktinfo.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp
		}

		_, _, err = c.wgConn.WriteMsgUDPAddrPort(wgPacket, clientPktinfo, clientAddrPort)
		if err != nil {
			c.logger.Warn("Failed to write wgPacket to wgConn",
				zap.String("client", c.name),
				zap.String("wgListen", c.wgListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("proxyAddress", c.proxyAddrPort),
				zap.Error(err),
			)
		}

		packetsSent++
		wgBytesSent += uint64(wgPacketLength)
	}

	c.logger.Info("Finished relay proxyConn -> wgConn",
		zap.String("client", c.name),
		zap.String("wgListen", c.wgListen),
		zap.Stringer("clientAddress", clientAddrPort),
		zap.Stringer("proxyAddress", c.proxyAddrPort),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

// Stop implements the Service Stop method.
func (c *client) Stop() error {
	if c.wgConn == nil {
		return nil
	}

	now := time.Now()

	if err := c.wgConn.SetReadDeadline(now); err != nil {
		return err
	}

	// Wait for serverConn receive goroutines to exit,
	// so there won't be any new sessions added to the table.
	c.mwg.Wait()

	c.mu.Lock()
	for clientAddrPort, entry := range c.table {
		if err := entry.proxyConn.SetReadDeadline(now); err != nil {
			c.logger.Warn("Failed to SetReadDeadline on proxyConn",
				zap.String("client", c.name),
				zap.String("wgListen", c.wgListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("proxyAddress", c.proxyAddrPort),
				zap.Error(err),
			)
		}
	}
	c.mu.Unlock()

	// Wait for all relay goroutines to exit before closing serverConn,
	// so in-flight packets can be written out.
	c.wg.Wait()

	return c.wgConn.Close()
}
