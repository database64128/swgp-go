package service

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
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
	clientPktinfoCache []byte
	proxyConn          *net.UDPConn
	proxyConnSendCh    chan queuedPacket
}

type client struct {
	config  ClientConfig
	logger  *zap.Logger
	handler packet.Handler

	wgConn    *net.UDPConn
	proxyAddr netip.AddrPort

	wgTunnelMTU        int
	maxProxyPacketSize int
	packetBufPool      *sync.Pool

	mu         sync.Mutex
	wg         sync.WaitGroup
	natTimeout time.Duration
	table      map[netip.AddrPort]*clientNatEntry

	relayWgToProxy func(clientAddr netip.AddrPort, natEntry *clientNatEntry)
	relayProxyToWg func(clientAddr netip.AddrPort, natEntry *clientNatEntry)
}

// NewClientService creates a swgp client service from the specified client config.
// Call the Start method on the returned service to start it.
func NewClientService(config ClientConfig, logger *zap.Logger) (Service, error) {
	// Require MTU to be at least 1280.
	if config.MTU < 1280 {
		return nil, ErrMTUTooSmall
	}

	c := &client{
		config:     config,
		logger:     logger,
		natTimeout: RejectAfterTime,
		table:      make(map[netip.AddrPort]*clientNatEntry),
	}
	var err error

	// Create packet handler for user-specified proxy mode.
	c.handler, err = getPacketHandlerForProxyMode(config.ProxyMode, config.ProxyPSK)
	if err != nil {
		return nil, err
	}

	frontOverhead := c.handler.FrontOverhead()
	rearOverhead := c.handler.RearOverhead()
	overhead := frontOverhead + rearOverhead

	// Resolve endpoint address.
	c.proxyAddr, err = conn.ResolveAddrPort(config.ProxyEndpoint)
	if err != nil {
		return nil, err
	}

	// Map to v6 since proxyConn is v6 socket.
	c.proxyAddr = conn.Tov4Mappedv6(c.proxyAddr)

	// maxProxyPacketSize = MTU - IP header length - UDP header length
	if addr := c.proxyAddr.Addr(); addr.Is4() || addr.Is4In6() {
		c.maxProxyPacketSize = config.MTU - IPv4HeaderLength - UDPHeaderLength
	} else {
		c.maxProxyPacketSize = config.MTU - IPv6HeaderLength - UDPHeaderLength
	}

	if c.maxProxyPacketSize <= overhead {
		return nil, fmt.Errorf("max proxy packet size %d must be greater than total overhead %d", c.maxProxyPacketSize, overhead)
	}

	c.wgTunnelMTU = (c.maxProxyPacketSize - overhead - WireGuardDataPacketOverhead) & WireGuardDataPacketLengthMask

	// Initialize packet buffer pool.
	c.packetBufPool = &sync.Pool{
		New: func() any {
			b := make([]byte, c.maxProxyPacketSize)
			return &b
		},
	}

	c.setRelayWgToProxyFunc()
	c.setRelayProxyToWgFunc()
	return c, nil
}

// String implements the Service String method.
func (c *client) String() string {
	return c.config.Name + " swgp client service"
}

// Start implements the Service Start method.
func (c *client) Start() (err error) {
	frontOverhead := c.handler.FrontOverhead()
	rearOverhead := c.handler.RearOverhead()

	var serr error
	c.wgConn, err, serr = conn.ListenUDP("udp", c.config.WgListen, true, c.config.WgFwmark)
	if err != nil {
		return
	}
	if serr != nil {
		c.logger.Warn("An error occurred while setting socket options on listener",
			zap.Stringer("service", c),
			zap.String("wgListen", c.config.WgListen),
			zap.Int("wgFwmark", c.config.WgFwmark),
			zap.NamedError("serr", serr),
		)
	}

	c.wg.Add(1)

	go func() {
		defer c.wg.Done()

		cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)

		for {
			packetBufp := c.packetBufPool.Get().(*[]byte)
			packetBuf := *packetBufp
			plaintextBuf := packetBuf[frontOverhead : c.maxProxyPacketSize-rearOverhead]

			n, cmsgn, flags, clientAddr, err := c.wgConn.ReadMsgUDPAddrPort(plaintextBuf, cmsgBuf)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					c.packetBufPool.Put(packetBufp)
					break
				}
				c.logger.Warn("Failed to read from wgConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Error(err),
				)
				c.packetBufPool.Put(packetBufp)
				continue
			}
			err = conn.ParseFlagsForError(flags)
			if err != nil {
				c.logger.Warn("Failed to read from wgConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Error(err),
				)
				c.packetBufPool.Put(packetBufp)
				continue
			}

			c.mu.Lock()

			natEntry := c.table[clientAddr]
			if natEntry == nil {
				proxyConn, err, serr := conn.ListenUDP("udp", "", false, c.config.ProxyFwmark)
				if err != nil {
					c.logger.Warn("Failed to start UDP listener for new UDP session",
						zap.Stringer("service", c),
						zap.String("wgListen", c.config.WgListen),
						zap.Stringer("clientAddress", clientAddr),
						zap.Error(err),
					)
					c.packetBufPool.Put(packetBufp)
					c.mu.Unlock()
					continue
				}
				if serr != nil {
					c.logger.Warn("An error occurred while setting socket options on proxyConn",
						zap.Stringer("service", c),
						zap.String("wgListen", c.config.WgListen),
						zap.Stringer("clientAddress", clientAddr),
						zap.Int("proxyFwmark", c.config.ProxyFwmark),
						zap.NamedError("serr", serr),
					)
				}

				err = proxyConn.SetReadDeadline(time.Now().Add(c.natTimeout))
				if err != nil {
					c.logger.Warn("Failed to SetReadDeadline on proxyConn",
						zap.Stringer("service", c),
						zap.String("wgListen", c.config.WgListen),
						zap.Stringer("clientAddress", clientAddr),
						zap.Stringer("proxyAddress", c.proxyAddr),
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

				c.table[clientAddr] = natEntry

				c.wg.Add(2)

				go func() {
					c.relayProxyToWg(clientAddr, natEntry)

					c.mu.Lock()
					close(natEntry.proxyConnSendCh)
					delete(c.table, clientAddr)
					c.mu.Unlock()

					c.wg.Done()
				}()

				go func() {
					c.relayWgToProxy(clientAddr, natEntry)
					natEntry.proxyConn.Close()
					c.wg.Done()
				}()

				c.logger.Info("New UDP session",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
				)
			} else {
				// Update proxyConn read deadline when a handshake initiation/response message is received.
				switch plaintextBuf[0] {
				case packet.WireGuardMessageTypeHandshakeInitiation, packet.WireGuardMessageTypeHandshakeResponse:
					err = natEntry.proxyConn.SetReadDeadline(time.Now().Add(c.natTimeout))
					if err != nil {
						c.logger.Warn("Failed to SetReadDeadline on proxyConn",
							zap.Stringer("service", c),
							zap.String("wgListen", c.config.WgListen),
							zap.Stringer("clientAddress", clientAddr),
							zap.Stringer("proxyAddress", c.proxyAddr),
							zap.Error(err),
						)
						c.packetBufPool.Put(packetBufp)
						c.mu.Unlock()
						continue
					}
				}
			}

			natEntry.clientPktinfoCache, err = conn.UpdatePktinfoCache(natEntry.clientPktinfoCache, cmsgBuf[:cmsgn], c.logger)
			if err != nil {
				c.logger.Warn("Failed to process socket control messages from wgConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Error(err),
				)
			}

			select {
			case natEntry.proxyConnSendCh <- queuedPacket{packetBufp, frontOverhead, n}:
			default:
				c.logger.Debug("swgpPacket dropped due to full send channel",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
				)
				c.packetBufPool.Put(packetBufp)
			}

			c.mu.Unlock()
		}
	}()

	c.logger.Info("Started service",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.String("proxyEndpoint", c.config.ProxyEndpoint),
		zap.String("proxyMode", c.config.ProxyMode),
		zap.Int("wgTunnelMTU", c.wgTunnelMTU),
	)
	return
}

func (c *client) relayWgToProxyGeneric(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	var (
		packetsSent uint64
		wgBytesSent uint64
	)

	for queuedPacket := range natEntry.proxyConnSendCh {
		packetBuf := *queuedPacket.bufp

		swgpPacketStart, swgpPacketLength, err := c.handler.EncryptZeroCopy(packetBuf, queuedPacket.start, queuedPacket.length)
		if err != nil {
			c.logger.Warn("Failed to encrypt WireGuard packet",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Error(err),
			)
			c.packetBufPool.Put(queuedPacket.bufp)
			continue
		}
		swgpPacket := packetBuf[swgpPacketStart : swgpPacketStart+swgpPacketLength]

		_, err = natEntry.proxyConn.WriteToUDPAddrPort(swgpPacket, c.proxyAddr)
		if err != nil {
			c.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}

		c.packetBufPool.Put(queuedPacket.bufp)
		packetsSent++
		wgBytesSent += uint64(queuedPacket.length)
	}

	c.logger.Info("Finished relay wgConn -> proxyConn",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("proxyAddress", c.proxyAddr),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (c *client) relayProxyToWgGeneric(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	var (
		packetsSent uint64
		wgBytesSent uint64
	)

	packetBuf := make([]byte, c.maxProxyPacketSize)

	for {
		n, _, flags, raddr, err := natEntry.proxyConn.ReadMsgUDPAddrPort(packetBuf, nil)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			c.logger.Warn("Failed to read from proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			c.logger.Warn("Failed to read from proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
			continue
		}
		if raddr != c.proxyAddr {
			c.logger.Debug("Ignoring packet from non-proxy address",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Stringer("raddr", raddr),
				zap.Error(err),
			)
			continue
		}

		wgPacketStart, wgPacketLength, err := c.handler.DecryptZeroCopy(packetBuf, 0, n)
		if err != nil {
			c.logger.Warn("Failed to decrypt swgpPacket",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
			continue
		}
		wgPacket := packetBuf[wgPacketStart : wgPacketStart+wgPacketLength]

		_, _, err = c.wgConn.WriteMsgUDPAddrPort(wgPacket, natEntry.clientPktinfoCache, clientAddr)
		if err != nil {
			c.logger.Warn("Failed to write wgPacket to wgConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}

		packetsSent++
		wgBytesSent += uint64(wgPacketLength)
	}

	c.logger.Info("Finished relay proxyConn -> wgConn",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("proxyAddress", c.proxyAddr),
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

	c.natTimeout = 0

	c.mu.Lock()
	for clientAddr, entry := range c.table {
		if err := entry.proxyConn.SetReadDeadline(now); err != nil {
			c.logger.Warn("Failed to SetReadDeadline on proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}
	}
	c.mu.Unlock()

	c.wg.Wait()
	return c.wgConn.Close()
}
