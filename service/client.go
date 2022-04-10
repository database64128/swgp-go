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
}

type clientNatEntry struct {
	clientOobCache    []byte
	proxyConn         *net.UDPConn
	proxyConnOobCache []byte
}

type client struct {
	config  ClientConfig
	logger  *zap.Logger
	handler packet.Handler

	wgConn    *net.UDPConn
	proxyAddr netip.AddrPort

	maxProxyPacketSize int

	mu    sync.RWMutex
	table map[netip.AddrPort]*clientNatEntry
}

// NewClientService creates a swgp client service from the specified client config.
// Call the Start method on the returned service to start it.
func NewClientService(config ClientConfig, logger *zap.Logger) Service {
	return &client{
		config: config,
		logger: logger,
		table:  make(map[netip.AddrPort]*clientNatEntry),
	}
}

// String implements the Service String method.
func (c *client) String() string {
	return c.config.Name + " swgp client service"
}

// Start implements the Service Start method.
func (c *client) Start() (err error) {
	// Require MTU to be at least 1280.
	if c.config.MTU < 1280 {
		return ErrMTUTooSmall
	}

	// Create packet handler for user-specified proxy mode.
	c.handler, err = getPacketHandlerForProxyMode(c.config.ProxyMode, c.config.ProxyPSK)
	if err != nil {
		return
	}

	frontOverhead := c.handler.FrontOverhead()
	rearOverhead := c.handler.RearOverhead()
	overhead := frontOverhead + rearOverhead

	// Resolve endpoint address.
	c.proxyAddr, err = netip.ParseAddrPort(c.config.ProxyEndpoint)
	if err != nil {
		rudpaddr, err := net.ResolveUDPAddr("udp", c.config.ProxyEndpoint)
		if err != nil {
			return err
		}
		c.proxyAddr = rudpaddr.AddrPort()
	}

	// Workaround for https://github.com/golang/go/issues/52264
	if c.proxyAddr.Addr().Is4() {
		addr6 := c.proxyAddr.Addr().As16()
		ip := netip.AddrFrom16(addr6)
		port := c.proxyAddr.Port()
		c.proxyAddr = netip.AddrPortFrom(ip, port)
	}

	// maxProxyPacketSize = MTU - IP header length - UDP header length
	if c.proxyAddr.Addr().Is4() {
		c.maxProxyPacketSize = c.config.MTU - IPv4HeaderLength - UDPHeaderLength
	} else {
		c.maxProxyPacketSize = c.config.MTU - IPv6HeaderLength - UDPHeaderLength
	}

	if c.maxProxyPacketSize <= overhead {
		return fmt.Errorf("max proxy packet size %d must be greater than total overhead %d", c.maxProxyPacketSize, overhead)
	}

	// Start listener.
	var serr error
	c.wgConn, err, serr = conn.ListenUDP("udp", c.config.WgListen, c.config.WgFwmark)
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

	// Main loop.
	go func() {
		defer c.wgConn.Close()

		packetBuf := make([]byte, c.maxProxyPacketSize)
		plaintextBuf := packetBuf[frontOverhead : c.maxProxyPacketSize-rearOverhead]
		oobBuf := make([]byte, conn.UDPOOBBufferSize)

		for {
			n, oobn, flags, clientAddr, err := c.wgConn.ReadMsgUDPAddrPort(plaintextBuf, oobBuf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break
				}
				c.logger.Warn("Failed to read from wgConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Error(err),
				)
				continue
			}
			err = conn.ParseFlagsForError(flags)
			if err != nil {
				c.logger.Warn("Failed to read from wgConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Error(err),
				)
				continue
			}

			c.mu.RLock()
			natEntry := c.table[clientAddr]
			c.mu.RUnlock()

			if natEntry == nil {
				proxyConn, err, serr := conn.ListenUDP("udp", "", c.config.ProxyFwmark)
				if err != nil {
					c.logger.Warn("Failed to start UDP listener for new UDP session",
						zap.Stringer("service", c),
						zap.String("wgListen", c.config.WgListen),
						zap.Stringer("clientAddress", clientAddr),
						zap.Error(err),
					)
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

				err = proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
				if err != nil {
					c.logger.Warn("Failed to SetReadDeadline on proxyConn",
						zap.Stringer("service", c),
						zap.String("wgListen", c.config.WgListen),
						zap.Stringer("clientAddress", clientAddr),
						zap.Stringer("proxyAddress", c.proxyAddr),
						zap.Error(err),
					)
					continue
				}

				natEntry = &clientNatEntry{
					proxyConn: proxyConn,
				}

				c.mu.Lock()
				c.table[clientAddr] = natEntry
				c.mu.Unlock()

				go func() {
					c.relayProxyToWg(clientAddr, natEntry)

					c.mu.Lock()
					delete(c.table, clientAddr)
					c.mu.Unlock()
				}()

				c.logger.Info("New UDP session",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
				)
			} else {
				c.logger.Debug("Found existing UDP session in NAT table",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
				)

				// Update proxyConn read deadline when a handshake initiation message is received.
				if plaintextBuf[0] == packet.WireGuardMessageTypeHandshakeInitiation {
					err = natEntry.proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
					if err != nil {
						c.logger.Warn("Failed to SetReadDeadline on proxyConn",
							zap.Stringer("service", c),
							zap.String("wgListen", c.config.WgListen),
							zap.Stringer("clientAddress", clientAddr),
							zap.Stringer("proxyAddress", c.proxyAddr),
							zap.Error(err),
						)
						continue
					}
				}
			}

			oob := oobBuf[:oobn]
			natEntry.clientOobCache, err = conn.UpdateOobCache(natEntry.clientOobCache, oob, c.logger)
			if err != nil {
				c.logger.Debug("Failed to process OOB from wgConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Error(err),
				)
			}

			swgpPacket, err := c.handler.EncryptZeroCopy(packetBuf, frontOverhead, n, c.maxProxyPacketSize)
			if err != nil {
				c.logger.Warn("Failed to encrypt WireGuard packet",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Error(err),
				)
				continue
			}

			_, _, err = natEntry.proxyConn.WriteMsgUDPAddrPort(swgpPacket, natEntry.proxyConnOobCache, c.proxyAddr)
			if err != nil {
				c.logger.Warn("Failed to write swgpPacket to proxyConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
			}
		}
	}()

	c.logger.Info("Started service",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.String("proxyEndpoint", c.config.ProxyEndpoint),
		zap.String("proxyMode", c.config.ProxyMode),
		zap.Int("wgTunnelMTU", (c.maxProxyPacketSize-overhead-WireGuardDataPacketOverhead)&WireGuardDataPacketLengthMask),
	)
	return
}

func (c *client) relayProxyToWg(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	defer natEntry.proxyConn.Close()

	packetBuf := make([]byte, c.maxProxyPacketSize)
	oobBuf := make([]byte, conn.UDPOOBBufferSize)

	for {
		n, oobn, flags, raddr, err := natEntry.proxyConn.ReadMsgUDPAddrPort(packetBuf, oobBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return
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

		swgpPacket := packetBuf[:n]
		wgPacket, err := c.handler.DecryptZeroCopy(swgpPacket)
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

		oob := oobBuf[:oobn]
		natEntry.proxyConnOobCache, err = conn.UpdateOobCache(natEntry.proxyConnOobCache, oob, c.logger)
		if err != nil {
			c.logger.Debug("Failed to process OOB from proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}

		_, _, err = c.wgConn.WriteMsgUDPAddrPort(wgPacket, natEntry.clientOobCache, clientAddr)
		if err != nil {
			c.logger.Warn("Failed to write wgPacket to wgConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}
	}
}

// Stop implements the Service Stop method.
func (c *client) Stop() error {
	if c.wgConn != nil {
		return c.wgConn.Close()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

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

	return nil
}
