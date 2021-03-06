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

// ServerConfig stores configurations for a swgp server service.
// It may be marshaled as or unmarshaled from JSON.
type ServerConfig struct {
	Name        string `json:"name"`
	ProxyListen string `json:"proxyListen"`
	ProxyMode   string `json:"proxyMode"`
	ProxyPSK    []byte `json:"proxyPSK"`
	ProxyFwmark int    `json:"proxyFwmark"`
	WgEndpoint  string `json:"wgEndpoint"`
	WgFwmark    int    `json:"wgFwmark"`
	MTU         int    `json:"mtu"`
	BatchMode   string `json:"batchMode"`
}

type serverNatEntry struct {
	clientOobCache     []byte
	wgConn             *net.UDPConn
	wgConnSendCh       chan queuedPacket
	maxProxyPacketSize int
}

type server struct {
	config  ServerConfig
	logger  *zap.Logger
	handler packet.Handler

	proxyConn     *net.UDPConn
	wgAddr        netip.AddrPort
	wgTunnelMTUv4 int
	wgTunnelMTUv6 int

	packetBufPool *sync.Pool

	mu    sync.Mutex
	wg    sync.WaitGroup
	table map[netip.AddrPort]*serverNatEntry

	relayProxyToWg func(clientAddr netip.AddrPort, natEntry *serverNatEntry)
	relayWgToProxy func(clientAddr netip.AddrPort, natEntry *serverNatEntry)
}

// NewServerService creates a swgp server service from the specified server config.
// Call the Start method on the returned service to start it.
func NewServerService(config ServerConfig, logger *zap.Logger) (Service, error) {
	// Require MTU to be at least 1280.
	if config.MTU < 1280 {
		return nil, ErrMTUTooSmall
	}

	s := &server{
		config: config,
		logger: logger,
		table:  make(map[netip.AddrPort]*serverNatEntry),
	}
	var err error

	// Create packet handler for user-specified proxy mode.
	s.handler, err = getPacketHandlerForProxyMode(config.ProxyMode, config.ProxyPSK)
	if err != nil {
		return nil, err
	}

	frontOverhead := s.handler.FrontOverhead()
	rearOverhead := s.handler.RearOverhead()
	overhead := frontOverhead + rearOverhead

	s.wgTunnelMTUv4 = (config.MTU - IPv4HeaderLength - UDPHeaderLength - overhead - WireGuardDataPacketOverhead) & WireGuardDataPacketLengthMask
	s.wgTunnelMTUv6 = (config.MTU - IPv6HeaderLength - UDPHeaderLength - overhead - WireGuardDataPacketOverhead) & WireGuardDataPacketLengthMask

	// packetBufSize = MTU - IPv4 header length - UDP header length
	packetBufSize := config.MTU - IPv4HeaderLength - UDPHeaderLength
	if packetBufSize <= overhead {
		return nil, fmt.Errorf("packet buf size %d must be greater than total overhead %d", packetBufSize, overhead)
	}

	// Initialize packet buffer pool.
	s.packetBufPool = &sync.Pool{
		New: func() any {
			b := make([]byte, packetBufSize)
			return &b
		},
	}

	// Resolve endpoint address.
	s.wgAddr, err = netip.ParseAddrPort(config.WgEndpoint)
	if err != nil {
		rudpaddr, err := net.ResolveUDPAddr("udp", config.WgEndpoint)
		if err != nil {
			return nil, err
		}
		s.wgAddr = rudpaddr.AddrPort()
	}

	// Workaround for https://github.com/golang/go/issues/52264
	s.wgAddr = conn.Tov4Mappedv6(s.wgAddr)

	s.setRelayProxyToWgFunc()
	s.setRelayWgToProxyFunc()
	return s, nil
}

// String implements the Service String method.
func (s *server) String() string {
	return s.config.Name + " swgp server service"
}

// Start implements the Service Start method.
func (s *server) Start() (err error) {
	// Start listener.
	var serr error
	s.proxyConn, err, serr = conn.ListenUDP("udp", s.config.ProxyListen, true, s.config.ProxyFwmark)
	if err != nil {
		return
	}
	if serr != nil {
		s.logger.Warn("An error occurred while setting socket options on listener",
			zap.Stringer("service", s),
			zap.String("proxyListen", s.config.ProxyListen),
			zap.Int("proxyFwmark", s.config.ProxyFwmark),
			zap.NamedError("serr", serr),
		)
	}

	// Main loop.
	go func() {
		oobBuf := make([]byte, conn.UDPOOBBufferSize)

		for {
			packetBufp := s.packetBufPool.Get().(*[]byte)
			packetBuf := *packetBufp

			n, oobn, flags, clientAddr, err := s.proxyConn.ReadMsgUDPAddrPort(packetBuf, oobBuf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					s.packetBufPool.Put(packetBufp)
					break
				}
				s.logger.Warn("Failed to read from proxyConn",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Error(err),
				)
				s.packetBufPool.Put(packetBufp)
				continue
			}
			err = conn.ParseFlagsForError(flags)
			if err != nil {
				s.logger.Warn("Failed to read from proxyConn",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Error(err),
				)
				s.packetBufPool.Put(packetBufp)
				continue
			}

			wgPacketStart, wgPacketLength, err := s.handler.DecryptZeroCopy(packetBuf, 0, n)
			if err != nil {
				s.logger.Warn("Failed to decrypt swgpPacket",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Error(err),
				)
				s.packetBufPool.Put(packetBufp)
				continue
			}

			s.mu.Lock()

			natEntry := s.table[clientAddr]
			if natEntry == nil {
				wgConn, err, serr := conn.ListenUDP("udp", "", false, s.config.WgFwmark)
				if err != nil {
					s.logger.Warn("Failed to start UDP listener for new UDP session",
						zap.Stringer("service", s),
						zap.String("proxyListen", s.config.ProxyListen),
						zap.Stringer("clientAddress", clientAddr),
						zap.Error(err),
					)
					s.packetBufPool.Put(packetBufp)
					s.mu.Unlock()
					continue
				}
				if serr != nil {
					s.logger.Warn("An error occurred while setting socket options on wgConn",
						zap.Stringer("service", s),
						zap.String("proxyListen", s.config.ProxyListen),
						zap.Stringer("clientAddress", clientAddr),
						zap.Int("wgFwmark", s.config.WgFwmark),
						zap.NamedError("serr", serr),
					)
				}

				err = wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
				if err != nil {
					s.logger.Warn("Failed to SetReadDeadline on wgConn",
						zap.Stringer("service", s),
						zap.String("proxyListen", s.config.ProxyListen),
						zap.Stringer("clientAddress", clientAddr),
						zap.Stringer("wgAddress", s.wgAddr),
						zap.Error(err),
					)
					s.packetBufPool.Put(packetBufp)
					s.mu.Unlock()
					continue
				}

				var wgTunnelMTU int

				natEntry = &serverNatEntry{
					wgConn:       wgConn,
					wgConnSendCh: make(chan queuedPacket, sendChannelCapacity),
				}

				if addr := clientAddr.Addr(); addr.Is4() || addr.Is4In6() {
					natEntry.maxProxyPacketSize = s.config.MTU - IPv4HeaderLength - UDPHeaderLength
					wgTunnelMTU = s.wgTunnelMTUv4
				} else {
					natEntry.maxProxyPacketSize = s.config.MTU - IPv6HeaderLength - UDPHeaderLength
					wgTunnelMTU = s.wgTunnelMTUv6
				}

				s.table[clientAddr] = natEntry

				s.wg.Add(2)

				go func() {
					s.relayWgToProxy(clientAddr, natEntry)

					s.mu.Lock()
					close(natEntry.wgConnSendCh)
					delete(s.table, clientAddr)
					s.mu.Unlock()

					s.wg.Done()
				}()

				go func() {
					s.relayProxyToWg(clientAddr, natEntry)
					natEntry.wgConn.Close()
					s.wg.Done()
				}()

				s.logger.Info("New UDP session",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("wgAddress", s.wgAddr),
					zap.Int("wgTunnelMTU", wgTunnelMTU),
				)
			} else {
				// Update wgConn read deadline when a handshake initiation/response message is received.
				switch packetBuf[wgPacketStart] {
				case packet.WireGuardMessageTypeHandshakeInitiation, packet.WireGuardMessageTypeHandshakeResponse:
					err = natEntry.wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
					if err != nil {
						s.logger.Warn("Failed to SetReadDeadline on wgConn",
							zap.Stringer("service", s),
							zap.String("proxyListen", s.config.ProxyListen),
							zap.Stringer("clientAddress", clientAddr),
							zap.Stringer("wgAddress", s.wgAddr),
							zap.Error(err),
						)
						s.packetBufPool.Put(packetBufp)
						s.mu.Unlock()
						continue
					}
				}
			}

			oob := oobBuf[:oobn]
			natEntry.clientOobCache, err = conn.UpdateOobCache(natEntry.clientOobCache, oob, s.logger)
			if err != nil {
				s.logger.Warn("Failed to process OOB from proxyConn",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Error(err),
				)
			}

			select {
			case natEntry.wgConnSendCh <- queuedPacket{packetBufp, wgPacketStart, wgPacketLength}:
			default:
				s.logger.Debug("wgPacket dropped due to full send channel",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("wgAddress", s.wgAddr),
				)
				s.packetBufPool.Put(packetBufp)
			}

			s.mu.Unlock()
		}
	}()

	s.logger.Info("Started service",
		zap.Stringer("service", s),
		zap.String("proxyListen", s.config.ProxyListen),
		zap.String("proxyMode", s.config.ProxyMode),
		zap.String("wgEndpoint", s.config.WgEndpoint),
		zap.Int("wgTunnelMTUv4", s.wgTunnelMTUv4),
		zap.Int("wgTunnelMTUv6", s.wgTunnelMTUv6),
	)
	return
}

func (s *server) relayProxyToWgGeneric(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	var (
		packetsSent uint64
		wgBytesSent uint64
	)

	for {
		queuedPacket, ok := <-natEntry.wgConnSendCh
		if !ok {
			break
		}
		packetBuf := *queuedPacket.bufp
		wgPacket := packetBuf[queuedPacket.start : queuedPacket.start+queuedPacket.length]

		_, err := natEntry.wgConn.WriteToUDPAddrPort(wgPacket, s.wgAddr)
		if err != nil {
			s.logger.Warn("Failed to write wgPacket to wgConn",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("wgAddress", s.wgAddr),
				zap.Error(err),
			)
		}

		s.packetBufPool.Put(queuedPacket.bufp)
		packetsSent++
		wgBytesSent += uint64(queuedPacket.length)
	}

	s.logger.Info("Finished relay proxyConn -> wgConn",
		zap.Stringer("service", s),
		zap.String("proxyListen", s.config.ProxyListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("wgAddress", s.wgAddr),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (s *server) relayWgToProxyGeneric(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	var (
		packetsSent uint64
		wgBytesSent uint64
	)

	packetBuf := make([]byte, natEntry.maxProxyPacketSize)

	frontOverhead := s.handler.FrontOverhead()
	rearOverhead := s.handler.RearOverhead()
	plaintextBuf := packetBuf[frontOverhead : natEntry.maxProxyPacketSize-rearOverhead]

	for {
		n, _, flags, raddr, err := natEntry.wgConn.ReadMsgUDPAddrPort(plaintextBuf, nil)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			s.logger.Warn("Failed to read from wgConn",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("wgAddress", s.wgAddr),
				zap.Error(err),
			)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			s.logger.Warn("Failed to read from wgConn",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("wgAddress", s.wgAddr),
				zap.Error(err),
			)
			continue
		}
		if raddr != s.wgAddr {
			s.logger.Debug("Ignoring packet from non-wg address",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("wgAddress", s.wgAddr),
				zap.Stringer("raddr", raddr),
				zap.Error(err),
			)
			continue
		}

		swgpPacketStart, swgpPacketLength, err := s.handler.EncryptZeroCopy(packetBuf, frontOverhead, n)
		if err != nil {
			s.logger.Warn("Failed to encrypt WireGuard packet",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("wgAddress", s.wgAddr),
				zap.Error(err),
			)
			continue
		}
		swgpPacket := packetBuf[swgpPacketStart : swgpPacketStart+swgpPacketLength]

		_, _, err = s.proxyConn.WriteMsgUDPAddrPort(swgpPacket, natEntry.clientOobCache, clientAddr)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			s.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("wgAddress", s.wgAddr),
				zap.Error(err),
			)
		}

		packetsSent++
		wgBytesSent += uint64(n)
	}

	s.logger.Info("Finished relay wgConn -> proxyConn",
		zap.Stringer("service", s),
		zap.String("proxyListen", s.config.ProxyListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("wgAddress", s.wgAddr),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

// Stop implements the Service Stop method.
func (s *server) Stop() error {
	if s.proxyConn == nil {
		return nil
	}

	s.proxyConn.Close()

	s.mu.Lock()
	now := time.Now()
	for clientAddr, entry := range s.table {
		if err := entry.wgConn.SetReadDeadline(now); err != nil {
			s.logger.Warn("Failed to SetReadDeadline on wgConn",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("wgAddress", s.wgAddr),
				zap.Error(err),
			)
		}
	}
	s.mu.Unlock()

	s.wg.Wait()

	return nil
}
