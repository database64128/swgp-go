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
	clientPktinfo      atomic.Pointer[[]byte]
	clientPktinfoCache []byte
	wgConn             *net.UDPConn
	wgConnSendCh       chan queuedPacket
	maxProxyPacketSize int
}

type server struct {
	name                 string
	proxyListen          string
	proxyFwmark          int
	wgFwmark             int
	maxProxyPacketSizev4 int
	maxProxyPacketSizev6 int
	wgTunnelMTUv4        int
	wgTunnelMTUv6        int
	wgAddrPort           netip.AddrPort
	handler              packet.Handler
	logger               *zap.Logger
	proxyConn            *net.UDPConn
	packetBufPool        sync.Pool
	mu                   sync.Mutex
	wg                   sync.WaitGroup
	mwg                  sync.WaitGroup
	table                map[netip.AddrPort]*serverNatEntry
	recvFromProxyConn    func()
}

// NewServerService creates a swgp server service from the specified server config.
// Call the Start method on the returned service to start it.
func NewServerService(config ServerConfig, logger *zap.Logger) (Service, error) {
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
	wgAddrPort, err := conn.ResolveAddrPort(config.WgEndpoint)
	if err != nil {
		return nil, err
	}

	// maxProxyPacketSize = MTU - IP header length - UDP header length
	maxProxyPacketSizev4 := config.MTU - IPv4HeaderLength - UDPHeaderLength
	maxProxyPacketSizev6 := config.MTU - IPv6HeaderLength - UDPHeaderLength

	frontOverhead := handler.FrontOverhead()
	rearOverhead := handler.RearOverhead()
	overhead := frontOverhead + rearOverhead

	wgTunnelMTUv4 := (maxProxyPacketSizev4 - overhead - WireGuardDataPacketOverhead) & WireGuardDataPacketLengthMask
	wgTunnelMTUv6 := (maxProxyPacketSizev6 - overhead - WireGuardDataPacketOverhead) & WireGuardDataPacketLengthMask

	s := server{
		name:                 config.Name,
		proxyListen:          config.ProxyListen,
		proxyFwmark:          config.ProxyFwmark,
		wgFwmark:             config.WgFwmark,
		maxProxyPacketSizev4: maxProxyPacketSizev4,
		maxProxyPacketSizev6: maxProxyPacketSizev6,
		wgTunnelMTUv4:        wgTunnelMTUv4,
		wgTunnelMTUv6:        wgTunnelMTUv6,
		wgAddrPort:           wgAddrPort,
		handler:              handler,
		logger:               logger,
		table:                make(map[netip.AddrPort]*serverNatEntry),
	}
	s.packetBufPool.New = func() any {
		b := make([]byte, maxProxyPacketSizev4)
		return &b
	}
	s.setRelayFunc(config.BatchMode)
	return &s, nil
}

// String implements the Service String method.
func (s *server) String() string {
	return s.name + " swgp server service"
}

// Start implements the Service Start method.
func (s *server) Start() (err error) {
	s.proxyConn, err = conn.ListenUDP("udp", s.proxyListen, true, s.proxyFwmark)
	if err != nil {
		return
	}

	s.mwg.Add(1)

	go func() {
		s.recvFromProxyConn()
		s.mwg.Done()
	}()

	s.logger.Info("Started service",
		zap.String("server", s.name),
		zap.String("proxyListen", s.proxyListen),
		zap.Stringer("wgAddress", s.wgAddrPort),
		zap.Int("wgTunnelMTUv4", s.wgTunnelMTUv4),
		zap.Int("wgTunnelMTUv6", s.wgTunnelMTUv6),
	)
	return
}

func (s *server) recvFromProxyConnGeneric() {
	cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)

	var (
		packetsReceived uint64
		wgBytesReceived uint64
	)

	for {
		packetBufp := s.packetBufPool.Get().(*[]byte)
		packetBuf := *packetBufp

		n, cmsgn, flags, clientAddrPort, err := s.proxyConn.ReadMsgUDPAddrPort(packetBuf, cmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				s.packetBufPool.Put(packetBufp)
				break
			}
			s.logger.Warn("Failed to read from proxyConn",
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Error(err),
			)
			s.packetBufPool.Put(packetBufp)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			s.logger.Warn("Failed to read from proxyConn",
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Error(err),
			)
			s.packetBufPool.Put(packetBufp)
			continue
		}
		cmsg := cmsgBuf[:cmsgn]

		wgPacketStart, wgPacketLength, err := s.handler.DecryptZeroCopy(packetBuf, 0, n)
		if err != nil {
			s.logger.Warn("Failed to decrypt swgpPacket",
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Error(err),
			)
			s.packetBufPool.Put(packetBufp)
			continue
		}

		packetsReceived++
		wgBytesReceived += uint64(wgPacketLength)

		var wgTunnelMTU int

		s.mu.Lock()

		natEntry, ok := s.table[clientAddrPort]
		if !ok {
			wgConn, err := conn.ListenUDP("udp", "", false, s.wgFwmark)
			if err != nil {
				s.logger.Warn("Failed to start UDP listener for new UDP session",
					zap.String("server", s.name),
					zap.String("proxyListen", s.proxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Error(err),
				)
				s.packetBufPool.Put(packetBufp)
				s.mu.Unlock()
				continue
			}

			err = wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
			if err != nil {
				s.logger.Warn("Failed to SetReadDeadline on wgConn",
					zap.String("server", s.name),
					zap.String("proxyListen", s.proxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("wgAddress", s.wgAddrPort),
					zap.Error(err),
				)
				s.packetBufPool.Put(packetBufp)
				s.mu.Unlock()
				continue
			}

			natEntry = &serverNatEntry{
				wgConn:       wgConn,
				wgConnSendCh: make(chan queuedPacket, sendChannelCapacity),
			}

			if addr := clientAddrPort.Addr(); addr.Is4() || addr.Is4In6() {
				natEntry.maxProxyPacketSize = s.maxProxyPacketSizev4
				wgTunnelMTU = s.wgTunnelMTUv4
			} else {
				natEntry.maxProxyPacketSize = s.maxProxyPacketSizev6
				wgTunnelMTU = s.wgTunnelMTUv6
			}

			s.table[clientAddrPort] = natEntry
		}

		var clientPktinfop *[]byte

		if !bytes.Equal(natEntry.clientPktinfoCache, cmsg) {
			clientPktinfoAddr, clientPktinfoIfindex, err := conn.ParsePktinfoCmsg(cmsg)
			if err != nil {
				s.logger.Warn("Failed to parse pktinfo control message from proxyConn",
					zap.String("server", s.name),
					zap.String("proxyListen", s.proxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Error(err),
				)
				s.packetBufPool.Put(packetBufp)
				s.mu.Unlock()
				continue
			}

			clientPktinfoCache := make([]byte, len(cmsg))
			copy(clientPktinfoCache, cmsg)
			clientPktinfop = &clientPktinfoCache
			natEntry.clientPktinfo.Store(clientPktinfop)
			natEntry.clientPktinfoCache = clientPktinfoCache

			s.logger.Debug("Updated client pktinfo",
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
				zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
			)
		}

		if !ok {
			s.wg.Add(2)

			go func() {
				s.relayWgToProxyGeneric(clientAddrPort, natEntry, clientPktinfop)

				s.mu.Lock()
				close(natEntry.wgConnSendCh)
				delete(s.table, clientAddrPort)
				s.mu.Unlock()

				s.wg.Done()
			}()

			go func() {
				s.relayProxyToWgGeneric(clientAddrPort, natEntry)
				natEntry.wgConn.Close()
				s.wg.Done()
			}()

			s.logger.Info("New UDP session",
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("wgAddress", s.wgAddrPort),
				zap.Int("wgTunnelMTU", wgTunnelMTU),
			)
		}

		select {
		case natEntry.wgConnSendCh <- queuedPacket{packetBufp, wgPacketStart, wgPacketLength}:
		default:
			s.logger.Debug("wgPacket dropped due to full send channel",
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("wgAddress", s.wgAddrPort),
			)
			s.packetBufPool.Put(packetBufp)
		}

		s.mu.Unlock()
	}

	s.logger.Info("Finished receiving from proxyConn",
		zap.String("server", s.name),
		zap.String("proxyListen", s.proxyListen),
		zap.Stringer("wgAddress", s.wgAddrPort),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("wgBytesReceived", wgBytesReceived),
	)
}

func (s *server) relayProxyToWgGeneric(clientAddrPort netip.AddrPort, natEntry *serverNatEntry) {
	var (
		packetsSent uint64
		wgBytesSent uint64
	)

	for queuedPacket := range natEntry.wgConnSendCh {
		packetBuf := *queuedPacket.bufp
		wgPacket := packetBuf[queuedPacket.start : queuedPacket.start+queuedPacket.length]

		if _, err := natEntry.wgConn.WriteToUDPAddrPort(wgPacket, s.wgAddrPort); err != nil {
			s.logger.Warn("Failed to write wgPacket to wgConn",
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("wgAddress", s.wgAddrPort),
				zap.Error(err),
			)
		}

		// Update wgConn read deadline when a handshake initiation/response message is received.
		switch wgPacket[0] {
		case packet.WireGuardMessageTypeHandshakeInitiation, packet.WireGuardMessageTypeHandshakeResponse:
			if err := natEntry.wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
				s.logger.Warn("Failed to SetReadDeadline on wgConn",
					zap.String("server", s.name),
					zap.String("proxyListen", s.proxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("wgAddress", s.wgAddrPort),
					zap.Error(err),
				)
			}
		}

		s.packetBufPool.Put(queuedPacket.bufp)
		packetsSent++
		wgBytesSent += uint64(queuedPacket.length)
	}

	s.logger.Info("Finished relay proxyConn -> wgConn",
		zap.String("server", s.name),
		zap.String("proxyListen", s.proxyListen),
		zap.Stringer("clientAddress", clientAddrPort),
		zap.Stringer("wgAddress", s.wgAddrPort),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (s *server) relayWgToProxyGeneric(clientAddrPort netip.AddrPort, natEntry *serverNatEntry, clientPktinfop *[]byte) {
	var (
		clientPktinfo []byte
		packetsSent   uint64
		wgBytesSent   uint64
	)

	if clientPktinfop != nil {
		clientPktinfo = *clientPktinfop
	}

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
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("wgAddress", s.wgAddrPort),
				zap.Error(err),
			)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			s.logger.Warn("Failed to read from wgConn",
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("wgAddress", s.wgAddrPort),
				zap.Error(err),
			)
			continue
		}
		if !conn.AddrPortMappedEqual(raddr, s.wgAddrPort) {
			s.logger.Debug("Ignoring packet from non-wg address",
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("wgAddress", s.wgAddrPort),
				zap.Stringer("raddr", raddr),
				zap.Error(err),
			)
			continue
		}

		swgpPacketStart, swgpPacketLength, err := s.handler.EncryptZeroCopy(packetBuf, frontOverhead, n)
		if err != nil {
			s.logger.Warn("Failed to encrypt WireGuard packet",
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("wgAddress", s.wgAddrPort),
				zap.Error(err),
			)
			continue
		}
		swgpPacket := packetBuf[swgpPacketStart : swgpPacketStart+swgpPacketLength]

		if cpp := natEntry.clientPktinfo.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp
		}

		_, _, err = s.proxyConn.WriteMsgUDPAddrPort(swgpPacket, clientPktinfo, clientAddrPort)
		if err != nil {
			s.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("wgAddress", s.wgAddrPort),
				zap.Error(err),
			)
		}

		packetsSent++
		wgBytesSent += uint64(n)
	}

	s.logger.Info("Finished relay wgConn -> proxyConn",
		zap.String("server", s.name),
		zap.String("proxyListen", s.proxyListen),
		zap.Stringer("clientAddress", clientAddrPort),
		zap.Stringer("wgAddress", s.wgAddrPort),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

// Stop implements the Service Stop method.
func (s *server) Stop() error {
	if s.proxyConn == nil {
		return nil
	}

	now := time.Now()

	if err := s.proxyConn.SetReadDeadline(now); err != nil {
		return err
	}

	// Wait for serverConn receive goroutines to exit,
	// so there won't be any new sessions added to the table.
	s.mwg.Wait()

	s.mu.Lock()
	for clientAddrPort, entry := range s.table {
		if err := entry.wgConn.SetReadDeadline(now); err != nil {
			s.logger.Warn("Failed to SetReadDeadline on wgConn",
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("wgAddress", s.wgAddrPort),
				zap.Error(err),
			)
		}
	}
	s.mu.Unlock()

	// Wait for all relay goroutines to exit before closing serverConn,
	// so in-flight packets can be written out.
	s.wg.Wait()

	return s.proxyConn.Close()
}
