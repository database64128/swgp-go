package service

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"time"
	"unsafe"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/packet"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func (s *server) setRelayFunc() {
	// Keep these dead methods for now.
	_ = s.relayProxyToWgSendmmsgRing
	_ = s.relayWgToProxySendmmsgRing

	switch s.config.BatchMode {
	case "sendmmsg", "":
		s.recvFromProxyConn = s.recvFromProxyConnRecvmmsg
	default:
		s.recvFromProxyConn = s.recvFromProxyConnGeneric
	}
}

func (s *server) recvFromProxyConnRecvmmsg() {
	bufvec := make([]*[]byte, conn.UIO_MAXIOV)
	namevec := make([]unix.RawSockaddrInet6, conn.UIO_MAXIOV)
	iovec := make([]unix.Iovec, conn.UIO_MAXIOV)
	cmsgvec := make([][]byte, conn.UIO_MAXIOV)
	msgvec := make([]conn.Mmsghdr, conn.UIO_MAXIOV)

	for i := range msgvec {
		cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)
		cmsgvec[i] = cmsgBuf
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&namevec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
		msgvec[i].Msghdr.Control = &cmsgBuf[0]
	}

	n := conn.UIO_MAXIOV

	var (
		err             error
		recvmmsgCount   uint64
		packetsReceived uint64
		wgBytesReceived uint64
	)

	for {
		for i := range iovec[:n] {
			packetBufp := s.packetBufPool.Get().(*[]byte)
			packetBuf := *packetBufp
			bufvec[i] = packetBufp
			iovec[i].Base = &packetBuf[0]
			iovec[i].SetLen(len(packetBuf))
			msgvec[i].Msghdr.SetControllen(conn.SocketControlMessageBufferSize)
		}

		n, err = conn.Recvmmsg(s.proxyConn, msgvec)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			s.logger.Warn("Failed to read from proxyConn",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Error(err),
			)
			n = 1
			s.packetBufPool.Put(bufvec[0])
			continue
		}

		recvmmsgCount++
		packetsReceived += uint64(n)

		s.mu.Lock()

		for i, msg := range msgvec[:n] {
			packetBufp := bufvec[i]
			packetBuf := *packetBufp
			cmsg := cmsgvec[i][:msg.Msghdr.Controllen]

			if msg.Msghdr.Controllen == 0 {
				s.logger.Warn("Skipping packet with no control message from proxyConn",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
				)
				s.packetBufPool.Put(packetBufp)
				continue
			}

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from proxyConn",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Error(err),
				)
				s.packetBufPool.Put(packetBufp)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				s.logger.Warn("Failed to read from proxyConn",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Error(err),
				)
				s.packetBufPool.Put(packetBufp)
				continue
			}

			wgPacketStart, wgPacketLength, err := s.handler.DecryptZeroCopy(packetBuf, 0, int(msg.Msglen))
			if err != nil {
				s.logger.Warn("Failed to decrypt swgpPacket",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Error(err),
				)
				s.packetBufPool.Put(packetBufp)
				continue
			}

			wgBytesReceived += uint64(wgPacketLength)

			var wgTunnelMTU int

			natEntry, ok := s.table[clientAddrPort]
			if !ok {
				wgConn, err, serr := conn.ListenUDP("udp", "", false, s.config.WgFwmark)
				if err != nil {
					s.logger.Warn("Failed to start UDP listener for new UDP session",
						zap.Stringer("service", s),
						zap.String("proxyListen", s.config.ProxyListen),
						zap.Stringer("clientAddress", clientAddrPort),
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
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Int("wgFwmark", s.config.WgFwmark),
						zap.NamedError("serr", serr),
					)
				}

				err = wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
				if err != nil {
					s.logger.Warn("Failed to SetReadDeadline on wgConn",
						zap.Stringer("service", s),
						zap.String("proxyListen", s.config.ProxyListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("wgAddress", s.wgAddr),
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
					natEntry.maxProxyPacketSize = s.config.MTU - IPv4HeaderLength - UDPHeaderLength
					wgTunnelMTU = s.wgTunnelMTUv4
				} else {
					natEntry.maxProxyPacketSize = s.config.MTU - IPv6HeaderLength - UDPHeaderLength
					wgTunnelMTU = s.wgTunnelMTUv6
				}

				s.table[clientAddrPort] = natEntry
			}

			var clientPktinfop *[]byte

			if !bytes.Equal(natEntry.clientPktinfoCache, cmsg) {
				clientPktinfoAddr, clientPktinfoIfindex, err := conn.ParsePktinfoCmsg(cmsg)
				if err != nil {
					s.logger.Warn("Failed to parse pktinfo control message from proxyConn",
						zap.Stringer("service", s),
						zap.String("proxyListen", s.config.ProxyListen),
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
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
					zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
				)
			}

			if !ok {
				s.wg.Add(2)

				go func() {
					s.relayWgToProxySendmmsg(clientAddrPort, natEntry, clientPktinfop)

					s.mu.Lock()
					close(natEntry.wgConnSendCh)
					delete(s.table, clientAddrPort)
					s.mu.Unlock()

					s.wg.Done()
				}()

				go func() {
					s.relayProxyToWgSendmmsg(clientAddrPort, natEntry)
					natEntry.wgConn.Close()
					s.wg.Done()
				}()

				s.logger.Info("New UDP session",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("wgAddress", s.wgAddr),
					zap.Int("wgTunnelMTU", wgTunnelMTU),
				)
			}

			select {
			case natEntry.wgConnSendCh <- queuedPacket{packetBufp, wgPacketStart, wgPacketLength}:
			default:
				s.logger.Debug("wgPacket dropped due to full send channel",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("wgAddress", s.wgAddr),
				)
				s.packetBufPool.Put(packetBufp)
			}
		}

		s.mu.Unlock()
	}

	for _, packetBufp := range bufvec {
		s.packetBufPool.Put(packetBufp)
	}

	s.logger.Info("Finished receiving from proxyConn",
		zap.Stringer("service", s),
		zap.String("proxyListen", s.config.ProxyListen),
		zap.Stringer("wgAddress", s.wgAddr),
		zap.Uint64("recvmmsgCount", recvmmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("wgBytesReceived", wgBytesReceived),
	)
}

func (s *server) relayProxyToWgSendmmsg(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	var (
		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

	rsa6 := conn.AddrPortToSockaddrInet6(s.wgAddr)
	dequeuedPackets := make([]queuedPacket, vecSize)
	iovec := make([]unix.Iovec, vecSize)
	msgvec := make([]conn.Mmsghdr, vecSize)

	for i := range msgvec {
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&rsa6))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

	for {
		var (
			count       int
			isHandshake bool
		)

		// Block on first dequeue op.
		dequeuedPacket, ok := <-natEntry.wgConnSendCh
		if !ok {
			break
		}
		packetBuf := *dequeuedPacket.bufp

	dequeue:
		for {
			// Update wgConn read deadline when a handshake initiation/response message is received.
			switch packetBuf[dequeuedPacket.start] {
			case packet.WireGuardMessageTypeHandshakeInitiation, packet.WireGuardMessageTypeHandshakeResponse:
				isHandshake = true
			}

			dequeuedPackets[count] = dequeuedPacket
			iovec[count].Base = &packetBuf[dequeuedPacket.start]
			iovec[count].SetLen(dequeuedPacket.length)
			count++
			wgBytesSent += uint64(dequeuedPacket.length)

			if count == vecSize {
				break
			}

			select {
			case dequeuedPacket, ok = <-natEntry.wgConnSendCh:
				if !ok {
					break dequeue
				}
				packetBuf = *dequeuedPacket.bufp
			default:
				break dequeue
			}
		}

		if err := conn.WriteMsgvec(natEntry.wgConn, msgvec[:count]); err != nil {
			s.logger.Warn("Failed to write wgPacket to wgConn",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("wgAddress", s.wgAddr),
				zap.Error(err),
			)
		}

		if isHandshake {
			if err := natEntry.wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
				s.logger.Warn("Failed to SetReadDeadline on wgConn",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("wgAddress", s.wgAddr),
					zap.Error(err),
				)
			}
		}

		sendmmsgCount++
		packetsSent += uint64(count)

		for _, packet := range dequeuedPackets[:count] {
			s.packetBufPool.Put(packet.bufp)
		}

		if !ok {
			break
		}
	}

	s.logger.Info("Finished relay proxyConn -> wgConn",
		zap.Stringer("service", s),
		zap.String("proxyListen", s.config.ProxyListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("wgAddress", s.wgAddr),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (s *server) relayProxyToWgSendmmsgRing(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	rsa6 := conn.AddrPortToSockaddrInet6(s.wgAddr)
	dequeuedPackets := make([]queuedPacket, vecSize)
	iovec := make([]unix.Iovec, vecSize)
	msgvec := make([]conn.Mmsghdr, vecSize)

	var (
		// Turn dequeuedPackets into a ring buffer.
		head, tail int

		// Number of messages in msgvec.
		count int

		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

	for i := range msgvec {
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&rsa6))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

	for {
		var isHandshake bool

		// Block on first dequeue op.
		dequeuedPacket, ok := <-natEntry.wgConnSendCh
		if !ok {
			break
		}
		packetBuf := *dequeuedPacket.bufp

	dequeue:
		for {
			// Update wgConn read deadline when a handshake initiation/response message is received.
			switch packetBuf[dequeuedPacket.start] {
			case packet.WireGuardMessageTypeHandshakeInitiation, packet.WireGuardMessageTypeHandshakeResponse:
				isHandshake = true
			}

			dequeuedPackets[tail] = dequeuedPacket
			tail = (tail + 1) & sizeMask

			iovec[count].Base = &packetBuf[dequeuedPacket.start]
			iovec[count].SetLen(dequeuedPacket.length)
			count++
			wgBytesSent += uint64(dequeuedPacket.length)

			if tail == head {
				break
			}

			select {
			case dequeuedPacket, ok = <-natEntry.wgConnSendCh:
				if !ok {
					break dequeue
				}
				packetBuf = *dequeuedPacket.bufp
			default:
				break dequeue
			}
		}

		// Batch write.
		n, err := conn.Sendmmsg(natEntry.wgConn, msgvec[:count])
		if err != nil {
			s.logger.Warn("Failed to write wgPacket to wgConn",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("wgAddress", s.wgAddr),
				zap.Error(err),
			)
			// Error is caused by the first packet in msgvec.
			n = 1
		}

		if isHandshake {
			if err := natEntry.wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
				s.logger.Warn("Failed to SetReadDeadline on wgConn",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("wgAddress", s.wgAddr),
					zap.Error(err),
				)
			}
		}

		sendmmsgCount++
		packetsSent += uint64(n)

		// Clean up and move head forward.
		for i := 0; i < n; i++ {
			s.packetBufPool.Put(dequeuedPackets[head].bufp)
			head = (head + 1) & sizeMask
		}

		// Move unsent packets to the beginning of msgvec.
		expectedCount := count - n
		count = 0
		for i := head; i != tail; i = (i + 1) & sizeMask {
			dequeuedPacket = dequeuedPackets[i]
			packetBuf = *dequeuedPacket.bufp
			iovec[count].Base = &packetBuf[dequeuedPacket.start]
			iovec[count].SetLen(dequeuedPacket.length)
			count++
		}
		if count != expectedCount {
			s.logger.Error("Packet count does not match ring buffer status",
				zap.Int("count", count),
				zap.Int("expectedCount", expectedCount),
			)
		}
	}

	// Exit cleanup.
	for head != tail {
		s.packetBufPool.Put(dequeuedPackets[head].bufp)
		head = (head + 1) & sizeMask
	}

	s.logger.Info("Finished relay proxyConn -> wgConn",
		zap.Stringer("service", s),
		zap.String("proxyListen", s.config.ProxyListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("wgAddress", s.wgAddr),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (s *server) relayWgToProxySendmmsg(clientAddr netip.AddrPort, natEntry *serverNatEntry, clientPktinfop *[]byte) {
	var (
		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

	clientPktinfo := *clientPktinfop

	name, namelen := conn.AddrPortToSockaddr(clientAddr)
	frontOverhead := s.handler.FrontOverhead()
	rearOverhead := s.handler.RearOverhead()
	plaintextLen := natEntry.maxProxyPacketSize - frontOverhead - rearOverhead

	savec := make([]unix.RawSockaddrInet6, vecSize)
	bufvec := make([][]byte, vecSize)
	riovec := make([]unix.Iovec, vecSize)
	siovec := make([]unix.Iovec, vecSize)
	rmsgvec := make([]conn.Mmsghdr, vecSize)
	smsgvec := make([]conn.Mmsghdr, vecSize)

	for i := 0; i < vecSize; i++ {
		bufvec[i] = make([]byte, natEntry.maxProxyPacketSize)

		riovec[i].Base = &bufvec[i][frontOverhead]
		riovec[i].SetLen(plaintextLen)

		rmsgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&savec[i]))
		rmsgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		rmsgvec[i].Msghdr.Iov = &riovec[i]
		rmsgvec[i].Msghdr.SetIovlen(1)

		smsgvec[i].Msghdr.Name = name
		smsgvec[i].Msghdr.Namelen = namelen
		smsgvec[i].Msghdr.Iov = &siovec[i]
		smsgvec[i].Msghdr.SetIovlen(1)
		smsgvec[i].Msghdr.Control = &clientPktinfo[0]
		smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
	}

	for {
		nr, err := conn.Recvmmsg(natEntry.wgConn, rmsgvec)
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

		var ns int

		for i, msg := range rmsgvec[:nr] {
			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from wgConn",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("wgAddress", s.wgAddr),
					zap.Error(err),
				)
				continue
			}
			if !conn.AddrPortMappedEqual(packetSourceAddrPort, s.wgAddr) {
				s.logger.Debug("Ignoring packet from non-wg address",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("wgAddress", s.wgAddr),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Error(err),
				)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				s.logger.Warn("Packet from wgConn discarded",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("wgAddress", s.wgAddr),
					zap.Error(err),
				)
				continue
			}

			packetBuf := bufvec[i]
			swgpPacketStart, swgpPacketLength, err := s.handler.EncryptZeroCopy(packetBuf, frontOverhead, int(msg.Msglen))
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

			siovec[ns].Base = &packetBuf[swgpPacketStart]
			siovec[ns].SetLen(swgpPacketLength)
			ns++
			wgBytesSent += uint64(msg.Msglen)
		}

		if ns == 0 {
			continue
		}

		if cpp := natEntry.clientPktinfo.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp

			for i := range smsgvec {
				smsgvec[i].Msghdr.Control = &clientPktinfo[0]
				smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
			}
		}

		err = conn.WriteMsgvec(s.proxyConn, smsgvec[:ns])
		if err != nil {
			s.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("wgAddress", s.wgAddr),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(ns)
	}

	s.logger.Info("Finished relay wgConn -> proxyConn",
		zap.Stringer("service", s),
		zap.String("proxyListen", s.config.ProxyListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("wgAddress", s.wgAddr),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (s *server) relayWgToProxySendmmsgRing(clientAddr netip.AddrPort, natEntry *serverNatEntry, clientPktinfop *[]byte) {
	const (
		vecSize  = 64
		sizeMask = 63
	)

	var (
		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

	clientPktinfo := *clientPktinfop

	name, namelen := conn.AddrPortToSockaddr(clientAddr)
	frontOverhead := s.handler.FrontOverhead()
	rearOverhead := s.handler.RearOverhead()
	plaintextLen := natEntry.maxProxyPacketSize - frontOverhead - rearOverhead

	savec := make([]unix.RawSockaddrInet6, vecSize)
	bufvec := make([][]byte, vecSize)
	riovec := make([]unix.Iovec, vecSize)
	siovec := make([]unix.Iovec, vecSize)
	rmsgvec := make([]conn.Mmsghdr, vecSize)
	smsgvec := make([]conn.Mmsghdr, vecSize)

	var (
		// Tracks individual buffer's usage in bufvec.
		usage uint64

		// Current position in bufvec.
		pos int = -1
	)

	for i := 0; i < vecSize; i++ {
		bufvec[i] = make([]byte, natEntry.maxProxyPacketSize)

		riovec[i].Base = &bufvec[i][frontOverhead]
		riovec[i].SetLen(plaintextLen)

		rmsgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&savec[i]))
		rmsgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		rmsgvec[i].Msghdr.Iov = &riovec[i]
		rmsgvec[i].Msghdr.SetIovlen(1)

		smsgvec[i].Msghdr.Name = name
		smsgvec[i].Msghdr.Namelen = namelen
		smsgvec[i].Msghdr.Iov = &siovec[i]
		smsgvec[i].Msghdr.SetIovlen(1)
		smsgvec[i].Msghdr.Control = &clientPktinfo[0]
		smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
	}

	var (
		n   int
		nr  int = vecSize
		ns  int
		err error
	)

	for {
		nr, err = conn.Recvmmsg(natEntry.wgConn, rmsgvec[:nr])
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

		for _, msg := range rmsgvec[:nr] {
			// Advance pos to the current unused buffer.
			for {
				pos = (pos + 1) & sizeMask
				if usage>>pos&1 == 0 { // unused
					break
				}
			}

			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from wgConn",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("wgAddress", s.wgAddr),
					zap.Error(err),
				)
				continue
			}
			if !conn.AddrPortMappedEqual(packetSourceAddrPort, s.wgAddr) {
				s.logger.Debug("Ignoring packet from non-wg address",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("wgAddress", s.wgAddr),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Error(err),
				)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				s.logger.Warn("Packet from wgConn discarded",
					zap.Stringer("service", s),
					zap.String("proxyListen", s.config.ProxyListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("wgAddress", s.wgAddr),
					zap.Error(err),
				)
				continue
			}

			packetBuf := bufvec[pos]
			swgpPacketStart, swgpPacketLength, err := s.handler.EncryptZeroCopy(packetBuf, frontOverhead, int(msg.Msglen))
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

			siovec[ns].Base = &packetBuf[swgpPacketStart]
			siovec[ns].SetLen(swgpPacketLength)
			ns++
			wgBytesSent += uint64(msg.Msglen)

			// Mark buffer as used.
			usage |= 1 << pos
		}

		if ns == 0 {
			continue
		}

		if cpp := natEntry.clientPktinfo.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp

			for i := range smsgvec {
				smsgvec[i].Msghdr.Control = &clientPktinfo[0]
				smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
			}
		}

		// Batch write.
		n, err = conn.Sendmmsg(s.proxyConn, smsgvec[:ns])
		if err != nil {
			s.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("wgAddress", s.wgAddr),
				zap.Error(err),
			)
			n = 1
		}
		ns -= n

		sendmmsgCount++
		packetsSent += uint64(n)

		// Move unsent packets to the beginning of smsgvec.
		for i := 0; i < ns; i++ {
			siovec[i].Base = siovec[n+i].Base
			siovec[i].Len = siovec[n+i].Len
		}

		// Assign unused buffers to rmsgvec.
		nr = 0
		tpos := pos
		for i := 0; i < vecSize; i++ {
			tpos = (tpos + 1) & sizeMask

			switch {
			case usage>>tpos&1 == 0: // unused
			case n > 0: // used and sent
				usage ^= 1 << tpos // Mark as unused.
				n--
			default: // used and not sent
				continue
			}

			riovec[nr].Base = &bufvec[tpos][frontOverhead]
			riovec[nr].SetLen(plaintextLen)
			nr++
		}
	}

	s.logger.Info("Finished relay wgConn -> proxyConn",
		zap.Stringer("service", s),
		zap.String("proxyListen", s.config.ProxyListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("wgAddress", s.wgAddr),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}
