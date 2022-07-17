package service

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"unsafe"

	"github.com/database64128/swgp-go/conn"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func (s *server) setRelayProxyToWgFunc() {
	switch s.config.BatchMode {
	case "ring":
		s.relayProxyToWg = s.relayProxyToWgSendmmsgRing
	case "sendmmsg", "":
		s.relayProxyToWg = s.relayProxyToWgSendmmsg
	default:
		s.relayProxyToWg = s.relayProxyToWgGeneric
	}
}

func (s *server) relayProxyToWgSendmmsg(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	var (
		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

	name, namelen := conn.AddrPortToSockaddr(s.wgAddr)
	dequeuedPackets := make([]queuedPacket, vecSize)
	iovec := make([]unix.Iovec, vecSize)
	msgvec := make([]conn.Mmsghdr, vecSize)

	// Initialize msgvec.
	for i := range msgvec {
		msgvec[i].Msghdr.Name = name
		msgvec[i].Msghdr.Namelen = namelen
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

	// Main relay loop.
	for {
		var count int

		// Block on first dequeue op.
		dequeuedPacket, ok := <-natEntry.wgConnSendCh
		if !ok {
			break
		}
		packetBuf := *dequeuedPacket.bufp

	dequeue:
		for {
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
					goto cleanup
				}
				packetBuf = *dequeuedPacket.bufp
			default:
				break dequeue
			}
		}

		// Batch write.
		if err := conn.WriteMsgvec(natEntry.wgConn, msgvec[:count]); err != nil {
			s.logger.Warn("Failed to write wgPacket to wgConn",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("wgAddress", s.wgAddr),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(count)

	cleanup:
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
	name, namelen := conn.AddrPortToSockaddr(s.wgAddr)
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

	// Initialize msgvec.
	for i := range msgvec {
		msgvec[i].Msghdr.Name = name
		msgvec[i].Msghdr.Namelen = namelen
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

	// Main relay loop.
relay:
	for {
		// Block on first dequeue op.
		dequeuedPacket, ok := <-natEntry.wgConnSendCh
		if !ok {
			break relay
		}
		packetBuf := *dequeuedPacket.bufp

	dequeue:
		for {
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
					break relay
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

func (s *server) setRelayWgToProxyFunc() {
	switch s.config.BatchMode {
	case "ring":
		s.relayWgToProxy = s.relayWgToProxySendmmsgRing
	case "sendmmsg", "":
		s.relayWgToProxy = s.relayWgToProxySendmmsg
	default:
		s.relayWgToProxy = s.relayWgToProxyGeneric
	}
}

func (s *server) relayWgToProxySendmmsg(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	var (
		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

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

	// Initialize riovec, rmsgvec and smsgvec.
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
	}

	// Main relay loop.
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

		smsgControl := natEntry.clientOobCache
		smsgControlLen := len(smsgControl)
		var ns int

		for i, msg := range rmsgvec[:nr] {
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

			raddr, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
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
			if smsgControlLen > 0 {
				smsgvec[ns].Msghdr.Control = &smsgControl[0]
				smsgvec[ns].Msghdr.SetControllen(smsgControlLen)
			}
			ns++
			wgBytesSent += uint64(msg.Msglen)
		}

		if ns == 0 {
			continue
		}

		err = conn.WriteMsgvec(s.proxyConn, smsgvec[:ns])
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

func (s *server) relayWgToProxySendmmsgRing(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	const (
		vecSize  = 64
		sizeMask = 63
	)

	var (
		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

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

	// Initialize riovec, rmsgvec and smsgvec.
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
	}

	var (
		n   int
		nr  int = vecSize
		ns  int
		err error
	)

	// Main relay loop.
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

		smsgControl := natEntry.clientOobCache
		smsgControlLen := len(smsgControl)

		for _, msg := range rmsgvec[:nr] {
			// Advance pos to the current unused buffer.
			for {
				pos = (pos + 1) & sizeMask
				if usage>>pos&1 == 0 { // unused
					break
				}
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

			raddr, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
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
			if smsgControlLen > 0 {
				smsgvec[ns].Msghdr.Control = &smsgControl[0]
				smsgvec[ns].Msghdr.SetControllen(smsgControlLen)
			}
			ns++
			wgBytesSent += uint64(msg.Msglen)

			// Mark buffer as used.
			usage |= 1 << pos
		}

		if ns == 0 {
			continue
		}

		// Batch write.
		n, err = conn.Sendmmsg(s.proxyConn, smsgvec[:ns])
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
