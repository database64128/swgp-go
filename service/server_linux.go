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

func (s *server) getRelayProxyToWgFunc(disableSendmmsg bool) func(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	if disableSendmmsg {
		return s.relayProxyToWgGeneric
	}
	return s.relayProxyToWgSendmmsg
}

func (s *server) relayProxyToWgSendmmsg(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	name, namelen := conn.AddrPortToSockaddr(s.wgAddr)
	dequeuedPackets := make([]serverQueuedPacket, 0, conn.UIO_MAXIOV)
	iovec := make([]unix.Iovec, 0, conn.UIO_MAXIOV)
	msgvec := make([]conn.Mmsghdr, 0, conn.UIO_MAXIOV)

	for {
		// Dequeue packets and append to dequeuedPackets.

		var (
			dequeuedPacket serverQueuedPacket
			ok             bool
		)

		dequeuedPackets = dequeuedPackets[:0]

		// Block on first dequeue op.
		dequeuedPacket, ok = <-natEntry.wgConnSendCh
		if !ok {
			break
		}
		dequeuedPackets = append(dequeuedPackets, dequeuedPacket)

	dequeue:
		for i := 1; i < conn.UIO_MAXIOV; i++ {
			select {
			case dequeuedPacket, ok = <-natEntry.wgConnSendCh:
				if !ok {
					goto cleanup
				}
				dequeuedPackets = append(dequeuedPackets, dequeuedPacket)
			default:
				break dequeue
			}
		}

		// Reslice iovec and msgvec.
		iovec = iovec[:len(dequeuedPackets)]
		msgvec = msgvec[:len(dequeuedPackets)]

		// Add packets to iovec and msgvec.
		for i, packet := range dequeuedPackets {
			iovec[i].Base = &packet.wgPacket[0]
			iovec[i].SetLen(len(packet.wgPacket))

			msgvec[i].Msghdr.Name = name
			msgvec[i].Msghdr.Namelen = namelen
			msgvec[i].Msghdr.Iov = &iovec[i]
			msgvec[i].Msghdr.SetIovlen(1)
			if len(natEntry.wgConnOobCache) > 0 {
				msgvec[i].Msghdr.Control = &natEntry.wgConnOobCache[0]
				msgvec[i].Msghdr.SetControllen(len(natEntry.wgConnOobCache))
			}
		}

		// Batch write.
		if err := conn.Sendmmsg(natEntry.wgConn, msgvec); err != nil {
			if errors.Is(err, net.ErrClosed) {
				ok = false
				goto cleanup
			}
			s.logger.Warn("Failed to write wgPacket to wgConn",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("wgAddress", s.wgAddr),
				zap.Error(err),
			)
		}

	cleanup:
		for _, packet := range dequeuedPackets {
			s.packetBufPool.Put(packet.bufp)
		}

		if !ok {
			break
		}
	}
}

func (s *server) getRelayWgToProxyFunc(disableSendmmsg bool) func(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	if disableSendmmsg {
		return s.relayWgToProxyGeneric
	}
	return s.relayWgToProxySendmmsg
}

func (s *server) relayWgToProxySendmmsg(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	name, namelen := conn.AddrPortToSockaddr(clientAddr)
	wgAddr16 := s.wgAddr.Addr().As16()
	wgPort := s.wgAddr.Port()
	frontOverhead := s.handler.FrontOverhead()
	rearOverhead := s.handler.RearOverhead()

	riovec := make([]unix.Iovec, conn.UIO_MAXIOV)
	siovec := make([]unix.Iovec, conn.UIO_MAXIOV)
	rmsgvec := make([]conn.Mmsghdr, conn.UIO_MAXIOV)
	smsgvec := make([]conn.Mmsghdr, conn.UIO_MAXIOV)
	plaintextLen := natEntry.maxProxyPacketSize - frontOverhead - rearOverhead

	// Initialize riovec, rmsgvec and smsgvec.
	for i := 0; i < conn.UIO_MAXIOV; i++ {
		var sockaddr unix.RawSockaddrInet6
		packetBuf := make([]byte, natEntry.maxProxyPacketSize)
		oobBuf := make([]byte, conn.UDPOOBBufferSize)
		plaintextBuf := packetBuf[frontOverhead : natEntry.maxProxyPacketSize-rearOverhead]

		riovec[i].Base = &plaintextBuf[0]
		riovec[i].SetLen(plaintextLen)

		rmsgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&sockaddr))
		rmsgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		rmsgvec[i].Msghdr.Iov = &riovec[i]
		rmsgvec[i].Msghdr.SetIovlen(1)
		rmsgvec[i].Msghdr.Control = &oobBuf[0]
		rmsgvec[i].Msghdr.SetControllen(conn.UDPOOBBufferSize)

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

		nrmsgvec := rmsgvec[:nr]
		smsgControl := natEntry.clientOobCache
		smsgControlLen := len(smsgControl)
		var (
			oob []byte
			ns  int
		)

		for _, msg := range nrmsgvec {
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

			msgSockaddr := *(*unix.RawSockaddrInet6)(unsafe.Pointer(msg.Msghdr.Name))
			msgSockaddrPortp := (*[2]byte)(unsafe.Pointer(&msgSockaddr.Port))
			msgSockaddrPort := uint16(msgSockaddrPortp[0])<<8 + uint16(msgSockaddrPortp[1])
			if msgSockaddrPort != wgPort || msgSockaddr.Addr != wgAddr16 {
				raddr := netip.AddrPortFrom(netip.AddrFrom16(msgSockaddr.Addr), msgSockaddrPort)
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

			packetBuf := unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(msg.Msghdr.Iov.Base), -frontOverhead)), natEntry.maxProxyPacketSize)
			swgpPacket, err := s.handler.EncryptZeroCopy(packetBuf, frontOverhead, int(msg.Msglen), natEntry.maxProxyPacketSize)
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

			// Only create slice here. Processing happens after the loop.
			// This essentially means only the last socket control message
			// is being processed.
			oob = unsafe.Slice(msg.Msghdr.Control, msg.Msghdr.Controllen)

			smsgvec[ns].Msghdr.Iov.Base = &swgpPacket[0]
			smsgvec[ns].Msghdr.Iov.SetLen(len(swgpPacket))
			if smsgControlLen > 0 {
				smsgvec[ns].Msghdr.Control = &smsgControl[0]
				smsgvec[ns].Msghdr.SetControllen(smsgControlLen)
			}
			ns++
		}

		if ns == 0 {
			continue
		}

		natEntry.wgConnOobCache, err = conn.UpdateOobCache(natEntry.wgConnOobCache, oob, s.logger)
		if err != nil {
			s.logger.Warn("Failed to process OOB from wgConn",
				zap.Stringer("service", s),
				zap.String("proxyListen", s.config.ProxyListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("wgAddress", s.wgAddr),
				zap.Error(err),
			)
		}

		err = conn.Sendmmsg(s.proxyConn, smsgvec[:ns])
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
	}
}
