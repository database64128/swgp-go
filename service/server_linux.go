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

func (s *server) setRelayFunc(batchMode string) {
	switch batchMode {
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
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Error(err),
			)
			n = 1
			s.packetBufPool.Put(bufvec[0])
			continue
		}

		recvmmsgCount++
		packetsReceived += uint64(n)

		s.mu.Lock()

		msgvecn := msgvec[:n]

		for i := range msgvecn {
			msg := &msgvecn[i]
			packetBufp := bufvec[i]

			if msg.Msghdr.Controllen == 0 {
				s.logger.Warn("Skipping packet with no control message from proxyConn",
					zap.String("server", s.name),
					zap.String("proxyListen", s.proxyListen),
				)
				s.packetBufPool.Put(packetBufp)
				continue
			}

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from proxyConn",
					zap.String("server", s.name),
					zap.String("proxyListen", s.proxyListen),
					zap.Error(err),
				)
				s.packetBufPool.Put(packetBufp)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				s.logger.Warn("Failed to read from proxyConn",
					zap.String("server", s.name),
					zap.String("proxyListen", s.proxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				s.packetBufPool.Put(packetBufp)
				continue
			}

			wgPacketStart, wgPacketLength, err := s.handler.DecryptZeroCopy(*packetBufp, 0, int(msg.Msglen))
			if err != nil {
				s.logger.Warn("Failed to decrypt swgpPacket",
					zap.String("server", s.name),
					zap.String("proxyListen", s.proxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				s.packetBufPool.Put(packetBufp)
				continue
			}

			wgBytesReceived += uint64(wgPacketLength)

			var wgTunnelMTU int

			natEntry, ok := s.table[clientAddrPort]
			if !ok {
				wgConn, err := conn.ListenUDP("udp", "", false, s.wgFwmark)
				if err != nil {
					s.logger.Warn("Failed to create UDP socket for new UDP session",
						zap.String("server", s.name),
						zap.String("proxyListen", s.proxyListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Int("wgFwmark", s.wgFwmark),
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
			cmsg := cmsgvec[i][:msg.Msghdr.Controllen]

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

				if ce := s.logger.Check(zap.DebugLevel, "Updated client pktinfo"); ce != nil {
					ce.Write(
						zap.String("server", s.name),
						zap.String("proxyListen", s.proxyListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
						zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
					)
				}
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
				if ce := s.logger.Check(zap.DebugLevel, "wgPacket dropped due to full send channel"); ce != nil {
					ce.Write(
						zap.String("server", s.name),
						zap.String("proxyListen", s.proxyListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("wgAddress", s.wgAddrPort),
					)
				}
				s.packetBufPool.Put(packetBufp)
			}
		}

		s.mu.Unlock()
	}

	for i := range bufvec {
		s.packetBufPool.Put(bufvec[i])
	}

	s.logger.Info("Finished receiving from proxyConn",
		zap.String("server", s.name),
		zap.String("proxyListen", s.proxyListen),
		zap.Stringer("wgAddress", s.wgAddrPort),
		zap.Uint64("recvmmsgCount", recvmmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("wgBytesReceived", wgBytesReceived),
	)
}

func (s *server) relayProxyToWgSendmmsg(clientAddrPort netip.AddrPort, natEntry *serverNatEntry) {
	var (
		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

	rsa6 := conn.AddrPortToSockaddrInet6(s.wgAddrPort)
	dequeuedPackets := make([]queuedPacket, conn.UIO_MAXIOV)
	iovec := make([]unix.Iovec, conn.UIO_MAXIOV)
	msgvec := make([]conn.Mmsghdr, conn.UIO_MAXIOV)

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

			if count == conn.UIO_MAXIOV {
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
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("wgAddress", s.wgAddrPort),
				zap.Error(err),
			)
		}

		if isHandshake {
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
		zap.String("server", s.name),
		zap.String("proxyListen", s.proxyListen),
		zap.Stringer("clientAddress", clientAddrPort),
		zap.Stringer("wgAddress", s.wgAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (s *server) relayWgToProxySendmmsg(clientAddrPort netip.AddrPort, natEntry *serverNatEntry, clientPktinfop *[]byte) {
	var (
		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

	clientPktinfo := *clientPktinfop

	name, namelen := conn.AddrPortToSockaddr(clientAddrPort)
	frontOverhead := s.handler.FrontOverhead()
	rearOverhead := s.handler.RearOverhead()
	plaintextLen := natEntry.maxProxyPacketSize - frontOverhead - rearOverhead

	savec := make([]unix.RawSockaddrInet6, conn.UIO_MAXIOV)
	bufvec := make([][]byte, conn.UIO_MAXIOV)
	riovec := make([]unix.Iovec, conn.UIO_MAXIOV)
	siovec := make([]unix.Iovec, conn.UIO_MAXIOV)
	rmsgvec := make([]conn.Mmsghdr, conn.UIO_MAXIOV)
	smsgvec := make([]conn.Mmsghdr, conn.UIO_MAXIOV)

	for i := 0; i < conn.UIO_MAXIOV; i++ {
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
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("wgAddress", s.wgAddrPort),
				zap.Error(err),
			)
			continue
		}

		var ns int
		rmsgvecn := rmsgvec[:nr]

		for i := range rmsgvecn {
			msg := &rmsgvecn[i]

			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from wgConn",
					zap.String("server", s.name),
					zap.String("proxyListen", s.proxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("wgAddress", s.wgAddrPort),
					zap.Error(err),
				)
				continue
			}
			if !conn.AddrPortMappedEqual(packetSourceAddrPort, s.wgAddrPort) {
				s.logger.Warn("Ignoring packet from non-wg address",
					zap.String("server", s.name),
					zap.String("proxyListen", s.proxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("wgAddress", s.wgAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				s.logger.Warn("Packet from wgConn discarded",
					zap.String("server", s.name),
					zap.String("proxyListen", s.proxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("wgAddress", s.wgAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			packetBuf := bufvec[i]
			swgpPacketStart, swgpPacketLength, err := s.handler.EncryptZeroCopy(packetBuf, frontOverhead, int(msg.Msglen))
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
				zap.String("server", s.name),
				zap.String("proxyListen", s.proxyListen),
				zap.Stringer("clientAddress", clientAddrPort),
				zap.Stringer("wgAddress", s.wgAddrPort),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(ns)
	}

	s.logger.Info("Finished relay wgConn -> proxyConn",
		zap.String("server", s.name),
		zap.String("proxyListen", s.proxyListen),
		zap.Stringer("clientAddress", clientAddrPort),
		zap.Stringer("wgAddress", s.wgAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}
