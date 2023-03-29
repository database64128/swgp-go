//go:build linux || netbsd

package service

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/packet"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

type serverNatUplinkMmsg struct {
	clientAddrPort netip.AddrPort
	wgConn         *conn.MmsgWConn
	wgConnSendCh   <-chan queuedPacket
}

type serverNatDownlinkMmsg struct {
	clientAddrPort     netip.AddrPort
	clientPktinfop     *[]byte
	clientPktinfo      *atomic.Pointer[[]byte]
	wgConn             *conn.MmsgRConn
	proxyConn          *conn.MmsgWConn
	maxProxyPacketSize int
}

func (s *server) setStartFunc(batchMode string) {
	switch batchMode {
	case "sendmmsg", "":
		s.startFunc = s.startMmsg
	default:
		s.startFunc = s.startGeneric
	}
}

func (s *server) startMmsg() error {
	proxyConn, err := s.proxyConnListenConfig.ListenUDPRawConn("udp", s.proxyListen)
	if err != nil {
		return err
	}
	s.proxyConn = proxyConn.UDPConn

	s.mwg.Add(1)

	go func() {
		s.recvFromProxyConnRecvmmsg(proxyConn.RConn())
		s.mwg.Done()
	}()

	s.logger.Info("Started service",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListen),
		zap.Stringer("wgAddress", &s.wgAddrPort),
		zap.Int("wgTunnelMTUv4", s.wgTunnelMTUv4),
		zap.Int("wgTunnelMTUv6", s.wgTunnelMTUv6),
	)
	return nil
}

func (s *server) recvFromProxyConnRecvmmsg(proxyConn *conn.MmsgRConn) {
	n := s.mainRecvBatchSize
	bufvec := make([][]byte, n)
	namevec := make([]unix.RawSockaddrInet6, n)
	iovec := make([]unix.Iovec, n)
	cmsgvec := make([][]byte, n)
	msgvec := make([]conn.Mmsghdr, n)

	for i := range msgvec {
		cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)
		cmsgvec[i] = cmsgBuf
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&namevec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
		msgvec[i].Msghdr.Control = &cmsgBuf[0]
	}

	var (
		err             error
		recvmmsgCount   uint64
		packetsReceived uint64
		wgBytesReceived uint64
		burstBatchSize  int
	)

	for {
		for i := range iovec[:n] {
			packetBuf := s.getPacketBuf()
			bufvec[i] = packetBuf
			iovec[i].Base = &packetBuf[0]
			iovec[i].SetLen(len(packetBuf))
			msgvec[i].Msghdr.SetControllen(conn.SocketControlMessageBufferSize)
		}

		n, err = proxyConn.ReadMsgs(msgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			s.logger.Warn("Failed to read from proxyConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListen),
				zap.Error(err),
			)
			n = 1
			s.putPacketBuf(bufvec[0])
			continue
		}

		recvmmsgCount++
		packetsReceived += uint64(n)
		if burstBatchSize < n {
			burstBatchSize = n
		}

		s.mu.Lock()

		msgvecn := msgvec[:n]

		for i := range msgvecn {
			msg := &msgvecn[i]
			packetBuf := bufvec[i]

			if msg.Msghdr.Controllen == 0 {
				s.logger.Warn("Skipping packet with no control message from proxyConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListen),
				)
				s.putPacketBuf(packetBuf)
				continue
			}

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from proxyConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListen),
					zap.Error(err),
				)
				s.putPacketBuf(packetBuf)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				s.logger.Warn("Failed to read from proxyConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				s.putPacketBuf(packetBuf)
				continue
			}

			wgPacketStart, wgPacketLength, err := s.handler.DecryptZeroCopy(packetBuf, 0, int(msg.Msglen))
			if err != nil {
				s.logger.Warn("Failed to decrypt swgpPacket",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				s.putPacketBuf(packetBuf)
				continue
			}

			wgBytesReceived += uint64(wgPacketLength)

			natEntry, ok := s.table[clientAddrPort]
			if !ok {
				natEntry = &serverNatEntry{}
			}

			var clientPktinfop *[]byte
			cmsg := cmsgvec[i][:msg.Msghdr.Controllen]

			if !bytes.Equal(natEntry.clientPktinfoCache, cmsg) {
				clientPktinfoAddr, clientPktinfoIfindex, err := conn.ParsePktinfoCmsg(cmsg)
				if err != nil {
					s.logger.Warn("Failed to parse pktinfo control message from proxyConn",
						zap.String("server", s.name),
						zap.String("listenAddress", s.proxyListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Error(err),
					)
					s.putPacketBuf(packetBuf)
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
						zap.String("listenAddress", s.proxyListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
						zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
					)
				}
			}

			if !ok {
				wgConn, err := s.wgConnListenConfig.ListenUDPRawConn("udp", "")
				if err != nil {
					s.logger.Warn("Failed to create UDP socket for new session",
						zap.String("server", s.name),
						zap.String("listenAddress", s.proxyListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Error(err),
					)
					s.putPacketBuf(packetBuf)
					s.mu.Unlock()
					continue
				}

				err = wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
				if err != nil {
					s.logger.Warn("Failed to SetReadDeadline on wgConn",
						zap.String("server", s.name),
						zap.String("listenAddress", s.proxyListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("wgAddress", &s.wgAddrPort),
						zap.Error(err),
					)
					s.putPacketBuf(packetBuf)
					s.mu.Unlock()
					continue
				}

				wgConnSendCh := make(chan queuedPacket, s.sendChannelCapacity)
				natEntry.wgConn = wgConn.UDPConn
				natEntry.wgConnSendCh = wgConnSendCh
				s.table[clientAddrPort] = natEntry

				var (
					maxProxyPacketSize int
					wgTunnelMTU        int
				)

				if addr := clientAddrPort.Addr(); addr.Is4() || addr.Is4In6() {
					maxProxyPacketSize = s.maxProxyPacketSizev4
					wgTunnelMTU = s.wgTunnelMTUv4
				} else {
					maxProxyPacketSize = s.maxProxyPacketSizev6
					wgTunnelMTU = s.wgTunnelMTUv6
				}

				s.wg.Add(2)

				go func() {
					s.relayWgToProxySendmmsg(serverNatDownlinkMmsg{
						clientAddrPort:     clientAddrPort,
						clientPktinfop:     clientPktinfop,
						clientPktinfo:      &natEntry.clientPktinfo,
						wgConn:             wgConn.RConn(),
						proxyConn:          proxyConn.WConn(),
						maxProxyPacketSize: maxProxyPacketSize,
					})

					s.mu.Lock()
					close(wgConnSendCh)
					delete(s.table, clientAddrPort)
					s.mu.Unlock()

					s.wg.Done()
				}()

				go func() {
					s.relayProxyToWgSendmmsg(serverNatUplinkMmsg{
						clientAddrPort: clientAddrPort,
						wgConn:         wgConn.WConn(),
						wgConnSendCh:   wgConnSendCh,
					})
					wgConn.Close()
					s.wg.Done()
				}()

				s.logger.Info("New session",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("wgAddress", &s.wgAddrPort),
					zap.Int("wgTunnelMTU", wgTunnelMTU),
				)
			}

			select {
			case natEntry.wgConnSendCh <- queuedPacket{packetBuf, wgPacketStart, wgPacketLength}:
			default:
				if ce := s.logger.Check(zap.DebugLevel, "wgPacket dropped due to full send channel"); ce != nil {
					ce.Write(
						zap.String("server", s.name),
						zap.String("listenAddress", s.proxyListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("wgAddress", &s.wgAddrPort),
					)
				}
				s.putPacketBuf(packetBuf)
			}
		}

		s.mu.Unlock()
	}

	for i := range bufvec {
		s.putPacketBuf(bufvec[i])
	}

	s.logger.Info("Finished receiving from proxyConn",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListen),
		zap.Stringer("wgAddress", &s.wgAddrPort),
		zap.Uint64("recvmmsgCount", recvmmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("wgBytesReceived", wgBytesReceived),
		zap.Int("burstBatchSize", burstBatchSize),
	)
}

func (s *server) relayProxyToWgSendmmsg(uplink serverNatUplinkMmsg) {
	var (
		sendmmsgCount  uint64
		packetsSent    uint64
		wgBytesSent    uint64
		burstBatchSize int
	)

	rsa6 := conn.AddrPortToSockaddrInet6(s.wgAddrPort)
	bufvec := make([][]byte, s.relayBatchSize)
	iovec := make([]unix.Iovec, s.relayBatchSize)
	msgvec := make([]conn.Mmsghdr, s.relayBatchSize)

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
		dequeuedPacket, ok := <-uplink.wgConnSendCh
		if !ok {
			break
		}

	dequeue:
		for {
			// Update wgConn read deadline when a handshake initiation/response message is received.
			switch dequeuedPacket.buf[dequeuedPacket.start] {
			case packet.WireGuardMessageTypeHandshakeInitiation, packet.WireGuardMessageTypeHandshakeResponse:
				isHandshake = true
			}

			bufvec[count] = dequeuedPacket.buf
			iovec[count].Base = &dequeuedPacket.buf[dequeuedPacket.start]
			iovec[count].SetLen(dequeuedPacket.length)
			count++
			wgBytesSent += uint64(dequeuedPacket.length)

			if count == s.relayBatchSize {
				break
			}

			select {
			case dequeuedPacket, ok = <-uplink.wgConnSendCh:
				if !ok {
					break dequeue
				}
			default:
				break dequeue
			}
		}

		if err := uplink.wgConn.WriteMsgs(msgvec[:count], 0); err != nil {
			s.logger.Warn("Failed to write wgPacket to wgConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListen),
				zap.Stringer("clientAddress", uplink.clientAddrPort),
				zap.Stringer("wgAddress", &s.wgAddrPort),
				zap.Error(err),
			)
		}

		if isHandshake {
			if err := uplink.wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
				s.logger.Warn("Failed to SetReadDeadline on wgConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListen),
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Stringer("wgAddress", &s.wgAddrPort),
					zap.Error(err),
				)
			}
		}

		sendmmsgCount++
		packetsSent += uint64(count)
		if burstBatchSize < count {
			burstBatchSize = count
		}

		bufvecn := bufvec[:count]

		for i := range bufvecn {
			s.putPacketBuf(bufvecn[i])
		}

		if !ok {
			break
		}
	}

	s.logger.Info("Finished relay proxyConn -> wgConn",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListen),
		zap.Stringer("clientAddress", uplink.clientAddrPort),
		zap.Stringer("wgAddress", &s.wgAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
	)
}

func (s *server) relayWgToProxySendmmsg(downlink serverNatDownlinkMmsg) {
	var (
		sendmmsgCount  uint64
		packetsSent    uint64
		wgBytesSent    uint64
		burstBatchSize int
	)

	clientPktinfop := downlink.clientPktinfop
	clientPktinfo := *clientPktinfop

	name, namelen := conn.AddrPortToSockaddr(downlink.clientAddrPort)
	frontOverhead := s.handler.FrontOverhead()
	rearOverhead := s.handler.RearOverhead()
	plaintextLen := downlink.maxProxyPacketSize - frontOverhead - rearOverhead

	savec := make([]unix.RawSockaddrInet6, s.relayBatchSize)
	bufvec := make([][]byte, s.relayBatchSize)
	riovec := make([]unix.Iovec, s.relayBatchSize)
	siovec := make([]unix.Iovec, s.relayBatchSize)
	rmsgvec := make([]conn.Mmsghdr, s.relayBatchSize)
	smsgvec := make([]conn.Mmsghdr, s.relayBatchSize)

	for i := 0; i < s.relayBatchSize; i++ {
		bufvec[i] = make([]byte, downlink.maxProxyPacketSize)

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
		nr, err := downlink.wgConn.ReadMsgs(rmsgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			s.logger.Warn("Failed to read from wgConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListen),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("wgAddress", &s.wgAddrPort),
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
					zap.String("listenAddress", s.proxyListen),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("wgAddress", &s.wgAddrPort),
					zap.Error(err),
				)
				continue
			}
			if !conn.AddrPortMappedEqual(packetSourceAddrPort, s.wgAddrPort) {
				s.logger.Warn("Ignoring packet from non-wg address",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListen),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("wgAddress", &s.wgAddrPort),
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
					zap.String("listenAddress", s.proxyListen),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("wgAddress", &s.wgAddrPort),
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
					zap.String("listenAddress", s.proxyListen),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("wgAddress", &s.wgAddrPort),
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

		if cpp := downlink.clientPktinfo.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp

			for i := range smsgvec {
				smsgvec[i].Msghdr.Control = &clientPktinfo[0]
				smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
			}
		}

		err = downlink.proxyConn.WriteMsgs(smsgvec[:ns], 0)
		if err != nil {
			s.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListen),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("wgAddress", &s.wgAddrPort),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(ns)
		if burstBatchSize < ns {
			burstBatchSize = ns
		}
	}

	s.logger.Info("Finished relay wgConn -> proxyConn",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListen),
		zap.Stringer("clientAddress", downlink.clientAddrPort),
		zap.Stringer("wgAddress", &s.wgAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
	)
}
