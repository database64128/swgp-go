//go:build linux || netbsd

package service

import (
	"context"
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
	wgAddrPort     netip.AddrPort
	wgConn         *conn.MmsgWConn
	wgConnInfo     conn.SocketInfo
	wgConnSendCh   <-chan queuedPacket
}

type serverNatDownlinkMmsg struct {
	clientAddrPort     netip.AddrPort
	clientPktinfop     *pktinfo
	clientPktinfo      *atomic.Pointer[pktinfo]
	wgAddrPort         netip.AddrPort
	wgConn             *conn.MmsgRConn
	proxyConn          *conn.MmsgWConn
	proxyConnInfo      conn.SocketInfo
	handler            packet.Handler
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

func (s *server) startMmsg(ctx context.Context) error {
	proxyConn, proxyConnInfo, err := s.proxyConnListenConfig.ListenUDPMmsgConn(ctx, s.proxyListenNetwork, s.proxyListenAddress)
	if err != nil {
		return err
	}
	s.proxyConn = proxyConn.UDPConn

	if proxyConnInfo.UDPGenericReceiveOffload {
		s.packetBufSize = 65535
	} else {
		s.packetBufSize = s.maxProxyPacketSizev4
	}

	s.mwg.Add(1)

	go func() {
		s.recvFromProxyConnRecvmmsg(ctx, proxyConn.NewRConn(), proxyConnInfo)
		s.mwg.Done()
	}()

	s.logger.Info("Started service",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListenAddress),
		zap.Stringer("wgAddress", &s.wgAddr),
		zap.Int("wgTunnelMTUv4", s.wgTunnelMTUv4),
		zap.Int("wgTunnelMTUv6", s.wgTunnelMTUv6),
		zap.Uint32("maxUDPGSOSegments", proxyConnInfo.MaxUDPGSOSegments),
		zap.Bool("udpGRO", proxyConnInfo.UDPGenericReceiveOffload),
	)
	return nil
}

func (s *server) recvFromProxyConnRecvmmsg(ctx context.Context, proxyConn *conn.MmsgRConn, proxyConnInfo conn.SocketInfo) {
	packetBuf := make([]byte, s.mainRecvBatchSize*s.packetBufSize)
	cmsgBuf := make([]byte, s.mainRecvBatchSize*conn.SocketControlMessageBufferSize)
	bufvec := make([][]byte, s.mainRecvBatchSize)
	cmsgvec := make([][]byte, s.mainRecvBatchSize)
	namevec := make([]unix.RawSockaddrInet6, s.mainRecvBatchSize)
	iovec := make([]unix.Iovec, s.mainRecvBatchSize)
	msgvec := make([]conn.Mmsghdr, s.mainRecvBatchSize)

	for i := range s.mainRecvBatchSize {
		bufvec[i] = packetBuf[:s.packetBufSize:s.packetBufSize]
		packetBuf = packetBuf[s.packetBufSize:]

		cmsgvec[i] = cmsgBuf[:conn.SocketControlMessageBufferSize:conn.SocketControlMessageBufferSize]
		cmsgBuf = cmsgBuf[conn.SocketControlMessageBufferSize:]

		iovec[i].Base = unsafe.SliceData(bufvec[i])
		iovec[i].SetLen(s.packetBufSize)

		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&namevec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
		msgvec[i].Msghdr.Control = unsafe.SliceData(cmsgvec[i])
		msgvec[i].Msghdr.SetControllen(conn.SocketControlMessageBufferSize)
	}

	qp := queuedPacket{
		buf: s.getPacketBuf(),
	}

	var (
		queuedPackets     []queuedPacket
		recvmmsgCount     uint64
		msgsReceived      uint64
		packetsReceived   uint64
		swgpBytesReceived uint64
		burstBatchSize    int
		burstSegmentCount uint32
	)

	for {
		n, err := proxyConn.ReadMsgs(msgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			s.logger.Warn("Failed to read from proxyConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Error(err),
			)
			continue
		}

		recvmmsgCount++
		msgsReceived += uint64(n)
		burstBatchSize = max(burstBatchSize, n)

		s.mu.Lock()

		msgvecn := msgvec[:n]

		for i := range msgvecn {
			msg := &msgvecn[i]
			cmsg := cmsgvec[i][:msg.Msghdr.Controllen]
			msg.Msghdr.SetControllen(conn.SocketControlMessageBufferSize)

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from proxyConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Error(err),
				)
				continue
			}

			if err = conn.ParseFlagsForError(int(msg.Msghdr.Flags)); err != nil {
				s.logger.Warn("Discarded packet from proxyConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Int("cmsgLength", len(cmsg)),
					zap.Error(err),
				)
				continue
			}

			rscm, err := conn.ParseSocketControlMessage(cmsg)
			if err != nil {
				s.logger.Warn("Failed to parse socket control message from proxyConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Int("cmsgLength", len(cmsg)),
					zap.Error(err),
				)
				continue
			}

			swgpBytesReceived += uint64(msg.Msglen)

			swgpPacketBuf := bufvec[i][:msg.Msglen]

			recvSegmentSize := int(rscm.SegmentSize)
			if recvSegmentSize == 0 {
				recvSegmentSize = len(swgpPacketBuf)
			}

			var (
				segmentCount uint32
				handler      packet.Handler
			)

			clientAddr := clientAddrPort.Addr()
			isClientAddr4 := clientAddr.Is4() || clientAddr.Is4In6()
			if isClientAddr4 {
				handler = s.handler4
			} else {
				handler = s.handler6
			}

			for len(swgpPacketBuf) > 0 {
				swgpPacketLength := min(len(swgpPacketBuf), recvSegmentSize)
				swgpPacket := swgpPacketBuf[:swgpPacketLength]
				swgpPacketBuf = swgpPacketBuf[swgpPacketLength:]
				segmentCount++

				dst, err := handler.Decrypt(qp.buf, swgpPacket)
				if err != nil {
					s.logger.Warn("Failed to decrypt swgpPacket",
						zap.String("server", s.name),
						zap.String("listenAddress", s.proxyListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Int("packetLength", swgpPacketLength),
						zap.Error(err),
					)
					continue
				}

				segmentSize := uint32(len(dst) - len(qp.buf))

				switch {
				case qp.segmentSize == 0:
					qp = queuedPacket{
						buf:          dst,
						segmentSize:  segmentSize,
						segmentCount: 1,
					}
				case qp.segmentSize < segmentSize:
					// Move segment to a new wgPacket.
					segment := dst[len(qp.buf):]
					queuedPackets = append(queuedPackets, qp)
					qp = queuedPacket{
						buf:          append(s.getPacketBuf(), segment...),
						segmentSize:  segmentSize,
						segmentCount: 1,
					}
				case qp.segmentSize == segmentSize:
					// Keep segment.
					qp.buf = dst
					qp.segmentCount++
				case qp.segmentSize > segmentSize:
					// Segment is the last short segment.
					qp.buf = dst
					qp.segmentCount++
					queuedPackets = append(queuedPackets, qp)
					qp = queuedPacket{
						buf: s.getPacketBuf(),
					}
				default:
					panic("unreachable")
				}
			}

			packetsReceived += uint64(segmentCount)
			burstSegmentCount = max(burstSegmentCount, segmentCount)

			if len(qp.buf) > 0 {
				queuedPackets = append(queuedPackets, qp)
				qp = queuedPacket{
					buf: s.getPacketBuf(),
				}
			}

			if len(queuedPackets) == 0 {
				continue
			}

			// Another possible approach is to process all received packets
			// before looking up the NAT table and sending them away.

			natEntry, ok := s.table[clientAddrPort]
			if !ok {
				natEntry = &serverNatEntry{}
			}

			clientPktinfo := pktinfo{
				addr:    rscm.PktinfoAddr,
				ifindex: rscm.PktinfoIfindex,
			}

			var clientPktinfop *pktinfo

			if clientPktinfo != natEntry.clientPktinfoCache {
				clientPktinfoCache := clientPktinfo
				clientPktinfop = &clientPktinfoCache
				natEntry.clientPktinfo.Store(clientPktinfop)
				natEntry.clientPktinfoCache = clientPktinfoCache

				if ce := s.logger.Check(zap.DebugLevel, "Updated client pktinfo"); ce != nil {
					ce.Write(
						zap.String("server", s.name),
						zap.String("listenAddress", s.proxyListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("clientPktinfoAddr", &clientPktinfop.addr),
						zap.Uint32("clientPktinfoIfindex", clientPktinfoCache.ifindex),
					)
				}
			}

			if !ok {
				wgConnSendCh := make(chan queuedPacket, s.sendChannelCapacity)
				natEntry.wgConnSendCh = wgConnSendCh
				s.table[clientAddrPort] = natEntry
				s.wg.Add(1)

				go func() {
					var sendChClean bool

					defer func() {
						s.mu.Lock()
						close(wgConnSendCh)
						delete(s.table, clientAddrPort)
						s.mu.Unlock()

						if !sendChClean {
							for queuedPacket := range wgConnSendCh {
								s.putPacketBuf(queuedPacket.buf)
							}
						}

						s.wg.Done()
					}()

					wgAddrPort, err := s.wgAddr.ResolveIPPort(ctx, s.wgNetwork)
					if err != nil {
						s.logger.Warn("Failed to resolve wgAddr",
							zap.String("server", s.name),
							zap.String("listenAddress", s.proxyListenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Error(err),
						)
						return
					}

					wgConn, wgConnInfo, err := s.wgConnListenConfig.ListenUDPMmsgConn(ctx, s.wgConnListenNetwork, s.wgConnListenAddress)
					if err != nil {
						s.logger.Warn("Failed to create UDP socket for new session",
							zap.String("server", s.name),
							zap.String("listenAddress", s.proxyListenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Error(err),
						)
						return
					}

					err = wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
					if err != nil {
						s.logger.Warn("Failed to SetReadDeadline on wgConn",
							zap.String("server", s.name),
							zap.String("listenAddress", s.proxyListenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Error(err),
						)
						wgConn.Close()
						return
					}

					oldState := natEntry.state.Swap(wgConn.UDPConn)
					if oldState != nil {
						wgConn.Close()
						return
					}

					// No more early returns!
					sendChClean = true

					var (
						maxProxyPacketSize int
						wgTunnelMTU        int
					)

					if isClientAddr4 {
						maxProxyPacketSize = s.maxProxyPacketSizev4
						wgTunnelMTU = s.wgTunnelMTUv4
					} else {
						maxProxyPacketSize = s.maxProxyPacketSizev6
						wgTunnelMTU = s.wgTunnelMTUv6
					}

					if wgConnInfo.UDPGenericReceiveOffload {
						maxProxyPacketSize = 65535
					}

					s.logger.Info("Server relay started",
						zap.String("server", s.name),
						zap.String("listenAddress", s.proxyListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("wgAddress", wgAddrPort),
						zap.Int("wgTunnelMTU", wgTunnelMTU),
						zap.Uint32("maxUDPGSOSegments", wgConnInfo.MaxUDPGSOSegments),
						zap.Bool("udpGRO", wgConnInfo.UDPGenericReceiveOffload),
					)

					s.wg.Add(1)

					go func() {
						s.relayProxyToWgSendmmsg(serverNatUplinkMmsg{
							clientAddrPort: clientAddrPort,
							wgAddrPort:     wgAddrPort,
							wgConn:         wgConn.NewWConn(),
							wgConnInfo:     wgConnInfo,
							wgConnSendCh:   wgConnSendCh,
						})
						wgConn.Close()
						s.wg.Done()
					}()

					s.relayWgToProxySendmmsg(serverNatDownlinkMmsg{
						clientAddrPort:     clientAddrPort,
						clientPktinfop:     clientPktinfop,
						clientPktinfo:      &natEntry.clientPktinfo,
						wgAddrPort:         wgAddrPort,
						wgConn:             wgConn.NewRConn(),
						proxyConn:          proxyConn.NewWConn(),
						proxyConnInfo:      proxyConnInfo,
						handler:            handler,
						maxProxyPacketSize: maxProxyPacketSize,
					})
				}()

				if ce := s.logger.Check(zap.DebugLevel, "New server session"); ce != nil {
					ce.Write(
						zap.String("server", s.name),
						zap.String("listenAddress", s.proxyListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("wgAddress", &s.wgAddr),
					)
				}
			}

			for _, qp := range queuedPackets {
				select {
				case natEntry.wgConnSendCh <- qp:
				default:
					if ce := s.logger.Check(zap.DebugLevel, "wgPacket dropped due to full send channel"); ce != nil {
						ce.Write(
							zap.String("server", s.name),
							zap.String("listenAddress", s.proxyListenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Stringer("wgAddress", &s.wgAddr),
						)
					}
					s.putPacketBuf(qp.buf)
				}
			}

			queuedPackets = queuedPackets[:0]
		}

		s.mu.Unlock()
	}

	s.putPacketBuf(qp.buf)

	s.logger.Info("Finished receiving from proxyConn",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListenAddress),
		zap.Stringer("wgAddress", &s.wgAddr),
		zap.Uint64("recvmmsgCount", recvmmsgCount),
		zap.Uint64("msgsReceived", msgsReceived),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("swgpBytesReceived", swgpBytesReceived),
		zap.Int("burstBatchSize", burstBatchSize),
		zap.Uint32("burstSegmentCount", burstSegmentCount),
	)
}

func (s *server) relayProxyToWgSendmmsg(uplink serverNatUplinkMmsg) {
	var (
		sendmmsgCount     uint64
		msgsSent          uint64
		packetsSent       uint64
		wgBytesSent       uint64
		burstBatchSize    int
		burstSegmentCount uint32
	)

	// TODO: use wgConn's listen address to determine the address family
	rsa6 := conn.AddrPortToSockaddrInet6(uplink.wgAddrPort)
	cmsgBuf := make([]byte, 0, s.relayBatchSize*conn.SocketControlMessageBufferSize)
	bufvec := make([][]byte, 0, s.relayBatchSize)
	iovec := make([]unix.Iovec, 0, s.relayBatchSize)
	msgvec := make([]conn.Mmsghdr, 0, s.relayBatchSize)

	for {
		var isHandshake bool

		// Block on first dequeue op.
		qp, ok := <-uplink.wgConnSendCh
		if !ok {
			break
		}

	dequeue:
		for {
			bufvec = append(bufvec, qp.buf)

			// Update wgConn read deadline when qp contains a WireGuard handshake initiation message.
			if qp.isWireGuardHandshakeInitiationMessage() {
				isHandshake = true
			}

			b := qp.buf
			segmentsRemaining := qp.segmentCount

			for segmentsRemaining > 0 {
				sendSegmentCount := min(segmentsRemaining, uplink.wgConnInfo.MaxUDPGSOSegments)
				segmentsRemaining -= sendSegmentCount

				sendBufSize := min(len(b), int(qp.segmentSize*sendSegmentCount))
				sendBuf := b[:sendBufSize]
				b = b[sendBufSize:]

				var cmsg []byte
				if sendSegmentCount > 1 {
					scm := conn.SocketControlMessage{
						SegmentSize: qp.segmentSize,
					}
					dst := scm.AppendTo(cmsgBuf)
					cmsg = dst[len(cmsgBuf):]
					cmsgBuf = dst
				}

				iovec = append(iovec, unix.Iovec{
					Base: unsafe.SliceData(sendBuf),
				})
				iovec[len(iovec)-1].SetLen(len(sendBuf))

				msgvec = append(msgvec, conn.Mmsghdr{
					Msghdr: unix.Msghdr{
						Name:    (*byte)(unsafe.Pointer(&rsa6)),
						Namelen: unix.SizeofSockaddrInet6,
						Iov:     &iovec[len(iovec)-1],
						Iovlen:  1,
						Control: unsafe.SliceData(cmsg),
					},
				})
				msgvec[len(msgvec)-1].Msghdr.SetControllen(len(cmsg))

				packetsSent += uint64(sendSegmentCount)
				burstSegmentCount = max(burstSegmentCount, sendSegmentCount)
			}

			wgBytesSent += uint64(len(qp.buf))

			if len(msgvec) >= s.relayBatchSize {
				break
			}

			select {
			case qp, ok = <-uplink.wgConnSendCh:
				if !ok {
					break dequeue
				}
			default:
				break dequeue
			}
		}

		for start := 0; start < len(msgvec); {
			n, err := uplink.wgConn.WriteMsgs(msgvec[start:], 0)
			start += n
			if err != nil {
				s.logger.Warn("Failed to write wgPacket to wgConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Stringer("wgAddress", uplink.wgAddrPort),
					zap.Uint("wgPacketLength", uint(iovec[start].Len)),
					zap.Error(err),
				)
				start++
			}

			sendmmsgCount++
			msgsSent += uint64(n)
			burstBatchSize = max(burstBatchSize, n)
		}

		if isHandshake {
			if err := uplink.wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
				s.logger.Warn("Failed to SetReadDeadline on wgConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Stringer("wgAddress", uplink.wgAddrPort),
					zap.Error(err),
				)
			}
		}

		cmsgBuf = cmsgBuf[:0]
		for _, buf := range bufvec {
			s.putPacketBuf(buf)
		}
		bufvec = bufvec[:0]
		iovec = iovec[:0]
		msgvec = msgvec[:0]

		if !ok {
			break
		}
	}

	s.logger.Info("Finished relay proxyConn -> wgConn",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListenAddress),
		zap.Stringer("clientAddress", uplink.clientAddrPort),
		zap.Stringer("wgAddress", uplink.wgAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("msgsSent", msgsSent),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
		zap.Uint32("burstSegmentCount", burstSegmentCount),
	)
}

func (s *server) relayWgToProxySendmmsg(downlink serverNatDownlinkMmsg) {
	var (
		clientPktinfo         pktinfo
		queuedPackets         []queuedPacket
		recvmmmsgCount        uint64
		msgsReceived          uint64
		packetsReceived       uint64
		wgBytesReceived       uint64
		sendmmsgCount         uint64
		msgsSent              uint64
		packetsSent           uint64
		swgpBytesSent         uint64
		burstRecvBatchSize    int
		burstSendBatchSize    int
		burstRecvSegmentCount uint32
		burstSendSegmentCount uint32
	)

	if downlink.clientPktinfop != nil {
		clientPktinfo = *downlink.clientPktinfop
	}

	name, namelen := conn.AddrPortToSockaddr(downlink.clientAddrPort)
	savec := make([]unix.RawSockaddrInet6, s.relayBatchSize)
	recvPacketBuf := make([]byte, s.relayBatchSize*downlink.maxProxyPacketSize)
	recvCmsgBuf := make([]byte, s.relayBatchSize*conn.SocketControlMessageBufferSize)
	sendPacketBuf := make([]byte, 0, s.relayBatchSize*downlink.maxProxyPacketSize)
	sendCmsgBuf := make([]byte, 0, s.relayBatchSize*conn.SocketControlMessageBufferSize)
	rbufvec := make([][]byte, s.relayBatchSize)
	rcmsgvec := make([][]byte, s.relayBatchSize)
	riovec := make([]unix.Iovec, s.relayBatchSize)
	siovec := make([]unix.Iovec, 0, s.relayBatchSize)
	rmsgvec := make([]conn.Mmsghdr, s.relayBatchSize)
	smsgvec := make([]conn.Mmsghdr, 0, s.relayBatchSize)

	for i := range s.relayBatchSize {
		rbufvec[i] = recvPacketBuf[:downlink.maxProxyPacketSize:downlink.maxProxyPacketSize]
		recvPacketBuf = recvPacketBuf[downlink.maxProxyPacketSize:]

		rcmsgvec[i] = recvCmsgBuf[:conn.SocketControlMessageBufferSize:conn.SocketControlMessageBufferSize]
		recvCmsgBuf = recvCmsgBuf[conn.SocketControlMessageBufferSize:]

		riovec[i].Base = unsafe.SliceData(rbufvec[i])
		riovec[i].SetLen(downlink.maxProxyPacketSize)

		rmsgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&savec[i]))
		rmsgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		rmsgvec[i].Msghdr.Iov = &riovec[i]
		rmsgvec[i].Msghdr.SetIovlen(1)
		rmsgvec[i].Msghdr.Control = unsafe.SliceData(rcmsgvec[i])
		rmsgvec[i].Msghdr.SetControllen(conn.SocketControlMessageBufferSize)
	}

	for {
		nr, err := downlink.wgConn.ReadMsgs(rmsgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			s.logger.Warn("Failed to read from wgConn",
				zap.String("server", s.name),
				zap.String("listenAddress", s.proxyListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("wgAddress", downlink.wgAddrPort),
				zap.Error(err),
			)
			continue
		}

		recvmmmsgCount++
		msgsReceived += uint64(nr)
		burstRecvBatchSize = max(burstRecvBatchSize, nr)

		var (
			qpLength       uint32
			qpSegmentSize  uint32
			qpSegmentCount uint32
		)

		rmsgvecn := rmsgvec[:nr]

		for i := range rmsgvecn {
			msg := &rmsgvecn[i]
			cmsg := rcmsgvec[i][:msg.Msghdr.Controllen]
			msg.Msghdr.SetControllen(conn.SocketControlMessageBufferSize)

			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from wgConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("wgAddress", downlink.wgAddrPort),
					zap.Error(err),
				)
				continue
			}
			if !conn.AddrPortMappedEqual(packetSourceAddrPort, downlink.wgAddrPort) {
				s.logger.Warn("Ignoring packet from non-wg address",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("wgAddress", downlink.wgAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			if err = conn.ParseFlagsForError(int(msg.Msghdr.Flags)); err != nil {
				s.logger.Warn("Discarded packet from wgConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("wgAddress", downlink.wgAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Int("cmsgLength", len(cmsg)),
					zap.Error(err),
				)
				continue
			}

			rscm, err := conn.ParseSocketControlMessage(cmsg)
			if err != nil {
				s.logger.Warn("Failed to parse socket control message from wgConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("wgAddress", downlink.wgAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Int("cmsgLength", len(cmsg)),
					zap.Error(err),
				)
				continue
			}

			wgBytesReceived += uint64(msg.Msglen)

			wgPacketBuf := rbufvec[i][:msg.Msglen]

			recvSegmentSize := int(rscm.SegmentSize)
			if recvSegmentSize == 0 {
				recvSegmentSize = len(wgPacketBuf)
			}

			var recvSegmentCount uint32

			for len(wgPacketBuf) > 0 {
				wgPacketLength := min(len(wgPacketBuf), recvSegmentSize)
				wgPacket := wgPacketBuf[:wgPacketLength]
				wgPacketBuf = wgPacketBuf[wgPacketLength:]
				recvSegmentCount++

				dst, err := downlink.handler.Encrypt(sendPacketBuf, wgPacket)
				if err != nil {
					s.logger.Warn("Failed to encrypt wgPacket",
						zap.String("server", s.name),
						zap.String("listenAddress", s.proxyListenAddress),
						zap.Stringer("clientAddress", downlink.clientAddrPort),
						zap.Stringer("wgAddress", downlink.wgAddrPort),
						zap.Int("packetLength", wgPacketLength),
						zap.Error(err),
					)
					continue
				}

				segmentSize := uint32(len(dst) - len(sendPacketBuf))

				switch {
				case qpLength == 0:
					qpLength = segmentSize
					qpSegmentSize = segmentSize
					qpSegmentCount = 1
				case qpSegmentSize < segmentSize:
					// Save existing qp and start a new one with the current segment.
					queuedPackets = append(queuedPackets, queuedPacket{
						buf:          sendPacketBuf[len(sendPacketBuf)-int(qpLength):],
						segmentSize:  qpSegmentSize,
						segmentCount: qpSegmentCount,
					})
					qpLength = segmentSize
					qpSegmentSize = segmentSize
					qpSegmentCount = 1
				case qpSegmentSize == segmentSize:
					// Keep segment.
					qpLength += segmentSize
					qpSegmentCount++
				case qpSegmentSize > segmentSize:
					// Segment is the last short segment.
					queuedPackets = append(queuedPackets, queuedPacket{
						buf:          dst[len(sendPacketBuf)-int(qpLength):],
						segmentSize:  qpSegmentSize,
						segmentCount: qpSegmentCount + 1,
					})
					qpLength = 0
				default:
					panic("unreachable")
				}

				sendPacketBuf = dst
			}

			packetsReceived += uint64(recvSegmentCount)
			burstRecvSegmentCount = max(burstRecvSegmentCount, recvSegmentCount)
		}

		if qpLength > 0 {
			queuedPackets = append(queuedPackets, queuedPacket{
				buf:          sendPacketBuf[len(sendPacketBuf)-int(qpLength):],
				segmentSize:  qpSegmentSize,
				segmentCount: qpSegmentCount,
			})
		}

		if len(queuedPackets) == 0 {
			continue
		}

		if cpp := downlink.clientPktinfo.Load(); cpp != downlink.clientPktinfop {
			clientPktinfo = *cpp
			downlink.clientPktinfop = cpp
		}

		for _, qp := range queuedPackets {
			b := qp.buf
			segmentsRemaining := qp.segmentCount

			for segmentsRemaining > 0 {
				sendSegmentCount := min(segmentsRemaining, downlink.proxyConnInfo.MaxUDPGSOSegments)
				segmentsRemaining -= sendSegmentCount

				sendBufSize := min(len(b), int(qp.segmentSize*sendSegmentCount))
				sendBuf := b[:sendBufSize]
				b = b[sendBufSize:]

				sscm := conn.SocketControlMessage{
					PktinfoAddr:    clientPktinfo.addr,
					PktinfoIfindex: clientPktinfo.ifindex,
				}
				if sendSegmentCount > 1 {
					sscm.SegmentSize = qp.segmentSize
				}
				dst := sscm.AppendTo(sendCmsgBuf)
				cmsg := dst[len(sendCmsgBuf):]
				sendCmsgBuf = dst

				siovec = append(siovec, unix.Iovec{
					Base: unsafe.SliceData(sendBuf),
				})
				siovec[len(siovec)-1].SetLen(len(sendBuf))

				smsgvec = append(smsgvec, conn.Mmsghdr{
					Msghdr: unix.Msghdr{
						Name:    name,
						Namelen: namelen,
						Iov:     &siovec[len(siovec)-1],
						Iovlen:  1,
						Control: unsafe.SliceData(cmsg),
					},
				})
				smsgvec[len(smsgvec)-1].Msghdr.SetControllen(len(cmsg))

				packetsSent += uint64(sendSegmentCount)
				swgpBytesSent += uint64(len(sendBuf))
				burstSendSegmentCount = max(burstSendSegmentCount, sendSegmentCount)
			}
		}

		queuedPackets = queuedPackets[:0]

		for start := 0; start < len(smsgvec); {
			n, err := downlink.proxyConn.WriteMsgs(smsgvec[start:], 0)
			start += n
			if err != nil {
				s.logger.Warn("Failed to write swgpPacket to proxyConn",
					zap.String("server", s.name),
					zap.String("listenAddress", s.proxyListenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("wgAddress", downlink.wgAddrPort),
					zap.Uint("swgpPacketLength", uint(siovec[start].Len)),
					zap.Error(err),
				)
				start++
			}

			sendmmsgCount++
			msgsSent += uint64(n)
			burstSendBatchSize = max(burstSendBatchSize, n)
		}

		sendPacketBuf = sendPacketBuf[:0]
		sendCmsgBuf = sendCmsgBuf[:0]
		siovec = siovec[:0]
		smsgvec = smsgvec[:0]
	}

	s.logger.Info("Finished relay wgConn -> proxyConn",
		zap.String("server", s.name),
		zap.String("listenAddress", s.proxyListenAddress),
		zap.Stringer("clientAddress", downlink.clientAddrPort),
		zap.Stringer("wgAddress", downlink.wgAddrPort),
		zap.Uint64("recvmmmsgCount", recvmmmsgCount),
		zap.Uint64("msgsReceived", msgsReceived),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("wgBytesReceived", wgBytesReceived),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("msgsSent", msgsSent),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("swgpBytesSent", swgpBytesSent),
		zap.Int("burstRecvBatchSize", burstRecvBatchSize),
		zap.Int("burstSendBatchSize", burstSendBatchSize),
		zap.Uint32("burstRecvSegmentCount", burstRecvSegmentCount),
		zap.Uint32("burstSendSegmentCount", burstSendSegmentCount),
	)
}
