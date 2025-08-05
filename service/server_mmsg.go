//go:build linux || netbsd

package service

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/packet"
	"github.com/database64128/swgp-go/tslog"
	"golang.org/x/sys/unix"
)

type serverNatUplinkMmsg struct {
	wgAddrPort   netip.AddrPort
	wgConnIs4    bool
	wgConn       *conn.MmsgWConn
	wgConnInfo   conn.SocketInfo
	wgConnSendCh <-chan queuedPacket
	logger       *tslog.Logger
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
	logger             *tslog.Logger
}

func (s *server) start(ctx context.Context) error {
	if s.disableMmsg {
		return s.startGeneric(ctx)
	}
	return s.startMmsg(ctx)
}

func (s *server) startMmsg(ctx context.Context) error {
	proxyConn, proxyConnInfo, err := s.proxyConnListenConfig.ListenUDPMmsgConn(ctx, s.proxyListenNetwork, s.proxyListenAddress)
	if err != nil {
		return err
	}
	s.proxyConn = proxyConn.UDPConn
	s.proxyListenAddress = proxyConn.LocalAddr().String()

	if proxyConnInfo.UDPGenericReceiveOffload {
		s.packetBufSize = 65535
	} else {
		s.packetBufSize = s.maxProxyPacketSizev4
	}

	logger := s.logger.WithAttrs(
		slog.String("server", s.name),
		slog.String("listenAddress", s.proxyListenAddress),
	)

	s.mwg.Add(1)

	go func() {
		s.recvFromProxyConnRecvmmsg(ctx, logger, proxyConn.NewRConn(), proxyConnInfo)
		s.mwg.Done()
	}()

	logger.Info("Started service",
		tslog.ConnAddrp("wgAddress", &s.wgAddr),
		slog.Int("wgTunnelMTUv4", s.wgTunnelMTUv4),
		slog.Int("wgTunnelMTUv6", s.wgTunnelMTUv6),
		tslog.Uint("maxUDPGSOSegments", proxyConnInfo.MaxUDPGSOSegments),
		slog.Bool("udpGRO", proxyConnInfo.UDPGenericReceiveOffload),
	)
	return nil
}

func (s *server) recvFromProxyConnRecvmmsg(ctx context.Context, logger *tslog.Logger, proxyConn *conn.MmsgRConn, proxyConnInfo conn.SocketInfo) {
	packetBuf := make([]byte, s.mainRecvBatchSize*s.packetBufSize)
	cmsgBuf := make([]byte, s.mainRecvBatchSize*conn.SocketControlMessageBufferSize)
	namevec := make([]unix.RawSockaddrInet6, s.mainRecvBatchSize)
	iovec := make([]unix.Iovec, s.mainRecvBatchSize)
	msgvec := make([]conn.Mmsghdr, s.mainRecvBatchSize)

	packetBufp := unsafe.Pointer(unsafe.SliceData(packetBuf))
	cmsgBufp := unsafe.Pointer(unsafe.SliceData(cmsgBuf))

	for i := range s.mainRecvBatchSize {
		iovec[i].Base = (*byte)(packetBufp)
		iovec[i].SetLen(s.packetBufSize)

		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&namevec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
		msgvec[i].Msghdr.Control = (*byte)(cmsgBufp)
		msgvec[i].Msghdr.SetControllen(conn.SocketControlMessageBufferSize)

		packetBufp = unsafe.Add(packetBufp, s.packetBufSize)
		cmsgBufp = unsafe.Add(cmsgBufp, conn.SocketControlMessageBufferSize)
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
			logger.Warn("Failed to read from proxyConn", tslog.Err(err))
			continue
		}

		recvmmsgCount++
		msgsReceived += uint64(n)
		burstBatchSize = max(burstBatchSize, n)

		s.mu.Lock()

		msgvecn := msgvec[:n]
		remainingPacketBuf := packetBuf
		remainingCmsgBuf := cmsgBuf

		for i := range msgvecn {
			msg := &msgvecn[i]
			swgpPacketBuf := remainingPacketBuf[:msg.Msglen]
			remainingPacketBuf = remainingPacketBuf[s.packetBufSize:]
			cmsg := remainingCmsgBuf[:msg.Msghdr.Controllen]
			remainingCmsgBuf = remainingCmsgBuf[conn.SocketControlMessageBufferSize:]
			msg.Msghdr.SetControllen(conn.SocketControlMessageBufferSize)

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				logger.Error("Failed to parse sockaddr of packet from proxyConn", tslog.Err(err))
				continue
			}

			if err = conn.ParseFlagsForError(int(msg.Msghdr.Flags)); err != nil {
				logger.Warn("Discarded packet from proxyConn",
					tslog.AddrPort("clientAddress", clientAddrPort),
					tslog.Uint("packetLength", msg.Msglen),
					slog.Int("cmsgLength", len(cmsg)),
					tslog.Err(err),
				)
				continue
			}

			rscm, err := conn.ParseSocketControlMessage(cmsg)
			if err != nil {
				logger.Error("Failed to parse socket control message from proxyConn",
					tslog.AddrPort("clientAddress", clientAddrPort),
					slog.Int("cmsgLength", len(cmsg)),
					tslog.Err(err),
				)
				continue
			}

			swgpBytesReceived += uint64(msg.Msglen)

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
					logger.Warn("Failed to decrypt swgpPacket",
						tslog.AddrPort("clientAddress", clientAddrPort),
						slog.Int("packetLength", swgpPacketLength),
						tslog.Err(err),
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

				if logger.Enabled(slog.LevelDebug) {
					logger.Debug("Updated client pktinfo",
						tslog.AddrPort("clientAddress", clientAddrPort),
						tslog.Addrp("clientPktinfoAddr", &clientPktinfop.addr),
						tslog.Uint("clientPktinfoIfindex", clientPktinfoCache.ifindex),
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
						logger.Warn("Failed to resolve wgAddr",
							tslog.AddrPort("clientAddress", clientAddrPort),
							tslog.Err(err),
						)
						return
					}

					wgConnListenNetwork := listenUDPNetworkForRemoteAddr(wgAddrPort.Addr())

					wgConn, wgConnInfo, err := s.wgConnListenConfig.ListenUDPMmsgConn(ctx, wgConnListenNetwork, s.wgConnListenAddress)
					if err != nil {
						logger.Warn("Failed to create UDP socket for new session",
							tslog.AddrPort("clientAddress", clientAddrPort),
							slog.String("wgConnListenNetwork", wgConnListenNetwork),
							slog.String("wgConnListenAddress", s.wgConnListenAddress),
							tslog.Err(err),
						)
						return
					}

					wgConnListenAddrPort := wgConn.LocalAddr().(*net.UDPAddr).AddrPort()

					if err = wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
						logger.Error("Failed to SetReadDeadline on wgConn",
							tslog.AddrPort("clientAddress", clientAddrPort),
							tslog.AddrPort("wgConnListenAddress", wgConnListenAddrPort),
							tslog.Err(err),
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

					sesLogger := logger.WithAttrs(
						tslog.AddrPort("clientAddress", clientAddrPort),
						tslog.AddrPort("wgConnListenAddress", wgConnListenAddrPort),
						tslog.AddrPort("wgAddress", wgAddrPort),
					)

					sesLogger.Info("Server relay started",
						slog.Int("wgTunnelMTU", wgTunnelMTU),
						tslog.Uint("maxUDPGSOSegments", wgConnInfo.MaxUDPGSOSegments),
						slog.Bool("udpGRO", wgConnInfo.UDPGenericReceiveOffload),
					)

					s.wg.Add(1)

					go func() {
						s.relayProxyToWgSendmmsg(serverNatUplinkMmsg{
							wgAddrPort:   wgAddrPort,
							wgConnIs4:    wgConnListenAddrPort.Addr().Is4(),
							wgConn:       wgConn.NewWConn(),
							wgConnInfo:   wgConnInfo,
							wgConnSendCh: wgConnSendCh,
							logger:       sesLogger,
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
						logger:             sesLogger,
					})
				}()

				if logger.Enabled(slog.LevelDebug) {
					logger.Debug("New server session",
						tslog.AddrPort("clientAddress", clientAddrPort),
						tslog.ConnAddrp("wgAddress", &s.wgAddr),
					)
				}
			}

			for _, qp := range queuedPackets {
				select {
				case natEntry.wgConnSendCh <- qp:
				default:
					if logger.Enabled(slog.LevelDebug) {
						logger.Debug("wgPacket dropped due to full send channel",
							tslog.AddrPort("clientAddress", clientAddrPort),
							tslog.ConnAddrp("wgAddress", &s.wgAddr),
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

	logger.Info("Finished receiving from proxyConn",
		tslog.ConnAddrp("wgAddress", &s.wgAddr),
		tslog.Uint("recvmmsgCount", recvmmsgCount),
		tslog.Uint("msgsReceived", msgsReceived),
		tslog.Uint("packetsReceived", packetsReceived),
		tslog.Uint("swgpBytesReceived", swgpBytesReceived),
		slog.Int("burstBatchSize", burstBatchSize),
		tslog.Uint("burstSegmentCount", burstSegmentCount),
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

	name, namelen := conn.AddrPortToSockaddrWithAddressFamily(uplink.wgAddrPort, uplink.wgConnIs4)
	cmsgBuf := make([]byte, 0, s.relayBatchSize*conn.SocketControlMessageBufferSize)
	bufvec := make([][]byte, 0, s.relayBatchSize)
	iovec := make([]unix.Iovec, 0, s.relayBatchSize)
	msgvec := make([]conn.Mmsghdr, 0, s.relayBatchSize)

	for {
		// Block on first dequeue op.
		qp, ok := <-uplink.wgConnSendCh
		if !ok {
			break
		}

		var isHandshake bool

	dequeue:
		for {
			bufvec = append(bufvec, qp.buf)

			// Update wgConn read deadline when qp contains a WireGuard handshake initiation message.
			if qp.isWireGuardHandshakeInitiationMessage() {
				isHandshake = true
			}

			b := qp.buf
			segmentsRemaining := qp.segmentCount

			maxUDPGSOSegments := uplink.wgConnInfo.MaxUDPGSOSegments
			if maxUDPGSOSegments > 1 {
				// Cap each coalesced message to 65535 bytes to prevent -EMSGSIZE.
				maxUDPGSOSegments = max(1, 65535/qp.segmentSize)
			}

			for segmentsRemaining > 0 {
				sendSegmentCount := min(segmentsRemaining, maxUDPGSOSegments)
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
						Name:    name,
						Namelen: namelen,
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
				uplink.logger.Warn("Failed to write wgPacket to wgConn",
					tslog.Uint("wgPacketLength", iovec[start].Len),
					tslog.Err(err),
				)
				start++
			}

			sendmmsgCount++
			msgsSent += uint64(n)
			burstBatchSize = max(burstBatchSize, n)
		}

		if isHandshake {
			if err := uplink.wgConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
				uplink.logger.Error("Failed to SetReadDeadline on wgConn", tslog.Err(err))
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

	uplink.logger.Info("Finished relay proxyConn -> wgConn",
		tslog.Uint("sendmmsgCount", sendmmsgCount),
		tslog.Uint("msgsSent", msgsSent),
		tslog.Uint("packetsSent", packetsSent),
		tslog.Uint("wgBytesSent", wgBytesSent),
		slog.Int("burstBatchSize", burstBatchSize),
		tslog.Uint("burstSegmentCount", burstSegmentCount),
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
	riovec := make([]unix.Iovec, s.relayBatchSize)
	siovec := make([]unix.Iovec, 0, s.relayBatchSize)
	rmsgvec := make([]conn.Mmsghdr, s.relayBatchSize)
	smsgvec := make([]conn.Mmsghdr, 0, s.relayBatchSize)

	recvPacketBufp := unsafe.Pointer(unsafe.SliceData(recvPacketBuf))
	recvCmsgBufp := unsafe.Pointer(unsafe.SliceData(recvCmsgBuf))

	for i := range s.relayBatchSize {
		riovec[i].Base = (*byte)(recvPacketBufp)
		riovec[i].SetLen(downlink.maxProxyPacketSize)

		rmsgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&savec[i]))
		rmsgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		rmsgvec[i].Msghdr.Iov = &riovec[i]
		rmsgvec[i].Msghdr.SetIovlen(1)
		rmsgvec[i].Msghdr.Control = (*byte)(recvCmsgBufp)
		rmsgvec[i].Msghdr.SetControllen(conn.SocketControlMessageBufferSize)

		recvPacketBufp = unsafe.Add(recvPacketBufp, downlink.maxProxyPacketSize)
		recvCmsgBufp = unsafe.Add(recvCmsgBufp, conn.SocketControlMessageBufferSize)
	}

	for {
		nr, err := downlink.wgConn.ReadMsgs(rmsgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			downlink.logger.Warn("Failed to read from wgConn", tslog.Err(err))
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
		remainingRecvPacketBuf := recvPacketBuf
		remainingRecvCmsgBuf := recvCmsgBuf

		for i := range rmsgvecn {
			msg := &rmsgvecn[i]
			wgPacketBuf := remainingRecvPacketBuf[:msg.Msglen]
			remainingRecvPacketBuf = remainingRecvPacketBuf[downlink.maxProxyPacketSize:]
			cmsg := remainingRecvCmsgBuf[:msg.Msghdr.Controllen]
			remainingRecvCmsgBuf = remainingRecvCmsgBuf[conn.SocketControlMessageBufferSize:]
			msg.Msghdr.SetControllen(conn.SocketControlMessageBufferSize)

			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				downlink.logger.Error("Failed to parse sockaddr of packet from wgConn", tslog.Err(err))
				continue
			}
			if !conn.AddrPortMappedEqual(packetSourceAddrPort, downlink.wgAddrPort) {
				downlink.logger.Warn("Ignoring packet from non-wg address",
					tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
					tslog.Uint("packetLength", msg.Msglen),
					tslog.Err(err),
				)
				continue
			}

			if err = conn.ParseFlagsForError(int(msg.Msghdr.Flags)); err != nil {
				downlink.logger.Warn("Discarded packet from wgConn",
					tslog.Uint("packetLength", msg.Msglen),
					slog.Int("cmsgLength", len(cmsg)),
					tslog.Err(err),
				)
				continue
			}

			rscm, err := conn.ParseSocketControlMessage(cmsg)
			if err != nil {
				downlink.logger.Error("Failed to parse socket control message from wgConn",
					tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
					slog.Int("cmsgLength", len(cmsg)),
					tslog.Err(err),
				)
				continue
			}

			wgBytesReceived += uint64(msg.Msglen)

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
					downlink.logger.Warn("Failed to encrypt wgPacket",
						slog.Int("packetLength", wgPacketLength),
						tslog.Err(err),
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

			maxUDPGSOSegments := downlink.proxyConnInfo.MaxUDPGSOSegments
			if maxUDPGSOSegments > 1 {
				// Cap each coalesced message to 65535 bytes to prevent -EMSGSIZE.
				maxUDPGSOSegments = max(1, 65535/qp.segmentSize)
			}

			for segmentsRemaining > 0 {
				sendSegmentCount := min(segmentsRemaining, maxUDPGSOSegments)
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
				downlink.logger.Warn("Failed to write swgpPacket to proxyConn",
					tslog.Uint("swgpPacketLength", siovec[start].Len),
					tslog.Err(err),
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

	downlink.logger.Info("Finished relay wgConn -> proxyConn",
		tslog.Uint("recvmmmsgCount", recvmmmsgCount),
		tslog.Uint("msgsReceived", msgsReceived),
		tslog.Uint("packetsReceived", packetsReceived),
		tslog.Uint("wgBytesReceived", wgBytesReceived),
		tslog.Uint("sendmmsgCount", sendmmsgCount),
		tslog.Uint("msgsSent", msgsSent),
		tslog.Uint("packetsSent", packetsSent),
		tslog.Uint("swgpBytesSent", swgpBytesSent),
		slog.Int("burstRecvBatchSize", burstRecvBatchSize),
		slog.Int("burstSendBatchSize", burstSendBatchSize),
		tslog.Uint("burstRecvSegmentCount", burstRecvSegmentCount),
		tslog.Uint("burstSendSegmentCount", burstSendSegmentCount),
	)
}
