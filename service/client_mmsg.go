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

type clientNatUplinkMmsg struct {
	clientAddrPort  netip.AddrPort
	proxyAddrPort   netip.AddrPort
	proxyConn       *conn.MmsgWConn
	proxyConnInfo   conn.SocketInfo
	proxyConnSendCh <-chan queuedPacket
	handler         packet.Handler
}

type clientNatDownlinkMmsg struct {
	clientAddrPort     netip.AddrPort
	clientPktinfop     *pktinfo
	clientPktinfo      *atomic.Pointer[pktinfo]
	proxyAddrPort      netip.AddrPort
	proxyConn          *conn.MmsgRConn
	wgConn             *conn.MmsgWConn
	wgConnInfo         conn.SocketInfo
	handler            packet.Handler
	maxProxyPacketSize int
}

func (c *client) setStartFunc(batchMode string) {
	switch batchMode {
	case "sendmmsg", "":
		c.startFunc = c.startMmsg
	default:
		c.startFunc = c.startGeneric
	}
}

func (c *client) startMmsg(ctx context.Context) error {
	wgConn, wgConnInfo, err := c.wgConnListenConfig.ListenUDPMmsgConn(ctx, c.wgListenNetwork, c.wgListenAddress)
	if err != nil {
		return err
	}
	c.wgConn = wgConn.UDPConn

	if wgConnInfo.UDPGenericReceiveOffload {
		c.packetBufSize = 65535
	} else {
		c.packetBufSize = c.maxProxyPacketSize
	}

	c.mwg.Add(1)

	go func() {
		c.recvFromWgConnRecvmmsg(ctx, wgConn.NewRConn(), wgConnInfo)
		c.mwg.Done()
	}()

	if ce := c.logger.Check(zap.InfoLevel, "Started service"); ce != nil {
		fields := make([]zap.Field, 0, 7)

		fields = append(fields,
			zap.String("client", c.name),
			zap.String("listenAddress", c.wgListenAddress),
			zap.Stringer("proxyAddress", &c.proxyAddr),
		)

		if c.proxyAddr.IsIP() {
			fields = append(fields, zap.Int("wgTunnelMTU", c.wgTunnelMTU))
		} else {
			fields = append(fields,
				zap.Int("wgTunnelMTUv4", c.wgTunnelMTU),
				zap.Int("wgTunnelMTUv6", c.wgTunnelMTUv6),
			)
		}

		fields = append(fields,
			zap.Uint32("maxUDPGSOSegments", wgConnInfo.MaxUDPGSOSegments),
			zap.Bool("udpGRO", wgConnInfo.UDPGenericReceiveOffload),
		)

		ce.Write(fields...)
	}
	return nil
}

func (c *client) recvFromWgConnRecvmmsg(ctx context.Context, wgConn *conn.MmsgRConn, wgConnInfo conn.SocketInfo) {
	cmsgBuf := make([]byte, c.mainRecvBatchSize*conn.SocketControlMessageBufferSize)
	bufvec := make([][]byte, c.mainRecvBatchSize)
	cmsgvec := make([][]byte, c.mainRecvBatchSize)
	namevec := make([]unix.RawSockaddrInet6, c.mainRecvBatchSize)
	iovec := make([]unix.Iovec, c.mainRecvBatchSize)
	msgvec := make([]conn.Mmsghdr, c.mainRecvBatchSize)

	for i := range c.mainRecvBatchSize {
		packetBuf := c.getPacketBuf()
		bufvec[i] = packetBuf

		cmsgvec[i] = cmsgBuf[:conn.SocketControlMessageBufferSize:conn.SocketControlMessageBufferSize]
		cmsgBuf = cmsgBuf[conn.SocketControlMessageBufferSize:]

		iovec[i].Base = unsafe.SliceData(packetBuf)
		iovec[i].SetLen(c.packetBufSize)

		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&namevec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
		msgvec[i].Msghdr.Control = unsafe.SliceData(cmsgvec[i])
		msgvec[i].Msghdr.SetControllen(conn.SocketControlMessageBufferSize)
	}

	var (
		recvmmsgCount     uint64
		msgsReceived      uint64
		packetsReceived   uint64
		wgBytesReceived   uint64
		burstBatchSize    int
		burstSegmentCount uint32
	)

	for {
		n, err := wgConn.ReadMsgs(msgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			c.logger.Warn("Failed to read from wgConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Error(err),
			)
			continue
		}

		recvmmsgCount++
		msgsReceived += uint64(n)
		burstBatchSize = max(burstBatchSize, n)

		c.mu.Lock()

		msgvecn := msgvec[:n]

		for i := range msgvecn {
			msg := &msgvecn[i]
			cmsg := cmsgvec[i][:msg.Msghdr.Controllen]
			msg.Msghdr.SetControllen(conn.SocketControlMessageBufferSize)

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				c.logger.Warn("Failed to parse sockaddr of packet from wgConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Error(err),
				)
				continue
			}

			if err = conn.ParseFlagsForError(int(msg.Msghdr.Flags)); err != nil {
				c.logger.Warn("Discarded packet from wgConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Int("cmsgLength", len(cmsg)),
					zap.Error(err),
				)
				continue
			}

			rscm, err := conn.ParseSocketControlMessage(cmsg)
			if err != nil {
				c.logger.Warn("Failed to parse socket control message from wgConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Int("cmsgLength", len(cmsg)),
					zap.Error(err),
				)
				continue
			}

			qp := queuedPacket{
				buf:          bufvec[i][:msg.Msglen],
				segmentSize:  msg.Msglen,
				segmentCount: 1,
			}

			if rscm.SegmentSize > 0 {
				qp.segmentSize = rscm.SegmentSize
				qp.segmentCount = (msg.Msglen + rscm.SegmentSize - 1) / rscm.SegmentSize
			}

			packetsReceived += uint64(qp.segmentCount)
			wgBytesReceived += uint64(msg.Msglen)
			burstSegmentCount = max(burstSegmentCount, qp.segmentCount)

			natEntry, ok := c.table[clientAddrPort]
			if !ok {
				natEntry = &clientNatEntry{}
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

				if ce := c.logger.Check(zap.DebugLevel, "Updated client pktinfo"); ce != nil {
					ce.Write(
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("clientPktinfoAddr", &clientPktinfop.addr),
						zap.Uint32("clientPktinfoIfindex", clientPktinfoCache.ifindex),
					)
				}
			}

			if !ok {
				proxyConnSendCh := make(chan queuedPacket, c.sendChannelCapacity)
				natEntry.proxyConnSendCh = proxyConnSendCh
				c.table[clientAddrPort] = natEntry
				c.wg.Add(1)

				go func() {
					var sendChClean bool

					defer func() {
						c.mu.Lock()
						close(proxyConnSendCh)
						delete(c.table, clientAddrPort)
						c.mu.Unlock()

						if !sendChClean {
							for queuedPacket := range proxyConnSendCh {
								c.putPacketBuf(queuedPacket.buf)
							}
						}

						c.wg.Done()
					}()

					proxyAddrPort, err := c.proxyAddr.ResolveIPPort(ctx, c.proxyNetwork)
					if err != nil {
						c.logger.Warn("Failed to resolve proxy address for new session",
							zap.String("client", c.name),
							zap.String("listenAddress", c.wgListenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Error(err),
						)
						return
					}

					proxyConn, proxyConnInfo, err := c.proxyConnListenConfig.ListenUDPMmsgConn(ctx, c.proxyConnListenNetwork, c.proxyConnListenAddress)
					if err != nil {
						c.logger.Warn("Failed to create UDP socket for new session",
							zap.String("client", c.name),
							zap.String("listenAddress", c.wgListenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Error(err),
						)
						return
					}

					err = proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
					if err != nil {
						c.logger.Warn("Failed to SetReadDeadline on proxyConn",
							zap.String("client", c.name),
							zap.String("listenAddress", c.wgListenAddress),
							zap.Stringer("clientAddress", clientAddrPort),
							zap.Error(err),
						)
						proxyConn.Close()
						return
					}

					oldState := natEntry.state.Swap(proxyConn.UDPConn)
					if oldState != nil {
						proxyConn.Close()
						return
					}

					// No more early returns!
					sendChClean = true

					maxProxyPacketSize := c.maxProxyPacketSize
					wgTunnelMTU := c.wgTunnelMTU
					handler := c.handler

					if c.proxyAddr.IsDomain() {
						if addr := proxyAddrPort.Addr(); !addr.Is4() && !addr.Is4In6() {
							maxProxyPacketSize = c.maxProxyPacketSizev6
							wgTunnelMTU = c.wgTunnelMTUv6
							handler = c.handler6
						}
					}

					if proxyConnInfo.UDPGenericReceiveOffload {
						maxProxyPacketSize = 65535
					}

					c.logger.Info("Client relay started",
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("proxyAddress", proxyAddrPort),
						zap.Int("wgTunnelMTU", wgTunnelMTU),
						zap.Uint32("maxUDPGSOSegments", proxyConnInfo.MaxUDPGSOSegments),
						zap.Bool("udpGRO", proxyConnInfo.UDPGenericReceiveOffload),
					)

					c.wg.Add(1)

					go func() {
						c.relayWgToProxySendmmsg(clientNatUplinkMmsg{
							clientAddrPort:  clientAddrPort,
							proxyAddrPort:   proxyAddrPort,
							proxyConn:       proxyConn.NewWConn(),
							proxyConnInfo:   proxyConnInfo,
							proxyConnSendCh: proxyConnSendCh,
							handler:         handler,
						})
						proxyConn.Close()
						c.wg.Done()
					}()

					c.relayProxyToWgSendmmsg(clientNatDownlinkMmsg{
						clientAddrPort:     clientAddrPort,
						clientPktinfop:     clientPktinfop,
						clientPktinfo:      &natEntry.clientPktinfo,
						proxyAddrPort:      proxyAddrPort,
						proxyConn:          proxyConn.NewRConn(),
						wgConn:             wgConn.NewWConn(),
						wgConnInfo:         wgConnInfo,
						handler:            handler,
						maxProxyPacketSize: maxProxyPacketSize,
					})
				}()

				if ce := c.logger.Check(zap.DebugLevel, "New client session"); ce != nil {
					ce.Write(
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("proxyAddress", &c.proxyAddr),
					)
				}
			}

			select {
			case natEntry.proxyConnSendCh <- qp:
				packetBuf := c.getPacketBuf()
				bufvec[i] = packetBuf
				iovec[i].Base = unsafe.SliceData(packetBuf)
			default:
				if ce := c.logger.Check(zap.DebugLevel, "swgpPacket dropped due to full send channel"); ce != nil {
					ce.Write(
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListenAddress),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("proxyAddress", &c.proxyAddr),
					)
				}
			}
		}

		c.mu.Unlock()
	}

	for i := range bufvec {
		c.putPacketBuf(bufvec[i])
	}

	c.logger.Info("Finished receiving from wgConn",
		zap.String("client", c.name),
		zap.String("listenAddress", c.wgListenAddress),
		zap.Stringer("proxyAddress", &c.proxyAddr),
		zap.Uint64("recvmmsgCount", recvmmsgCount),
		zap.Uint64("msgsReceived", msgsReceived),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("wgBytesReceived", wgBytesReceived),
		zap.Int("burstBatchSize", burstBatchSize),
		zap.Uint32("burstSegmentCount", burstSegmentCount),
	)
}

func (c *client) relayWgToProxySendmmsg(uplink clientNatUplinkMmsg) {
	var (
		sendQueuedPackets []queuedPacket
		sendmmsgCount     uint64
		msgsSent          uint64
		packetsSent       uint64
		swgpBytesSent     uint64
		burstBatchSize    int
		burstSegmentCount uint32
	)

	rsa6 := conn.AddrPortToSockaddrInet6(uplink.proxyAddrPort)
	packetBuf := make([]byte, 0, c.relayBatchSize*c.packetBufSize)
	cmsgBuf := make([]byte, 0, c.relayBatchSize*conn.SocketControlMessageBufferSize)
	iovec := make([]unix.Iovec, 0, c.relayBatchSize)
	msgvec := make([]conn.Mmsghdr, 0, c.relayBatchSize)

main:
	for {
		var isHandshake bool

		// Block on first dequeue op.
		rqp, ok := <-uplink.proxyConnSendCh
		if !ok {
			break
		}

	dequeue:
		for {
			// Update proxyConn read deadline when rqp contains a WireGuard handshake initiation message.
			if rqp.isWireGuardHandshakeInitiationMessage() { // TODO: merge into the loop below as an optimization
				isHandshake = true
			}

			wgPacketBuf := rqp.buf

			var (
				sqpLength       uint32
				sqpSegmentSize  uint32
				sqpSegmentCount uint32
			)

			for len(wgPacketBuf) > 0 {
				wgPacketLength := min(len(wgPacketBuf), int(rqp.segmentSize))
				wgPacket := wgPacketBuf[:wgPacketLength]
				wgPacketBuf = wgPacketBuf[wgPacketLength:]

				dst, err := uplink.handler.Encrypt(packetBuf, wgPacket)
				if err != nil {
					c.logger.Warn("Failed to encrypt wgPacket",
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListenAddress),
						zap.Stringer("clientAddress", uplink.clientAddrPort),
						zap.Int("wgPacketLength", wgPacketLength),
						zap.Error(err),
					)
					continue
				}

				segmentSize := uint32(len(dst) - len(packetBuf))

				switch {
				case sqpLength == 0:
					sqpLength = segmentSize
					sqpSegmentSize = segmentSize
					sqpSegmentCount = 1
				case sqpSegmentSize < segmentSize:
					// Save existing sqp and start a new one with the current segment.
					sendQueuedPackets = append(sendQueuedPackets, queuedPacket{
						buf:          packetBuf[len(packetBuf)-int(sqpLength):],
						segmentSize:  sqpSegmentSize,
						segmentCount: sqpSegmentCount,
					})
					sqpLength = segmentSize
					sqpSegmentSize = segmentSize
					sqpSegmentCount = 1
				case sqpSegmentSize == segmentSize:
					// Keep segment.
					sqpLength += segmentSize
					sqpSegmentCount++
				case sqpSegmentSize > segmentSize:
					// Segment is the last short segment.
					sendQueuedPackets = append(sendQueuedPackets, queuedPacket{
						buf:          dst[len(packetBuf)-int(sqpLength):],
						segmentSize:  sqpSegmentSize,
						segmentCount: sqpSegmentCount + 1,
					})
					sqpLength = 0
				default:
					panic("unreachable")
				}

				packetBuf = dst
			}

			if sqpLength > 0 {
				sendQueuedPackets = append(sendQueuedPackets, queuedPacket{
					buf:          packetBuf[len(packetBuf)-int(sqpLength):],
					segmentSize:  sqpSegmentSize,
					segmentCount: sqpSegmentCount,
				})
			}

			c.putPacketBuf(rqp.buf)

			if len(sendQueuedPackets) == 0 {
				continue main
			}

			if len(sendQueuedPackets) >= c.relayBatchSize {
				break
			}

			select {
			case rqp, ok = <-uplink.proxyConnSendCh:
				if !ok {
					break dequeue
				}
			default:
				break dequeue
			}
		}

		for _, sqp := range sendQueuedPackets {
			b := sqp.buf
			segmentsRemaining := sqp.segmentCount

			for segmentsRemaining > 0 {
				sendSegmentCount := min(segmentsRemaining, uplink.proxyConnInfo.MaxUDPGSOSegments)
				segmentsRemaining -= sendSegmentCount

				sendBufSize := min(len(b), int(sqp.segmentSize*sendSegmentCount))
				sendBuf := b[:sendBufSize]
				b = b[sendBufSize:]

				var cmsg []byte
				if sendSegmentCount > 1 {
					scm := conn.SocketControlMessage{
						SegmentSize: sqp.segmentSize,
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
				swgpBytesSent += uint64(len(sendBuf))
				burstSegmentCount = max(burstSegmentCount, uint32(sendSegmentCount))
			}
		}

		sendQueuedPackets = sendQueuedPackets[:0]

		for start := 0; start < len(msgvec); {
			n, err := uplink.proxyConn.WriteMsgs(msgvec[start:], 0)
			start += n
			if err != nil {
				c.logger.Warn("Failed to write swgpPacket to proxyConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Stringer("proxyAddress", uplink.proxyAddrPort),
					zap.Uint("swgpPacketLength", uint(iovec[start].Len)),
					zap.Error(err),
				)
				start++
			}

			sendmmsgCount++
			msgsSent += uint64(n)
			burstBatchSize = max(burstBatchSize, n)
		}

		if isHandshake {
			if err := uplink.proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
				c.logger.Warn("Failed to SetReadDeadline on proxyConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Stringer("proxyAddress", uplink.proxyAddrPort),
					zap.Error(err),
				)
			}
		}

		packetBuf = packetBuf[:0]
		cmsgBuf = cmsgBuf[:0]
		iovec = iovec[:0]
		msgvec = msgvec[:0]

		if !ok {
			break
		}
	}

	c.logger.Info("Finished relay wgConn -> proxyConn",
		zap.String("client", c.name),
		zap.String("listenAddress", c.wgListenAddress),
		zap.Stringer("clientAddress", uplink.clientAddrPort),
		zap.Stringer("proxyAddress", uplink.proxyAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("msgsSent", msgsSent),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("swgpBytesSent", swgpBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
		zap.Uint32("burstSegmentCount", burstSegmentCount),
	)
}

func (c *client) relayProxyToWgSendmmsg(downlink clientNatDownlinkMmsg) {
	var (
		clientPktinfo         pktinfo
		queuedPackets         []queuedPacket
		recvmmmsgCount        uint64
		msgsReceived          uint64
		packetsReceived       uint64
		swgpBytesReceived     uint64
		sendmmsgCount         uint64
		msgsSent              uint64
		packetsSent           uint64
		wgBytesSent           uint64
		burstRecvBatchSize    int
		burstSendBatchSize    int
		burstRecvSegmentCount uint32
		burstSendSegmentCount uint32
	)

	if downlink.clientPktinfop != nil {
		clientPktinfo = *downlink.clientPktinfop
	}

	name, namelen := conn.AddrPortToSockaddr(downlink.clientAddrPort)
	savec := make([]unix.RawSockaddrInet6, c.relayBatchSize)
	recvPacketBuf := make([]byte, c.relayBatchSize*downlink.maxProxyPacketSize)
	recvCmsgBuf := make([]byte, c.relayBatchSize*conn.SocketControlMessageBufferSize)
	sendPacketBuf := make([]byte, 0, c.relayBatchSize*downlink.maxProxyPacketSize)
	sendCmsgBuf := make([]byte, 0, c.relayBatchSize*conn.SocketControlMessageBufferSize)
	rbufvec := make([][]byte, c.relayBatchSize)
	rcmsgvec := make([][]byte, c.relayBatchSize)
	riovec := make([]unix.Iovec, c.relayBatchSize)
	siovec := make([]unix.Iovec, 0, c.relayBatchSize)
	rmsgvec := make([]conn.Mmsghdr, c.relayBatchSize)
	smsgvec := make([]conn.Mmsghdr, 0, c.relayBatchSize)

	for i := range c.relayBatchSize {
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
		nr, err := downlink.proxyConn.ReadMsgs(rmsgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			c.logger.Warn("Failed to read from proxyConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListenAddress),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("proxyAddress", downlink.proxyAddrPort),
				zap.Error(err),
			)
			continue
		}

		recvmmmsgCount++
		msgsReceived += uint64(nr)
		burstRecvBatchSize = max(burstRecvBatchSize, nr)

		rmsgvecn := rmsgvec[:nr]

		for i := range rmsgvecn {
			msg := &rmsgvecn[i]
			cmsg := rcmsgvec[i][:msg.Msghdr.Controllen]
			msg.Msghdr.SetControllen(conn.SocketControlMessageBufferSize)

			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				c.logger.Warn("Failed to parse sockaddr of packet from proxyConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("proxyAddress", downlink.proxyAddrPort),
					zap.Error(err),
				)
				continue
			}
			if !conn.AddrPortMappedEqual(packetSourceAddrPort, downlink.proxyAddrPort) {
				c.logger.Warn("Ignoring packet from non-proxy address",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("proxyAddress", downlink.proxyAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			if err = conn.ParseFlagsForError(int(msg.Msghdr.Flags)); err != nil {
				c.logger.Warn("Discarded packet from proxyConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("proxyAddress", downlink.proxyAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Int("cmsgLength", len(cmsg)),
					zap.Error(err),
				)
				continue
			}

			rscm, err := conn.ParseSocketControlMessage(cmsg)
			if err != nil {
				c.logger.Warn("Failed to parse socket control message from proxyConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("proxyAddress", downlink.proxyAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Int("cmsgLength", len(cmsg)),
					zap.Error(err),
				)
				continue
			}

			swgpBytesReceived += uint64(msg.Msglen)

			swgpPacketBuf := rbufvec[i][:msg.Msglen]

			recvSegmentSize := int(rscm.SegmentSize)
			if recvSegmentSize == 0 {
				recvSegmentSize = len(swgpPacketBuf)
			}

			var (
				recvSegmentCount uint32
				qpLength         uint32
				qpSegmentSize    uint32
				qpSegmentCount   uint32
			)

			for len(swgpPacketBuf) > 0 {
				swgpPacketLength := min(len(swgpPacketBuf), recvSegmentSize)
				swgpPacket := swgpPacketBuf[:swgpPacketLength]
				swgpPacketBuf = swgpPacketBuf[swgpPacketLength:]
				recvSegmentCount++

				dst, err := downlink.handler.Decrypt(sendPacketBuf, swgpPacket)
				if err != nil {
					c.logger.Warn("Failed to decrypt swgpPacket",
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListenAddress),
						zap.Stringer("clientAddress", downlink.clientAddrPort),
						zap.Stringer("proxyAddress", downlink.proxyAddrPort),
						zap.Int("packetLength", swgpPacketLength),
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

			if qpLength > 0 {
				queuedPackets = append(queuedPackets, queuedPacket{
					buf:          sendPacketBuf[len(sendPacketBuf)-int(qpLength):],
					segmentSize:  qpSegmentSize,
					segmentCount: qpSegmentCount,
				})
			}
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
				sendSegmentCount := min(segmentsRemaining, downlink.wgConnInfo.MaxUDPGSOSegments)
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
				wgBytesSent += uint64(len(sendBuf))
				burstSendSegmentCount = max(burstSendSegmentCount, sendSegmentCount)
			}
		}

		queuedPackets = queuedPackets[:0]

		for start := 0; start < len(smsgvec); {
			n, err := downlink.wgConn.WriteMsgs(smsgvec[start:], 0)
			start += n
			if err != nil {
				c.logger.Warn("Failed to write wgPacket to wgConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListenAddress),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("proxyAddress", downlink.proxyAddrPort),
					zap.Uint("wgPacketLength", uint(siovec[start].Len)),
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

	c.logger.Info("Finished relay proxyConn -> wgConn",
		zap.String("client", c.name),
		zap.String("listenAddress", c.wgListenAddress),
		zap.Stringer("clientAddress", downlink.clientAddrPort),
		zap.Stringer("proxyAddress", downlink.proxyAddrPort),
		zap.Uint64("recvmmmsgCount", recvmmmsgCount),
		zap.Uint64("msgsReceived", msgsReceived),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("swgpBytesReceived", swgpBytesReceived),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("msgsSent", msgsSent),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
		zap.Int("burstRecvBatchSize", burstRecvBatchSize),
		zap.Int("burstSendBatchSize", burstSendBatchSize),
		zap.Uint32("burstRecvSegmentCount", burstRecvSegmentCount),
		zap.Uint32("burstSendSegmentCount", burstSendSegmentCount),
	)
}
