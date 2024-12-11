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

type clientNatUplinkMmsg struct {
	clientAddrPort          netip.AddrPort
	proxyConnListenAddrPort netip.AddrPort
	proxyAddrPort           netip.AddrPort
	proxyConn               *conn.MmsgWConn
	proxyConnInfo           conn.SocketInfo
	proxyConnSendCh         <-chan queuedPacket
	handler                 packet.Handler
}

type clientNatDownlinkMmsg struct {
	clientAddrPort          netip.AddrPort
	clientPktinfop          *pktinfo
	clientPktinfo           *atomic.Pointer[pktinfo]
	proxyConnListenAddrPort netip.AddrPort
	proxyAddrPort           netip.AddrPort
	proxyConn               *conn.MmsgRConn
	wgConn                  *conn.MmsgWConn
	wgConnInfo              conn.SocketInfo
	handler                 packet.Handler
	maxProxyPacketSize      int
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
	c.wgListenAddress = wgConn.LocalAddr().String()

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

	if c.logger.Enabled(slog.LevelInfo) {
		fields := make([]slog.Attr, 0, 7)

		fields = append(fields,
			slog.String("client", c.name),
			slog.String("listenAddress", c.wgListenAddress),
			tslog.ConnAddrp("proxyAddress", &c.proxyAddr),
		)

		if c.proxyAddr.IsIP() {
			fields = append(fields, slog.Int("wgTunnelMTU", c.wgTunnelMTU))
		} else {
			fields = append(fields,
				slog.Int("wgTunnelMTUv4", c.wgTunnelMTU),
				slog.Int("wgTunnelMTUv6", c.wgTunnelMTUv6),
			)
		}

		fields = append(fields,
			tslog.Uint("maxUDPGSOSegments", wgConnInfo.MaxUDPGSOSegments),
			slog.Bool("udpGRO", wgConnInfo.UDPGenericReceiveOffload),
		)

		c.logger.Info("Started service", fields...)
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
				slog.String("client", c.name),
				slog.String("listenAddress", c.wgListenAddress),
				tslog.Err(err),
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
					slog.String("client", c.name),
					slog.String("listenAddress", c.wgListenAddress),
					tslog.Err(err),
				)
				continue
			}

			if err = conn.ParseFlagsForError(int(msg.Msghdr.Flags)); err != nil {
				c.logger.Warn("Discarded packet from wgConn",
					slog.String("client", c.name),
					slog.String("listenAddress", c.wgListenAddress),
					tslog.AddrPort("clientAddress", clientAddrPort),
					tslog.Uint("packetLength", msg.Msglen),
					slog.Int("cmsgLength", len(cmsg)),
					tslog.Err(err),
				)
				continue
			}

			rscm, err := conn.ParseSocketControlMessage(cmsg)
			if err != nil {
				c.logger.Warn("Failed to parse socket control message from wgConn",
					slog.String("client", c.name),
					slog.String("listenAddress", c.wgListenAddress),
					tslog.AddrPort("clientAddress", clientAddrPort),
					slog.Int("cmsgLength", len(cmsg)),
					tslog.Err(err),
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

				if c.logger.Enabled(slog.LevelDebug) {
					c.logger.Debug("Updated client pktinfo",
						slog.String("client", c.name),
						slog.String("listenAddress", c.wgListenAddress),
						tslog.AddrPort("clientAddress", clientAddrPort),
						tslog.Addrp("clientPktinfoAddr", &clientPktinfop.addr),
						tslog.Uint("clientPktinfoIfindex", clientPktinfoCache.ifindex),
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
							slog.String("client", c.name),
							slog.String("listenAddress", c.wgListenAddress),
							tslog.AddrPort("clientAddress", clientAddrPort),
							tslog.Err(err),
						)
						return
					}

					proxyConnListenNetwork := listenUDPNetworkForRemoteAddr(proxyAddrPort.Addr())

					proxyConn, proxyConnInfo, err := c.proxyConnListenConfig.ListenUDPMmsgConn(ctx, proxyConnListenNetwork, c.proxyConnListenAddress)
					if err != nil {
						c.logger.Warn("Failed to create UDP socket for new session",
							slog.String("client", c.name),
							slog.String("listenAddress", c.wgListenAddress),
							tslog.AddrPort("clientAddress", clientAddrPort),
							slog.String("proxyConnListenNetwork", proxyConnListenNetwork),
							slog.String("proxyConnListenAddress", c.proxyConnListenAddress),
							tslog.Err(err),
						)
						return
					}

					proxyConnListenAddrPort := proxyConn.LocalAddr().(*net.UDPAddr).AddrPort()

					if err = proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
						c.logger.Warn("Failed to SetReadDeadline on proxyConn",
							slog.String("client", c.name),
							slog.String("listenAddress", c.wgListenAddress),
							tslog.AddrPort("clientAddress", clientAddrPort),
							tslog.AddrPort("proxyConnListenAddress", proxyConnListenAddrPort),
							tslog.Err(err),
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
						slog.String("client", c.name),
						slog.String("listenAddress", c.wgListenAddress),
						tslog.AddrPort("clientAddress", clientAddrPort),
						tslog.AddrPort("proxyConnListenAddress", proxyConnListenAddrPort),
						tslog.AddrPort("proxyAddress", proxyAddrPort),
						slog.Int("wgTunnelMTU", wgTunnelMTU),
						tslog.Uint("maxUDPGSOSegments", proxyConnInfo.MaxUDPGSOSegments),
						slog.Bool("udpGRO", proxyConnInfo.UDPGenericReceiveOffload),
					)

					c.wg.Add(1)

					go func() {
						c.relayWgToProxySendmmsg(clientNatUplinkMmsg{
							clientAddrPort:          clientAddrPort,
							proxyConnListenAddrPort: proxyConnListenAddrPort,
							proxyAddrPort:           proxyAddrPort,
							proxyConn:               proxyConn.NewWConn(),
							proxyConnInfo:           proxyConnInfo,
							proxyConnSendCh:         proxyConnSendCh,
							handler:                 handler,
						})
						proxyConn.Close()
						c.wg.Done()
					}()

					c.relayProxyToWgSendmmsg(clientNatDownlinkMmsg{
						clientAddrPort:          clientAddrPort,
						clientPktinfop:          clientPktinfop,
						clientPktinfo:           &natEntry.clientPktinfo,
						proxyConnListenAddrPort: proxyConnListenAddrPort,
						proxyAddrPort:           proxyAddrPort,
						proxyConn:               proxyConn.NewRConn(),
						wgConn:                  wgConn.NewWConn(),
						wgConnInfo:              wgConnInfo,
						handler:                 handler,
						maxProxyPacketSize:      maxProxyPacketSize,
					})
				}()

				if c.logger.Enabled(slog.LevelDebug) {
					c.logger.Debug("New client session",
						slog.String("client", c.name),
						slog.String("listenAddress", c.wgListenAddress),
						tslog.AddrPort("clientAddress", clientAddrPort),
						tslog.ConnAddrp("proxyAddress", &c.proxyAddr),
					)
				}
			}

			select {
			case natEntry.proxyConnSendCh <- qp:
				packetBuf := c.getPacketBuf()
				bufvec[i] = packetBuf
				iovec[i].Base = unsafe.SliceData(packetBuf)
			default:
				if c.logger.Enabled(slog.LevelDebug) {
					c.logger.Debug("swgpPacket dropped due to full send channel",
						slog.String("client", c.name),
						slog.String("listenAddress", c.wgListenAddress),
						tslog.AddrPort("clientAddress", clientAddrPort),
						tslog.ConnAddrp("proxyAddress", &c.proxyAddr),
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
		slog.String("client", c.name),
		slog.String("listenAddress", c.wgListenAddress),
		tslog.ConnAddrp("proxyAddress", &c.proxyAddr),
		tslog.Uint("recvmmsgCount", recvmmsgCount),
		tslog.Uint("msgsReceived", msgsReceived),
		tslog.Uint("packetsReceived", packetsReceived),
		tslog.Uint("wgBytesReceived", wgBytesReceived),
		slog.Int("burstBatchSize", burstBatchSize),
		tslog.Uint("burstSegmentCount", burstSegmentCount),
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

	name, namelen := conn.AddrPortToSockaddrWithAddressFamily(uplink.proxyAddrPort, uplink.proxyConnListenAddrPort.Addr().Is4())
	packetBuf := make([]byte, 0, c.relayBatchSize*c.packetBufSize)
	cmsgBuf := make([]byte, 0, c.relayBatchSize*conn.SocketControlMessageBufferSize)
	iovec := make([]unix.Iovec, 0, c.relayBatchSize)
	msgvec := make([]conn.Mmsghdr, 0, c.relayBatchSize)

main:
	for {
		// Block on first dequeue op.
		rqp, ok := <-uplink.proxyConnSendCh
		if !ok {
			break
		}

		var (
			isHandshake     bool
			sqpLength       uint32
			sqpSegmentSize  uint32
			sqpSegmentCount uint32
		)

	dequeue:
		for {
			for wgPacketBuf := rqp.buf; len(wgPacketBuf) > 0; {
				wgPacketLength := min(len(wgPacketBuf), int(rqp.segmentSize))
				wgPacket := wgPacketBuf[:wgPacketLength]
				wgPacketBuf = wgPacketBuf[wgPacketLength:]

				// Update proxyConn read deadline when rqp contains a WireGuard handshake initiation message.
				if wgPacket[0] == packet.WireGuardMessageTypeHandshakeInitiation {
					isHandshake = true
				}

				dst, err := uplink.handler.Encrypt(packetBuf, wgPacket)
				if err != nil {
					c.logger.Warn("Failed to encrypt wgPacket",
						slog.String("client", c.name),
						slog.String("listenAddress", c.wgListenAddress),
						tslog.AddrPort("clientAddress", uplink.clientAddrPort),
						tslog.AddrPort("proxyConnListenAddress", uplink.proxyConnListenAddrPort),
						tslog.AddrPort("proxyAddress", uplink.proxyAddrPort),
						slog.Int("wgPacketLength", wgPacketLength),
						tslog.Err(err),
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

			c.putPacketBuf(rqp.buf)

			if len(sendQueuedPackets) == 0 && sqpLength == 0 {
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

		if sqpLength > 0 {
			sendQueuedPackets = append(sendQueuedPackets, queuedPacket{
				buf:          packetBuf[len(packetBuf)-int(sqpLength):],
				segmentSize:  sqpSegmentSize,
				segmentCount: sqpSegmentCount,
			})
		}

		for _, sqp := range sendQueuedPackets {
			b := sqp.buf
			segmentsRemaining := sqp.segmentCount

			maxUDPGSOSegments := uplink.proxyConnInfo.MaxUDPGSOSegments
			if maxUDPGSOSegments > 1 {
				// Cap each coalesced message to 65535 bytes to prevent -EMSGSIZE.
				maxUDPGSOSegments = max(1, 65535/sqp.segmentSize)
			}

			for segmentsRemaining > 0 {
				sendSegmentCount := min(segmentsRemaining, maxUDPGSOSegments)
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
						Name:    name,
						Namelen: namelen,
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
					slog.String("client", c.name),
					slog.String("listenAddress", c.wgListenAddress),
					tslog.AddrPort("clientAddress", uplink.clientAddrPort),
					tslog.AddrPort("proxyConnListenAddress", uplink.proxyConnListenAddrPort),
					tslog.AddrPort("proxyAddress", uplink.proxyAddrPort),
					tslog.Uint("swgpPacketLength", iovec[start].Len),
					tslog.Err(err),
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
					slog.String("client", c.name),
					slog.String("listenAddress", c.wgListenAddress),
					tslog.AddrPort("clientAddress", uplink.clientAddrPort),
					tslog.AddrPort("proxyConnListenAddress", uplink.proxyConnListenAddrPort),
					tslog.AddrPort("proxyAddress", uplink.proxyAddrPort),
					tslog.Err(err),
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
		slog.String("client", c.name),
		slog.String("listenAddress", c.wgListenAddress),
		tslog.AddrPort("clientAddress", uplink.clientAddrPort),
		tslog.AddrPort("proxyConnListenAddress", uplink.proxyConnListenAddrPort),
		tslog.AddrPort("proxyAddress", uplink.proxyAddrPort),
		tslog.Uint("sendmmsgCount", sendmmsgCount),
		tslog.Uint("msgsSent", msgsSent),
		tslog.Uint("packetsSent", packetsSent),
		tslog.Uint("swgpBytesSent", swgpBytesSent),
		slog.Int("burstBatchSize", burstBatchSize),
		tslog.Uint("burstSegmentCount", burstSegmentCount),
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
				slog.String("client", c.name),
				slog.String("listenAddress", c.wgListenAddress),
				tslog.AddrPort("clientAddress", downlink.clientAddrPort),
				tslog.AddrPort("proxyConnListenAddress", downlink.proxyConnListenAddrPort),
				tslog.AddrPort("proxyAddress", downlink.proxyAddrPort),
				tslog.Err(err),
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
					slog.String("client", c.name),
					slog.String("listenAddress", c.wgListenAddress),
					tslog.AddrPort("clientAddress", downlink.clientAddrPort),
					tslog.AddrPort("proxyConnListenAddress", downlink.proxyConnListenAddrPort),
					tslog.AddrPort("proxyAddress", downlink.proxyAddrPort),
					tslog.Err(err),
				)
				continue
			}
			if !conn.AddrPortMappedEqual(packetSourceAddrPort, downlink.proxyAddrPort) {
				c.logger.Warn("Ignoring packet from non-proxy address",
					slog.String("client", c.name),
					slog.String("listenAddress", c.wgListenAddress),
					tslog.AddrPort("clientAddress", downlink.clientAddrPort),
					tslog.AddrPort("proxyConnListenAddress", downlink.proxyConnListenAddrPort),
					tslog.AddrPort("proxyAddress", downlink.proxyAddrPort),
					tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
					tslog.Uint("packetLength", msg.Msglen),
					tslog.Err(err),
				)
				continue
			}

			if err = conn.ParseFlagsForError(int(msg.Msghdr.Flags)); err != nil {
				c.logger.Warn("Discarded packet from proxyConn",
					slog.String("client", c.name),
					slog.String("listenAddress", c.wgListenAddress),
					tslog.AddrPort("clientAddress", downlink.clientAddrPort),
					tslog.AddrPort("proxyConnListenAddress", downlink.proxyConnListenAddrPort),
					tslog.AddrPort("proxyAddress", downlink.proxyAddrPort),
					tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
					tslog.Uint("packetLength", msg.Msglen),
					slog.Int("cmsgLength", len(cmsg)),
					tslog.Err(err),
				)
				continue
			}

			rscm, err := conn.ParseSocketControlMessage(cmsg)
			if err != nil {
				c.logger.Warn("Failed to parse socket control message from proxyConn",
					slog.String("client", c.name),
					slog.String("listenAddress", c.wgListenAddress),
					tslog.AddrPort("clientAddress", downlink.clientAddrPort),
					tslog.AddrPort("proxyConnListenAddress", downlink.proxyConnListenAddrPort),
					tslog.AddrPort("proxyAddress", downlink.proxyAddrPort),
					tslog.AddrPort("packetSourceAddress", packetSourceAddrPort),
					slog.Int("cmsgLength", len(cmsg)),
					tslog.Err(err),
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
						slog.String("client", c.name),
						slog.String("listenAddress", c.wgListenAddress),
						tslog.AddrPort("clientAddress", downlink.clientAddrPort),
						tslog.AddrPort("proxyConnListenAddress", downlink.proxyConnListenAddrPort),
						tslog.AddrPort("proxyAddress", downlink.proxyAddrPort),
						slog.Int("packetLength", swgpPacketLength),
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

			maxUDPGSOSegments := downlink.wgConnInfo.MaxUDPGSOSegments
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
					slog.String("client", c.name),
					slog.String("listenAddress", c.wgListenAddress),
					tslog.AddrPort("clientAddress", downlink.clientAddrPort),
					tslog.AddrPort("proxyConnListenAddress", downlink.proxyConnListenAddrPort),
					tslog.AddrPort("proxyAddress", downlink.proxyAddrPort),
					tslog.Uint("wgPacketLength", siovec[start].Len),
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

	c.logger.Info("Finished relay proxyConn -> wgConn",
		slog.String("client", c.name),
		slog.String("listenAddress", c.wgListenAddress),
		tslog.AddrPort("clientAddress", downlink.clientAddrPort),
		tslog.AddrPort("proxyConnListenAddress", downlink.proxyConnListenAddrPort),
		tslog.AddrPort("proxyAddress", downlink.proxyAddrPort),
		tslog.Uint("recvmmmsgCount", recvmmmsgCount),
		tslog.Uint("msgsReceived", msgsReceived),
		tslog.Uint("packetsReceived", packetsReceived),
		tslog.Uint("swgpBytesReceived", swgpBytesReceived),
		tslog.Uint("sendmmsgCount", sendmmsgCount),
		tslog.Uint("msgsSent", msgsSent),
		tslog.Uint("packetsSent", packetsSent),
		tslog.Uint("wgBytesSent", wgBytesSent),
		slog.Int("burstRecvBatchSize", burstRecvBatchSize),
		slog.Int("burstSendBatchSize", burstSendBatchSize),
		tslog.Uint("burstRecvSegmentCount", burstRecvSegmentCount),
		tslog.Uint("burstSendSegmentCount", burstSendSegmentCount),
	)
}
