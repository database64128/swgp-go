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

type clientNatUplinkMmsg struct {
	clientAddrPort  netip.AddrPort
	proxyConn       *conn.MmsgWConn
	proxyConnSendCh <-chan queuedPacket
}

type clientNatDownlinkMmsg struct {
	clientAddrPort netip.AddrPort
	clientPktinfop *[]byte
	clientPktinfo  *atomic.Pointer[[]byte]
	proxyConn      *conn.MmsgRConn
	wgConn         *conn.MmsgWConn
}

func (c *client) setStartFunc(batchMode string) {
	switch batchMode {
	case "sendmmsg", "":
		c.startFunc = c.startMmsg
	default:
		c.startFunc = c.startGeneric
	}
}

func (c *client) startMmsg() error {
	wgConn, err := c.wgConnListenConfig.ListenUDPRawConn("udp", c.wgListen)
	if err != nil {
		return err
	}
	c.wgConn = wgConn.UDPConn

	c.mwg.Add(1)

	go func() {
		c.recvFromWgConnRecvmmsg(wgConn.RConn())
		c.mwg.Done()
	}()

	wgTunnelMTU := (c.maxProxyPacketSize - c.handler.FrontOverhead() - c.handler.RearOverhead() - WireGuardDataPacketOverhead) & WireGuardDataPacketLengthMask

	c.logger.Info("Started service",
		zap.String("client", c.name),
		zap.String("listenAddress", c.wgListen),
		zap.Stringer("proxyAddress", &c.proxyAddrPort),
		zap.Int("wgTunnelMTU", wgTunnelMTU),
	)
	return nil
}

func (c *client) recvFromWgConnRecvmmsg(wgConn *conn.MmsgRConn) {
	frontOverhead := c.handler.FrontOverhead()
	rearOverhead := c.handler.RearOverhead()
	packetBufRecvSize := c.maxProxyPacketSize - frontOverhead - rearOverhead

	n := c.mainRecvBatchSize
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
			packetBuf := c.getPacketBuf()
			bufvec[i] = packetBuf
			iovec[i].Base = &packetBuf[frontOverhead]
			iovec[i].SetLen(packetBufRecvSize)
			msgvec[i].Msghdr.SetControllen(conn.SocketControlMessageBufferSize)
		}

		n, err = wgConn.ReadMsgs(msgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			c.logger.Warn("Failed to read from wgConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListen),
				zap.Error(err),
			)
			n = 1
			c.putPacketBuf(bufvec[0])
			continue
		}

		recvmmsgCount++
		packetsReceived += uint64(n)
		if burstBatchSize < n {
			burstBatchSize = n
		}

		c.mu.Lock()

		msgvecn := msgvec[:n]

		for i := range msgvecn {
			msg := &msgvecn[i]
			packetBuf := bufvec[i]

			if msg.Msghdr.Controllen == 0 {
				c.logger.Warn("Skipping packet with no control message from wgConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListen),
				)
				c.putPacketBuf(packetBuf)
				continue
			}

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				c.logger.Warn("Failed to parse sockaddr of packet from wgConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListen),
					zap.Error(err),
				)
				c.putPacketBuf(packetBuf)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				c.logger.Warn("Failed to read from wgConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				c.putPacketBuf(packetBuf)
				continue
			}

			wgBytesReceived += uint64(msg.Msglen)

			natEntry, ok := c.table[clientAddrPort]
			if !ok {
				natEntry = &clientNatEntry{}
			}

			var clientPktinfop *[]byte
			cmsg := cmsgvec[i][:msg.Msghdr.Controllen]

			if !bytes.Equal(natEntry.clientPktinfoCache, cmsg) {
				clientPktinfoAddr, clientPktinfoIfindex, err := conn.ParsePktinfoCmsg(cmsg)
				if err != nil {
					c.logger.Warn("Failed to parse pktinfo control message from wgConn",
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Error(err),
					)
					c.putPacketBuf(packetBuf)
					c.mu.Unlock()
					continue
				}

				clientPktinfoCache := make([]byte, len(cmsg))
				copy(clientPktinfoCache, cmsg)
				clientPktinfop = &clientPktinfoCache
				natEntry.clientPktinfo.Store(clientPktinfop)
				natEntry.clientPktinfoCache = clientPktinfoCache

				if ce := c.logger.Check(zap.DebugLevel, "Updated client pktinfo"); ce != nil {
					ce.Write(
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("clientPktinfoAddr", clientPktinfoAddr),
						zap.Uint32("clientPktinfoIfindex", clientPktinfoIfindex),
					)
				}
			}

			if !ok {
				proxyConn, err := c.proxyConnListenConfig.ListenUDPRawConn("udp", "")
				if err != nil {
					c.logger.Warn("Failed to create UDP socket for new session",
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Error(err),
					)
					c.putPacketBuf(packetBuf)
					c.mu.Unlock()
					continue
				}

				err = proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime))
				if err != nil {
					c.logger.Warn("Failed to SetReadDeadline on proxyConn",
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("proxyAddress", &c.proxyAddrPort),
						zap.Error(err),
					)
					c.putPacketBuf(packetBuf)
					c.mu.Unlock()
					continue
				}

				proxyConnSendCh := make(chan queuedPacket, c.sendChannelCapacity)
				natEntry.proxyConn = proxyConn.UDPConn
				natEntry.proxyConnSendCh = proxyConnSendCh
				c.table[clientAddrPort] = natEntry

				c.wg.Add(2)

				go func() {
					c.relayProxyToWgSendmmsg(clientNatDownlinkMmsg{
						clientAddrPort: clientAddrPort,
						clientPktinfop: clientPktinfop,
						clientPktinfo:  &natEntry.clientPktinfo,
						proxyConn:      proxyConn.RConn(),
						wgConn:         wgConn.WConn(),
					})

					c.mu.Lock()
					close(proxyConnSendCh)
					delete(c.table, clientAddrPort)
					c.mu.Unlock()

					c.wg.Done()
				}()

				go func() {
					c.relayWgToProxySendmmsg(clientNatUplinkMmsg{
						clientAddrPort:  clientAddrPort,
						proxyConn:       proxyConn.WConn(),
						proxyConnSendCh: proxyConnSendCh,
					})
					proxyConn.Close()
					c.wg.Done()
				}()

				c.logger.Info("New session",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListen),
					zap.Stringer("clientAddress", clientAddrPort),
					zap.Stringer("proxyAddress", &c.proxyAddrPort),
				)
			}

			select {
			case natEntry.proxyConnSendCh <- queuedPacket{packetBuf, frontOverhead, int(msg.Msglen)}:
			default:
				if ce := c.logger.Check(zap.DebugLevel, "swgpPacket dropped due to full send channel"); ce != nil {
					ce.Write(
						zap.String("client", c.name),
						zap.String("listenAddress", c.wgListen),
						zap.Stringer("clientAddress", clientAddrPort),
						zap.Stringer("proxyAddress", &c.proxyAddrPort),
					)
				}
				c.putPacketBuf(packetBuf)
			}
		}

		c.mu.Unlock()
	}

	for i := range bufvec {
		c.putPacketBuf(bufvec[i])
	}

	c.logger.Info("Finished receiving from wgConn",
		zap.String("client", c.name),
		zap.String("listenAddress", c.wgListen),
		zap.Stringer("proxyAddress", &c.proxyAddrPort),
		zap.Uint64("recvmmsgCount", recvmmsgCount),
		zap.Uint64("packetsReceived", packetsReceived),
		zap.Uint64("wgBytesReceived", wgBytesReceived),
		zap.Int("burstBatchSize", burstBatchSize),
	)
}

func (c *client) relayWgToProxySendmmsg(uplink clientNatUplinkMmsg) {
	var (
		sendmmsgCount  uint64
		packetsSent    uint64
		wgBytesSent    uint64
		burstBatchSize int
	)

	rsa6 := conn.AddrPortToSockaddrInet6(c.proxyAddrPort)
	bufvec := make([][]byte, c.relayBatchSize)
	iovec := make([]unix.Iovec, c.relayBatchSize)
	msgvec := make([]conn.Mmsghdr, c.relayBatchSize)

	for i := range msgvec {
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&rsa6))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

main:
	for {
		var (
			count       int
			isHandshake bool
		)

		// Block on first dequeue op.
		dequeuedPacket, ok := <-uplink.proxyConnSendCh
		if !ok {
			break
		}

	dequeue:
		for {
			// Update proxyConn read deadline when a handshake initiation/response message is received.
			switch dequeuedPacket.buf[dequeuedPacket.start] {
			case packet.WireGuardMessageTypeHandshakeInitiation, packet.WireGuardMessageTypeHandshakeResponse:
				isHandshake = true
			}

			swgpPacketStart, swgpPacketLength, err := c.handler.EncryptZeroCopy(dequeuedPacket.buf, dequeuedPacket.start, dequeuedPacket.length)
			if err != nil {
				c.logger.Warn("Failed to encrypt WireGuard packet",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListen),
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Error(err),
				)

				c.putPacketBuf(dequeuedPacket.buf)

				if count == 0 {
					continue main
				}
				goto next
			}

			bufvec[count] = dequeuedPacket.buf
			iovec[count].Base = &dequeuedPacket.buf[swgpPacketStart]
			iovec[count].SetLen(swgpPacketLength)
			count++
			wgBytesSent += uint64(dequeuedPacket.length)

			if count == c.relayBatchSize {
				break
			}

		next:
			select {
			case dequeuedPacket, ok = <-uplink.proxyConnSendCh:
				if !ok {
					break dequeue
				}
			default:
				break dequeue
			}
		}

		// Batch write.
		if err := uplink.proxyConn.WriteMsgs(msgvec[:count], 0); err != nil {
			c.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListen),
				zap.Stringer("clientAddress", uplink.clientAddrPort),
				zap.Stringer("proxyAddress", &c.proxyAddrPort),
				zap.Error(err),
			)
		}

		if isHandshake {
			if err := uplink.proxyConn.SetReadDeadline(time.Now().Add(RejectAfterTime)); err != nil {
				c.logger.Warn("Failed to SetReadDeadline on proxyConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListen),
					zap.Stringer("clientAddress", uplink.clientAddrPort),
					zap.Stringer("proxyAddress", &c.proxyAddrPort),
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
			c.putPacketBuf(bufvecn[i])
		}

		if !ok {
			break
		}
	}

	c.logger.Info("Finished relay wgConn -> proxyConn",
		zap.String("client", c.name),
		zap.String("listenAddress", c.wgListen),
		zap.Stringer("clientAddress", uplink.clientAddrPort),
		zap.Stringer("proxyAddress", &c.proxyAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
	)
}

func (c *client) relayProxyToWgSendmmsg(downlink clientNatDownlinkMmsg) {
	var (
		sendmmsgCount  uint64
		packetsSent    uint64
		wgBytesSent    uint64
		burstBatchSize int
	)

	clientPktinfop := downlink.clientPktinfop
	clientPktinfo := *clientPktinfop

	name, namelen := conn.AddrPortToSockaddr(downlink.clientAddrPort)
	savec := make([]unix.RawSockaddrInet6, c.relayBatchSize)
	bufvec := make([][]byte, c.relayBatchSize)
	riovec := make([]unix.Iovec, c.relayBatchSize)
	siovec := make([]unix.Iovec, c.relayBatchSize)
	rmsgvec := make([]conn.Mmsghdr, c.relayBatchSize)
	smsgvec := make([]conn.Mmsghdr, c.relayBatchSize)

	for i := 0; i < c.relayBatchSize; i++ {
		bufvec[i] = make([]byte, c.maxProxyPacketSize)

		riovec[i].Base = &bufvec[i][0]
		riovec[i].SetLen(c.maxProxyPacketSize)

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
		nr, err := downlink.proxyConn.ReadMsgs(rmsgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			c.logger.Warn("Failed to read from proxyConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListen),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("proxyAddress", &c.proxyAddrPort),
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
				c.logger.Warn("Failed to parse sockaddr of packet from proxyConn",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListen),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("proxyAddress", &c.proxyAddrPort),
					zap.Error(err),
				)
				continue
			}
			if !conn.AddrPortMappedEqual(packetSourceAddrPort, c.proxyAddrPort) {
				c.logger.Warn("Ignoring packet from non-proxy address",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListen),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("proxyAddress", &c.proxyAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				c.logger.Warn("Packet from proxyConn discarded",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListen),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("proxyAddress", &c.proxyAddrPort),
					zap.Stringer("packetSourceAddress", packetSourceAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			packetBuf := bufvec[i]
			wgPacketStart, wgPacketLength, err := c.handler.DecryptZeroCopy(packetBuf, 0, int(msg.Msglen))
			if err != nil {
				c.logger.Warn("Failed to decrypt swgpPacket",
					zap.String("client", c.name),
					zap.String("listenAddress", c.wgListen),
					zap.Stringer("clientAddress", downlink.clientAddrPort),
					zap.Stringer("proxyAddress", &c.proxyAddrPort),
					zap.Uint32("packetLength", msg.Msglen),
					zap.Error(err),
				)
				continue
			}

			siovec[ns].Base = &packetBuf[wgPacketStart]
			siovec[ns].SetLen(wgPacketLength)
			ns++
			wgBytesSent += uint64(wgPacketLength)
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

		err = downlink.wgConn.WriteMsgs(smsgvec[:ns], 0)
		if err != nil {
			c.logger.Warn("Failed to write wgPacket to wgConn",
				zap.String("client", c.name),
				zap.String("listenAddress", c.wgListen),
				zap.Stringer("clientAddress", downlink.clientAddrPort),
				zap.Stringer("proxyAddress", &c.proxyAddrPort),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(ns)
		if burstBatchSize < ns {
			burstBatchSize = ns
		}
	}

	c.logger.Info("Finished relay proxyConn -> wgConn",
		zap.String("client", c.name),
		zap.String("listenAddress", c.wgListen),
		zap.Stringer("clientAddress", downlink.clientAddrPort),
		zap.Stringer("proxyAddress", &c.proxyAddrPort),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
		zap.Int("burstBatchSize", burstBatchSize),
	)
}
