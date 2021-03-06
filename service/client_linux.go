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

func (c *client) setRelayWgToProxyFunc() {
	switch c.config.BatchMode {
	case "ring":
		c.relayWgToProxy = c.relayWgToProxySendmmsgRing
	case "sendmmsg", "":
		c.relayWgToProxy = c.relayWgToProxySendmmsg
	default:
		c.relayWgToProxy = c.relayWgToProxyGeneric
	}
}

func (c *client) relayWgToProxySendmmsg(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	var (
		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

	name, namelen := conn.AddrPortToSockaddr(c.proxyAddr)
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
		dequeuedPacket, ok := <-natEntry.proxyConnSendCh
		if !ok {
			break
		}
		packetBuf := *dequeuedPacket.bufp

	dequeue:
		for {
			swgpPacketStart, swgpPacketLength, err := c.handler.EncryptZeroCopy(packetBuf, dequeuedPacket.start, dequeuedPacket.length)
			if err != nil {
				c.logger.Warn("Failed to encrypt WireGuard packet",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Error(err),
				)
				c.packetBufPool.Put(dequeuedPacket.bufp)
				continue
			}

			dequeuedPackets[count] = dequeuedPacket
			iovec[count].Base = &packetBuf[swgpPacketStart]
			iovec[count].SetLen(swgpPacketLength)
			count++
			wgBytesSent += uint64(dequeuedPacket.length)

			if count == vecSize {
				break
			}

			select {
			case dequeuedPacket, ok = <-natEntry.proxyConnSendCh:
				if !ok {
					goto cleanup
				}
				packetBuf = *dequeuedPacket.bufp
			default:
				break dequeue
			}
		}

		// Batch write.
		if err := conn.WriteMsgvec(natEntry.proxyConn, msgvec[:count]); err != nil {
			c.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(count)

	cleanup:
		for _, packet := range dequeuedPackets[:count] {
			c.packetBufPool.Put(packet.bufp)
		}

		if !ok {
			break
		}
	}

	c.logger.Info("Finished relay wgConn -> proxyConn",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("proxyAddress", c.proxyAddr),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (c *client) relayWgToProxySendmmsgRing(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	name, namelen := conn.AddrPortToSockaddr(c.proxyAddr)
	dequeuedPackets := make([]queuedPacket, vecSize)
	iovec := make([]unix.Iovec, vecSize)
	msgvec := make([]conn.Mmsghdr, vecSize)

	var (
		// Turn dequeuedPackets into a ring buffer.
		head, tail int

		// Number of messages in msgvec.
		count int

		err error

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
		dequeuedPacket, ok := <-natEntry.proxyConnSendCh
		if !ok {
			break
		}
		packetBuf := *dequeuedPacket.bufp

	dequeue:
		for {
			dequeuedPacket.start, dequeuedPacket.length, err = c.handler.EncryptZeroCopy(packetBuf, dequeuedPacket.start, dequeuedPacket.length)
			if err != nil {
				c.logger.Warn("Failed to encrypt WireGuard packet",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Error(err),
				)
				c.packetBufPool.Put(dequeuedPacket.bufp)
				continue
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
			case dequeuedPacket, ok = <-natEntry.proxyConnSendCh:
				if !ok {
					break relay
				}
				packetBuf = *dequeuedPacket.bufp
			default:
				break dequeue
			}
		}

		// Batch write.
		n, err := conn.Sendmmsg(natEntry.proxyConn, msgvec[:count])
		if err != nil {
			c.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
			// Error is caused by the first packet in msgvec.
			n = 1
		}

		sendmmsgCount++
		packetsSent += uint64(n)

		// Clean up and move head forward.
		for i := 0; i < n; i++ {
			c.packetBufPool.Put(dequeuedPackets[head].bufp)
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
			c.logger.Error("Packet count does not match ring buffer status",
				zap.Int("count", count),
				zap.Int("expectedCount", expectedCount),
			)
		}
	}

	// Exit cleanup.
	for head != tail {
		c.packetBufPool.Put(dequeuedPackets[head].bufp)
		head = (head + 1) & sizeMask
	}

	c.logger.Info("Finished relay wgConn -> proxyConn",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("proxyAddress", c.proxyAddr),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (c *client) setRelayProxyToWgFunc() {
	switch c.config.BatchMode {
	case "ring":
		c.relayProxyToWg = c.relayProxyToWgSendmmsgRing
	case "sendmmsg", "":
		c.relayProxyToWg = c.relayProxyToWgSendmmsg
	default:
		c.relayProxyToWg = c.relayProxyToWgGeneric
	}
}

func (c *client) relayProxyToWgSendmmsg(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	var (
		sendmmsgCount uint64
		packetsSent   uint64
		wgBytesSent   uint64
	)

	name, namelen := conn.AddrPortToSockaddr(clientAddr)
	savec := make([]unix.RawSockaddrInet6, vecSize)
	bufvec := make([][]byte, vecSize)
	riovec := make([]unix.Iovec, vecSize)
	siovec := make([]unix.Iovec, vecSize)
	rmsgvec := make([]conn.Mmsghdr, vecSize)
	smsgvec := make([]conn.Mmsghdr, vecSize)

	// Initialize riovec, rmsgvec and smsgvec.
	for i := 0; i < vecSize; i++ {
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
	}

	// Main relay loop.
	for {
		nr, err := conn.Recvmmsg(natEntry.proxyConn, rmsgvec)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			c.logger.Warn("Failed to read from proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
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
				c.logger.Warn("Packet from proxyConn discarded",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
				continue
			}

			raddr, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				c.logger.Warn("Failed to parse sockaddr of packet from proxyConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
				continue
			}
			if raddr != c.proxyAddr {
				c.logger.Debug("Ignoring packet from non-proxy address",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Stringer("raddr", raddr),
					zap.Error(err),
				)
				continue
			}

			packetBuf := bufvec[i]
			wgPacketStart, wgPacketLength, err := c.handler.DecryptZeroCopy(packetBuf, 0, int(msg.Msglen))
			if err != nil {
				c.logger.Warn("Failed to decrypt swgpPacket",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
				continue
			}

			siovec[ns].Base = &packetBuf[wgPacketStart]
			siovec[ns].SetLen(wgPacketLength)
			if smsgControlLen > 0 {
				smsgvec[ns].Msghdr.Control = &smsgControl[0]
				smsgvec[ns].Msghdr.SetControllen(smsgControlLen)
			}
			ns++
			wgBytesSent += uint64(wgPacketLength)
		}

		if ns == 0 {
			continue
		}

		err = conn.WriteMsgvec(c.wgConn, smsgvec[:ns])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			c.logger.Warn("Failed to write wgPacket to wgConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(ns)
	}

	c.logger.Info("Finished relay proxyConn -> wgConn",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("proxyAddress", c.proxyAddr),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}

func (c *client) relayProxyToWgSendmmsgRing(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
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
	}

	var (
		n   int
		nr  int = vecSize
		ns  int
		err error
	)

	// Main relay loop.
	for {
		nr, err = conn.Recvmmsg(natEntry.proxyConn, rmsgvec[:nr])
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			c.logger.Warn("Failed to read from proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
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
				c.logger.Warn("Packet from proxyConn discarded",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
				continue
			}

			raddr, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				c.logger.Warn("Failed to parse sockaddr of packet from proxyConn",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
				continue
			}
			if raddr != c.proxyAddr {
				c.logger.Debug("Ignoring packet from non-proxy address",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Stringer("raddr", raddr),
					zap.Error(err),
				)
				continue
			}

			packetBuf := bufvec[pos]
			wgPacketStart, wgPacketLength, err := c.handler.DecryptZeroCopy(packetBuf, 0, int(msg.Msglen))
			if err != nil {
				c.logger.Warn("Failed to decrypt swgpPacket",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
				continue
			}

			siovec[ns].Base = &packetBuf[wgPacketStart]
			siovec[ns].SetLen(wgPacketLength)
			if smsgControlLen > 0 {
				smsgvec[ns].Msghdr.Control = &smsgControl[0]
				smsgvec[ns].Msghdr.SetControllen(smsgControlLen)
			}
			ns++
			wgBytesSent += uint64(wgPacketLength)

			// Mark buffer as used.
			usage |= 1 << pos
		}

		if ns == 0 {
			continue
		}

		// Batch write.
		n, err = conn.Sendmmsg(c.wgConn, smsgvec[:ns])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			c.logger.Warn("Failed to write wgPacket to wgConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
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

			riovec[nr].Base = &bufvec[tpos][0]
			riovec[nr].SetLen(c.maxProxyPacketSize)
			nr++
		}
	}

	c.logger.Info("Finished relay proxyConn -> wgConn",
		zap.Stringer("service", c),
		zap.String("wgListen", c.config.WgListen),
		zap.Stringer("clientAddress", clientAddr),
		zap.Stringer("proxyAddress", c.proxyAddr),
		zap.Uint64("sendmmsgCount", sendmmsgCount),
		zap.Uint64("packetsSent", packetsSent),
		zap.Uint64("wgBytesSent", wgBytesSent),
	)
}
