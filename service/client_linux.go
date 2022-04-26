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

func (c *client) getRelayWgToProxyFunc(disableSendmmsg bool) func(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	if disableSendmmsg {
		return c.relayWgToProxyGeneric
	}
	return c.relayWgToProxySendmmsg
}

func (c *client) relayWgToProxySendmmsg(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	name, namelen := conn.AddrPortToSockaddr(c.proxyAddr)
	dequeuedPackets := make([]clientQueuedPacket, 0, conn.UIO_MAXIOV)
	iovec := make([]unix.Iovec, 0, conn.UIO_MAXIOV)
	msgvec := make([]conn.Mmsghdr, 0, conn.UIO_MAXIOV)

	for {
		// Dequeue packets and append to dequeuedPackets.

		var (
			dequeuedPacket clientQueuedPacket
			ok             bool
		)

		dequeuedPackets = dequeuedPackets[:0]

		// Block on first dequeue op.
		dequeuedPacket, ok = <-natEntry.proxyConnSendCh
		if !ok {
			break
		}
		dequeuedPackets = append(dequeuedPackets, dequeuedPacket)

	dequeue:
		for i := 1; i < conn.UIO_MAXIOV; i++ {
			select {
			case dequeuedPacket, ok = <-natEntry.proxyConnSendCh:
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

		// Encrypt packets and add to iovec and msgvec.
		for i, packet := range dequeuedPackets {
			packetBuf := *packet.bufp

			swgpPacket, err := c.handler.EncryptZeroCopy(packetBuf, packet.start, packet.length, c.maxProxyPacketSize)
			if err != nil {
				c.logger.Warn("Failed to encrypt WireGuard packet",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Error(err),
				)
				goto cleanup
			}

			iovec[i].Base = &swgpPacket[0]
			iovec[i].SetLen(len(swgpPacket))

			msgvec[i].Msghdr.Name = name
			msgvec[i].Msghdr.Namelen = namelen
			msgvec[i].Msghdr.Iov = &iovec[i]
			msgvec[i].Msghdr.SetIovlen(1)
			if len(natEntry.proxyConnOobCache) > 0 {
				msgvec[i].Msghdr.Control = &natEntry.proxyConnOobCache[0]
				msgvec[i].Msghdr.SetControllen(len(natEntry.proxyConnOobCache))
			}
		}

		// Batch write.
		if err := conn.Sendmmsg(natEntry.proxyConn, msgvec); err != nil {
			if errors.Is(err, net.ErrClosed) {
				ok = false
				goto cleanup
			}
			c.logger.Warn("Failed to write swgpPacket to proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}

	cleanup:
		for _, packet := range dequeuedPackets {
			c.packetBufPool.Put(packet.bufp)
		}

		if !ok {
			break
		}
	}
}

func (c *client) getRelayProxyToWgFunc(disableSendmmsg bool) func(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	if disableSendmmsg {
		return c.relayProxyToWgGeneric
	}
	return c.relayProxyToWgSendmmsg
}

func (c *client) relayProxyToWgSendmmsg(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	name, namelen := conn.AddrPortToSockaddr(clientAddr)
	proxyAddr16 := c.proxyAddr.Addr().As16()
	proxyPort := c.proxyAddr.Port()

	riovec := make([]unix.Iovec, conn.UIO_MAXIOV)
	siovec := make([]unix.Iovec, conn.UIO_MAXIOV)
	rmsgvec := make([]conn.Mmsghdr, conn.UIO_MAXIOV)
	smsgvec := make([]conn.Mmsghdr, conn.UIO_MAXIOV)

	// Initialize riovec, rmsgvec and smsgvec.
	for i := 0; i < conn.UIO_MAXIOV; i++ {
		var sockaddr unix.RawSockaddrInet6
		packetBuf := make([]byte, c.maxProxyPacketSize)
		oobBuf := make([]byte, conn.UDPOOBBufferSize)

		riovec[i].Base = &packetBuf[0]
		riovec[i].SetLen(c.maxProxyPacketSize)

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
				c.logger.Warn("Packet from proxyConn discarded",
					zap.Stringer("service", c),
					zap.String("wgListen", c.config.WgListen),
					zap.Stringer("clientAddress", clientAddr),
					zap.Stringer("proxyAddress", c.proxyAddr),
					zap.Error(err),
				)
				continue
			}

			msgSockaddr := *(*unix.RawSockaddrInet6)(unsafe.Pointer(msg.Msghdr.Name))
			msgSockaddrPortp := (*[2]byte)(unsafe.Pointer(&msgSockaddr.Port))
			msgSockaddrPort := uint16(msgSockaddrPortp[0])<<8 + uint16(msgSockaddrPortp[1])
			if msgSockaddrPort != proxyPort || msgSockaddr.Addr != proxyAddr16 {
				raddr := netip.AddrPortFrom(netip.AddrFrom16(msgSockaddr.Addr), msgSockaddrPort)
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

			packetBuf := unsafe.Slice(msg.Msghdr.Iov.Base, c.maxProxyPacketSize)
			swgpPacket := packetBuf[:msg.Msglen]
			wgPacket, err := c.handler.DecryptZeroCopy(swgpPacket)
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

			// Only create slice here. Processing happens after the loop.
			// This essentially means only the last socket control message
			// is being processed.
			oob = unsafe.Slice(msg.Msghdr.Control, msg.Msghdr.Controllen)

			smsgvec[ns].Msghdr.Iov.Base = &wgPacket[0]
			smsgvec[ns].Msghdr.Iov.SetLen(len(wgPacket))
			if smsgControlLen > 0 {
				smsgvec[ns].Msghdr.Control = &smsgControl[0]
				smsgvec[ns].Msghdr.SetControllen(smsgControlLen)
			}
			ns++
		}

		if ns == 0 {
			continue
		}

		natEntry.proxyConnOobCache, err = conn.UpdateOobCache(natEntry.proxyConnOobCache, oob, c.logger)
		if err != nil {
			c.logger.Warn("Failed to process OOB from proxyConn",
				zap.Stringer("service", c),
				zap.String("wgListen", c.config.WgListen),
				zap.Stringer("clientAddress", clientAddr),
				zap.Stringer("proxyAddress", c.proxyAddr),
				zap.Error(err),
			)
		}

		err = conn.Sendmmsg(c.wgConn, smsgvec[:ns])
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
	}
}
