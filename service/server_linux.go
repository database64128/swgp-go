package service

import (
	"net/netip"

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
