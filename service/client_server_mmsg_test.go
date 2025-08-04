//go:build linux || netbsd

package service

import (
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/packet"
	"github.com/database64128/swgp-go/service/internal/packetseq"
	"github.com/database64128/swgp-go/tslog"
	"github.com/database64128/swgp-go/tslogtest"
	"golang.org/x/sys/unix"
)

func TestClientServerMmsgSendDrain(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping client-server send/drain test in short mode")
	}

	logCfg := tslogtest.Config{Level: slog.LevelInfo}
	logger := logCfg.NewTestLogger(t)

	for _, proxyModeCase := range proxyModeCases {
		t.Run(proxyModeCase.name, func(t *testing.T) {
			for _, afCase := range addressFamilyCases[1:2] { // No point in testing other cases.
				t.Run(afCase.name, func(t *testing.T) {
					for _, mtuCase := range mtuCases[1:] { // Skip 1492, which should perform similarly to 1500.
						t.Run(mtuCase.name, func(t *testing.T) {
							if mtuCase.mtu > loMTU {
								t.Skipf("MTU %d is larger than loopback interface MTU %d", mtuCase.mtu, loMTU)
							}

							testClientServerConn(
								t,
								logger,
								proxyModeCase.proxyMode,
								proxyModeCase.generatePSK,
								afCase.listenNetwork,
								afCase.listenAddress,
								afCase.endpointNetwork,
								afCase.connectLocalAddress,
								mtuCase.mtu,
								PerfConfig{},
								time.Minute,
								false,
								testClientServerMmsgConn,
							)
						})
					}
				})
			}
		})
	}
}

func testClientServerMmsgConn(
	t *testing.T,
	logger *tslog.Logger,
	clientConn, serverConn *net.UDPConn,
	clientConnInfo, serverConnInfo conn.SocketInfo,
	client *client, _ *server,
) {
	var serverConnPeer netip.AddrPort
	segmentSize := client.wgTunnelMTUv6 + WireGuardDataPacketOverhead
	clientMmsgConn, err := conn.NewMmsgConn(clientConn)
	if err != nil {
		t.Fatalf("Failed to create clientMmsgConn: %v", err)
	}
	serverMmsgConn, err := conn.NewMmsgConn(serverConn)
	if err != nil {
		t.Fatalf("Failed to create serverMmsgConn: %v", err)
	}
	clientMmsgRConn, clientMmsgWConn := clientMmsgConn.NewRConn(), clientMmsgConn.NewWConn()
	serverMmsgRConn, serverMmsgWConn := serverMmsgConn.NewRConn(), serverMmsgConn.NewWConn()

	t.Run("C->S", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			serverConnPeer = testDrainMmsgConn(t, logger, serverMmsgRConn, serverConnInfo, segmentSize, true)
			wg.Done()
		}()
		testSendMmsgConn(t, logger, clientMmsgWConn, clientConnInfo, netip.AddrPort{}, segmentSize)
		wg.Wait()
	})

	if !serverConnPeer.IsValid() {
		t.Fatalf("serverConnPeer is unknown")
	}

	t.Run("S->C", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			_ = testDrainMmsgConn(t, logger, clientMmsgRConn, clientConnInfo, segmentSize, false)
			wg.Done()
		}()
		testSendMmsgConn(t, logger, serverMmsgWConn, serverConnInfo, serverConnPeer, segmentSize)
		wg.Wait()
	})
}

func testDrainMmsgConn(
	t *testing.T,
	logger *tslog.Logger,
	drainConn *conn.MmsgRConn,
	drainConnInfo conn.SocketInfo,
	sendSegmentSize int,
	wantFrom bool,
) (from netip.AddrPort) {
	const batchSize = 1024

	var (
		recvmmsgCount         uint
		msgsReceived          uint
		bytesReceived         uint64
		packetsReceived       uint
		burstBatchSize        int
		burstRecvSegmentCount uint
		receiver              packetseq.Receiver
		savec                 []unix.RawSockaddrInet6
		packetBufSize         = sendSegmentSize
	)

	if wantFrom {
		savec = make([]unix.RawSockaddrInet6, batchSize)
	}

	if drainConnInfo.UDPGenericReceiveOffload {
		packetBufSize = 65535
	}

	batchPacketBuf := make([]byte, batchSize*packetBufSize)
	batchCmsgBuf := make([]byte, batchSize*conn.SocketControlMessageBufferSize)
	iovec := make([]unix.Iovec, batchSize)
	msgvec := make([]conn.Mmsghdr, batchSize)

	packetBufp := unsafe.Pointer(unsafe.SliceData(batchPacketBuf))
	cmsgBufp := unsafe.Pointer(unsafe.SliceData(batchCmsgBuf))

	for i := range 1024 {
		iovec[i].Base = (*byte)(packetBufp)
		iovec[i].SetLen(packetBufSize)

		if wantFrom {
			msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&savec[i]))
			msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		}

		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
		msgvec[i].Msghdr.Control = (*byte)(cmsgBufp)
		msgvec[i].Msghdr.SetControllen(conn.SocketControlMessageBufferSize)

		packetBufp = unsafe.Add(packetBufp, packetBufSize)
		cmsgBufp = unsafe.Add(cmsgBufp, conn.SocketControlMessageBufferSize)
	}

	for {
		n, err := drainConn.ReadMsgs(msgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			t.Errorf("drainConn.ReadMsgs failed: %v", err)
			return from
		}

		recvmmsgCount++
		msgsReceived += uint(n)
		burstBatchSize = max(burstBatchSize, n)

		msgvecn := msgvec[:n]
		remainingPacketBuf := batchPacketBuf
		remainingCmsgBuf := batchCmsgBuf

		for i := range msgvecn {
			msg := &msgvecn[i]
			packet := remainingPacketBuf[:msg.Msglen]
			remainingPacketBuf = remainingPacketBuf[packetBufSize:]
			cmsg := remainingCmsgBuf[:msg.Msghdr.Controllen]
			remainingCmsgBuf = remainingCmsgBuf[conn.SocketControlMessageBufferSize:]
			msg.Msghdr.SetControllen(conn.SocketControlMessageBufferSize)

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				t.Errorf("Failed to parse sockaddr of packet from drainConn: %v", err)
				return from
			}

			if err = conn.ParseFlagsForError(int(msg.Msghdr.Flags)); err != nil {
				t.Errorf("drainConn.ReadMsgs flags error: %v", err)
				return from
			}

			scm, err := conn.ParseSocketControlMessage(cmsg)
			if err != nil {
				t.Errorf("Failed to parse socket control message from drainConn: %v", err)
				return from
			}

			bytesReceived += uint64(msg.Msglen)

			segmentSize := int(scm.SegmentSize)
			if segmentSize == 0 {
				segmentSize = int(msg.Msglen)
			}

			var recvSegmentCount uint

			for buf := packet; len(buf) > 0; {
				segmentLength := min(len(buf), segmentSize)
				segment := buf[:segmentLength]
				buf = buf[segmentLength:]
				recvSegmentCount++

				if err := receiver.Validate(segment); err != nil {
					t.Logf("receiver.Validate failed: %v", err)
				} else {
					from = clientAddrPort
				}
			}

			packetsReceived += recvSegmentCount
			burstRecvSegmentCount = max(burstRecvSegmentCount, recvSegmentCount)
		}

		// After the initial read, the next read should return quickly, until all packets are drained.
		// Therefore, we set a short read deadline to detect completion.
		if err := drainConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Errorf("drainConn.SetReadDeadline failed: %v", err)
			return from
		}
	}

	logger.Info("Drained packets",
		tslog.Uint("recvmmsgCount", recvmmsgCount),
		tslog.Uint("msgsReceived", msgsReceived),
		tslog.Uint("bytesReceived", bytesReceived),
		tslog.Uint("packetsReceived", packetsReceived),
		tslog.Int("burstBatchSize", burstBatchSize),
		tslog.Uint("burstRecvSegmentCount", burstRecvSegmentCount),
		tslog.Uint("lastPacketID", receiver.LastID()),
		tslog.Uint("receiverCount", receiver.Count()),
	)

	return from
}

func testSendMmsgConn(
	t *testing.T,
	logger *tslog.Logger,
	sendConn *conn.MmsgWConn,
	sendConnInfo conn.SocketInfo,
	sendAddrPort netip.AddrPort,
	segmentSize int,
) {
	const batchSize = 128
	var segmentCount uint
	name, namelen := conn.AddrPortToSockaddr(sendAddrPort)
	batchPacketBuf := make([]byte, 0, batchSize*65535)
	rand.Read(batchPacketBuf[:cap(batchPacketBuf)])
	cmsgBuf := make([]byte, 0, conn.SocketControlMessageBufferSize)
	iovec := make([]unix.Iovec, batchSize)
	msgvec := make([]conn.Mmsghdr, batchSize)

	for i := range batchSize {
		packetBuf := batchPacketBuf[len(batchPacketBuf) : len(batchPacketBuf) : len(batchPacketBuf)+65535]

		for segmentsRemaining := sendConnInfo.MaxUDPGSOSegments; segmentsRemaining > 0 && cap(packetBuf)-len(packetBuf) >= segmentSize; segmentsRemaining-- {
			packetBufLen := len(packetBuf)
			packetBuf = packetBuf[:packetBufLen+segmentSize]
			segment := packetBuf[packetBufLen:]
			segment[0] = packet.WireGuardMessageTypeData
			if i == 0 {
				segmentCount++
			}
		}

		// Segment count won't change, so we can reuse the same cmsg.
		if i == 0 {
			var scm conn.SocketControlMessage
			if segmentCount > 1 {
				scm.SegmentSize = uint32(segmentSize)
			}
			cmsgBuf = scm.AppendTo(cmsgBuf)
		}

		batchPacketBuf = batchPacketBuf[:len(batchPacketBuf)+len(packetBuf)]

		iovec[i].Base = unsafe.SliceData(packetBuf)
		iovec[i].SetLen(len(packetBuf))

		msgvec[i].Msghdr.Name = name
		msgvec[i].Msghdr.Namelen = namelen
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
		msgvec[i].Msghdr.Control = unsafe.SliceData(cmsgBuf)
		msgvec[i].Msghdr.SetControllen(len(cmsgBuf))
	}

	var sender packetseq.Sender
	ctxDone := t.Context().Done()

	for range 32 {
		for buf := batchPacketBuf; len(buf) >= segmentSize; buf = buf[segmentSize:] {
			sender.Stamp(buf[:segmentSize])
		}

		if _, err := sendConn.WriteMsgs(msgvec, 0); err != nil {
			t.Errorf("sendConn.WriteMsgs failed: %v", err)
			return
		}

		select {
		case <-ctxDone:
		case <-time.After(10 * time.Millisecond):
		}
	}

	logger.Info("Sent packets",
		tslog.Int("segmentSize", segmentSize),
		tslog.Uint("segmentCount", segmentCount),
		tslog.Uint("packetCount", sender.Count()),
	)
}
