//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package netiface

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/netiface/internal/bsdroute"
	"github.com/database64128/swgp-go/tslog"
	"golang.org/x/sys/unix"
)

func (*PickerConfig) newPicker(logger *tslog.Logger) (*Picker, error) {
	p := Picker{
		picker: picker{
			logger:                logger,
			ifaceCandidateByIndex: make(map[uint16]*ifaceCandidate),
		},
	}
	p.pktinfo4p.Store(&conn.Pktinfo{})
	p.pktinfo6p.Store(&conn.Pktinfo{})
	return &p, nil
}

type picker struct {
	logger                *tslog.Logger
	ifaceCandidateByIndex map[uint16]*ifaceCandidate
	pktinfo4              conn.Pktinfo
	pktinfo6              conn.Pktinfo
	pktinfo4p             atomic.Pointer[conn.Pktinfo]
	pktinfo6p             atomic.Pointer[conn.Pktinfo]
	wg                    sync.WaitGroup
}

func (p *picker) start(ctx context.Context) error {
	// Open routing socket first to ensure we don't miss any updates.
	f, err := bsdroute.OpenRoutingSocket()
	if err != nil {
		return fmt.Errorf("failed to open routing socket: %w", err)
	}

	ioctlFd, err := bsdroute.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to open ioctl socket: %w", err)
	}

	b, err := bsdroute.SysctlGetBytes([]int32{unix.CTL_NET, unix.AF_ROUTE, 0, unix.AF_UNSPEC, unix.NET_RT_IFLIST, 0})
	if err != nil {
		_ = f.Close()
		_ = unix.Close(ioctlFd)
		return fmt.Errorf("failed to get interface dump: %w", err)
	}
	p.handleRouteMessage(ioctlFd, b)

	b, err = bsdroute.SysctlGetBytes([]int32{unix.CTL_NET, unix.AF_ROUTE, 0, unix.AF_UNSPEC, unix.NET_RT_DUMP, 0})
	if err != nil {
		_ = f.Close()
		_ = unix.Close(ioctlFd)
		return fmt.Errorf("failed to get route dump: %w", err)
	}
	p.handleRouteMessage(ioctlFd, b)

	p.wg.Add(1)
	go func() {
		p.monitorRoutingSocket(f, ioctlFd)
		_ = f.Close()
		_ = unix.Close(ioctlFd)
		p.wg.Done()
	}()

	if ctxDone := ctx.Done(); ctxDone != nil {
		go func() {
			<-ctxDone
			if err := f.SetReadDeadline(conn.ALongTimeAgo); err != nil {
				p.logger.Error("Failed to set read deadline on routing socket", tslog.Err(err))
			}
		}()
	}

	p.logger.Info("Started interface picker")
	return nil
}

func (p *picker) monitorRoutingSocket(f *os.File, ioctlFd int) {
	// route(8) monitor uses this buffer size.
	// Each read only returns a single message.
	const readBufSize = 2048
	b := make([]byte, readBufSize)
	for {
		n, err := f.Read(b)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			p.logger.Error("Failed to read from routing socket", tslog.Err(err))
			continue
		}
		p.handleRouteMessage(ioctlFd, b[:n])
	}
}

func (p *picker) handleRouteMessage(ioctlFd int, b []byte) {
	for len(b) >= bsdroute.SizeofMsghdr {
		m := (*bsdroute.Msghdr)(unsafe.Pointer(unsafe.SliceData(b)))
		if m.Msglen < bsdroute.SizeofMsghdr || int(m.Msglen) > len(b) {
			p.logger.Error("Invalid routing message length",
				tslog.Uint("msglen", m.Msglen),
				tslog.Uint("version", m.Version),
				slog.Any("type", bsdroute.MsgType(m.Type)),
			)
			return
		}
		msgBuf := b[:m.Msglen]
		b = b[m.Msglen:]

		if m.Version != unix.RTM_VERSION {
			p.logger.Warn("Unsupported routing message version",
				tslog.Uint("msglen", m.Msglen),
				tslog.Uint("version", m.Version),
				slog.Any("type", bsdroute.MsgType(m.Type)),
			)
			continue
		}

		switch m.Type {
		case unix.RTM_IFINFO:
			if len(msgBuf) < unix.SizeofIfMsghdr {
				p.logger.Error("Invalid if_msghdr length",
					tslog.Uint("msglen", m.Msglen),
					tslog.Uint("version", m.Version),
					slog.Any("type", bsdroute.MsgType(m.Type)),
				)
				return
			}

			ifm := (*unix.IfMsghdr)(unsafe.Pointer(m))

			if ifm.Flags&unix.IFF_LOOPBACK != 0 ||
				ifm.Flags&unix.IFF_POINTOPOINT != 0 {
				continue
			}

			addrsBuf, ok := m.AddrsBuf(msgBuf, unix.SizeofIfMsghdr)
			if !ok {
				p.logger.Error("Invalid ifm_hdrlen",
					tslog.Uint("msglen", m.Msglen),
					tslog.Uint("version", m.Version),
					slog.Any("type", bsdroute.MsgType(m.Type)),
					tslog.Uint("hdrlen", m.HeaderLen()),
				)
				return
			}

			var addrs [unix.RTAX_MAX]*unix.RawSockaddr
			bsdroute.ParseAddrs(&addrs, addrsBuf, ifm.Addrs)
			ifpAddr := ifnameFromSockaddr(addrs[unix.RTAX_IFP])

			if p.logger.Enabled(slog.LevelDebug) {
				p.logger.Debug("Processing if_msghdr for physical interface",
					slog.Any("flags", bsdroute.IfaceFlags(ifm.Flags)),
					tslog.Uint("index", ifm.Index),
					slog.String("ifpAddr", ifpAddr),
				)
			}

			if ifm.Flags&unix.IFF_UP != 0 {
				// Interface is up, add it to the candidate map or update its name.
				iface, ok := p.ifaceCandidateByIndex[ifm.Index]
				switch {
				case !ok:
					p.ifaceCandidateByIndex[ifm.Index] = &ifaceCandidate{
						name: ifpAddr,
					}
				case ifpAddr != "" && iface.name == "":
					iface.name = ifpAddr
				}
			} else {
				// Interface is down, remove it from the candidate map.
				delete(p.ifaceCandidateByIndex, ifm.Index)
			}

		case unix.RTM_NEWADDR, unix.RTM_DELADDR:
			if len(msgBuf) < unix.SizeofIfaMsghdr {
				p.logger.Error("Invalid ifa_msghdr length",
					tslog.Uint("msglen", m.Msglen),
					tslog.Uint("version", m.Version),
					slog.Any("type", bsdroute.MsgType(m.Type)),
				)
				return
			}

			ifam := (*unix.IfaMsghdr)(unsafe.Pointer(m))

			iface, ok := p.ifaceCandidateByIndex[ifam.Index]
			if !ok {
				continue
			}

			addrsBuf, ok := m.AddrsBuf(msgBuf, unix.SizeofIfaMsghdr)
			if !ok {
				p.logger.Error("Invalid ifam_hdrlen",
					tslog.Uint("msglen", m.Msglen),
					tslog.Uint("version", m.Version),
					slog.Any("type", bsdroute.MsgType(m.Type)),
					tslog.Uint("hdrlen", m.HeaderLen()),
				)
				return
			}

			var addrs [unix.RTAX_MAX]*unix.RawSockaddr
			bsdroute.ParseAddrs(&addrs, addrsBuf, ifam.Addrs)

			ifpAddr := ifnameFromSockaddr(addrs[unix.RTAX_IFP])
			if ifpAddr != "" && iface.name == "" {
				iface.name = ifpAddr
			}

			ifaAddr := addrFromSockaddr(addrs[unix.RTAX_IFA])
			if ifaAddr.Is6() && !ifaAddr.IsLinkLocalUnicast() {
				if p.logger.Enabled(slog.LevelDebug) {
					p.logger.Debug("Processing ifa_msghdr for physical interface IPv6 address",
						slog.Any("type", bsdroute.MsgType(ifam.Type)),
						tslog.Uint("index", ifam.Index),
						tslog.Addr("ifaAddr", ifaAddr),
						slog.String("ifpAddr", ifpAddr),
					)
				}

				switch m.Type {
				case unix.RTM_NEWADDR:
					ifaFlags, err := bsdroute.IoctlGetIfaFlagInet6(ioctlFd, iface.name, (*unix.RawSockaddrInet6)(unsafe.Pointer(addrs[unix.RTAX_IFA])))
					if err != nil {
						p.logger.Warn("Failed to get interface IPv6 address flags",
							tslog.Uint("index", ifam.Index),
							tslog.Addr("ifaAddr", ifaAddr),
							slog.String("ifname", iface.name),
							tslog.Err(err),
						)
						continue
					}

					if ifaFlags&bsdroute.IN6_IFF_DEPRECATED != 0 ||
						ifaFlags&bsdroute.IN6_IFF_TEMPORARY != 0 {
						continue
					}

					if p.logger.Enabled(slog.LevelDebug) {
						p.logger.Debug("Updating physical interface IPv6 address",
							tslog.Uint("index", ifam.Index),
							tslog.Addr("ifaAddr", ifaAddr),
							tslog.Int("ifaFlags", ifaFlags),
							slog.String("ifname", iface.name),
						)
					}

					iface.addr6 = ifaAddr

				case unix.RTM_DELADDR:
					if iface.addr6 == ifaAddr {
						iface.addr6 = netip.Addr{}
					}

				default:
					panic("unreachable")
				}
			}

		case unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE, unix.RTM_GET:
			if len(msgBuf) < unix.SizeofRtMsghdr {
				p.logger.Error("Invalid rt_msghdr length",
					tslog.Uint("msglen", m.Msglen),
					tslog.Uint("version", m.Version),
					slog.Any("type", bsdroute.MsgType(m.Type)),
				)
				return
			}

			rtm := (*unix.RtMsghdr)(unsafe.Pointer(m))

			iface, ok := p.ifaceCandidateByIndex[rtm.Index]
			if !ok {
				continue
			}

			// Don't filter for RTF_UP, as RTM_DELETE messages do not have it set.
			if rtm.Flags&unix.RTF_GATEWAY == 0 ||
				rtm.Flags&unix.RTF_HOST != 0 {
				continue
			}

			// For RTM_GET messages, we only care about the ones from the route dump.
			// On macOS, RTM_GET messages received from sysctl(2) have its rtm_pid set to 0.
			// We assume this is the case on all BSDs.
			if rtm.Type == unix.RTM_GET && rtm.Pid != 0 {
				continue
			}

			addrsBuf, ok := m.AddrsBuf(msgBuf, unix.SizeofRtMsghdr)
			if !ok {
				p.logger.Error("Invalid rtm_hdrlen",
					tslog.Uint("msglen", m.Msglen),
					tslog.Uint("version", m.Version),
					slog.Any("type", bsdroute.MsgType(m.Type)),
					tslog.Uint("hdrlen", m.HeaderLen()),
				)
				return
			}

			var addrs [unix.RTAX_MAX]*unix.RawSockaddr
			bsdroute.ParseAddrs(&addrs, addrsBuf, rtm.Addrs)

			dstAddr := addrFromSockaddr(addrs[unix.RTAX_DST])
			if !dstAddr.IsUnspecified() {
				continue
			}

			netmaskAddr := addrFromSockaddr(addrs[unix.RTAX_NETMASK])
			if netmaskAddr.IsValid() && !netmaskAddr.IsUnspecified() {
				continue
			}

			ifaAddr := addrFromSockaddr(addrs[unix.RTAX_IFA])
			if !ifaAddr.IsValid() {
				continue
			}

			ifpAddr := ifnameFromSockaddr(addrs[unix.RTAX_IFP])
			if ifpAddr != "" && iface.name == "" {
				iface.name = ifpAddr
			}

			if p.logger.Enabled(slog.LevelDebug) {
				p.logger.Debug("Processing rt_msghdr for physical interface default route",
					slog.Any("type", bsdroute.MsgType(rtm.Type)),
					tslog.Uint("index", rtm.Index),
					slog.Any("flags", bsdroute.RouteFlags(rtm.Flags)),
					tslog.Int("pid", rtm.Pid),
					tslog.Int("seq", rtm.Seq),
					tslog.Addr("dstAddr", dstAddr),
					tslog.Addr("netmaskAddr", netmaskAddr),
					tslog.Addr("ifaAddr", ifaAddr),
					slog.String("ifpAddr", ifpAddr),
				)
			}

			switch m.Type {
			case unix.RTM_ADD, unix.RTM_CHANGE, unix.RTM_GET:
				switch {
				case ifaAddr.Is4():
					if p.pktinfo4.Addr != ifaAddr || p.pktinfo4.Ifindex != uint32(rtm.Index) {
						pktinfo4 := conn.Pktinfo{
							Addr:    ifaAddr,
							Ifindex: uint32(rtm.Index),
						}
						p.logger.Info("Updating default pktinfo4",
							tslog.Addr("oldAddr", p.pktinfo4.Addr),
							tslog.Uint("oldIfindex", p.pktinfo4.Ifindex),
							tslog.Addr("newAddr", pktinfo4.Addr),
							tslog.Uint("newIfindex", pktinfo4.Ifindex),
						)
						p.pktinfo4 = pktinfo4
						p.pktinfo4p.Store(&pktinfo4)
					}
				case iface.addr6.IsValid():
					// Unlike IPv4, the IPv6 address in a default route message is a link-local address.
					if p.pktinfo6.Addr != iface.addr6 || p.pktinfo6.Ifindex != uint32(rtm.Index) {
						pktinfo6 := conn.Pktinfo{
							Addr:    iface.addr6,
							Ifindex: uint32(rtm.Index),
						}
						p.logger.Info("Updating default pktinfo6",
							tslog.Addr("oldAddr", p.pktinfo6.Addr),
							tslog.Uint("oldIfindex", p.pktinfo6.Ifindex),
							tslog.Addr("newAddr", pktinfo6.Addr),
							tslog.Uint("newIfindex", pktinfo6.Ifindex),
						)
						p.pktinfo6 = pktinfo6
						p.pktinfo6p.Store(&pktinfo6)
					}
				}

			case unix.RTM_DELETE:
				switch {
				case ifaAddr.Is4():
					if p.pktinfo4.Addr == ifaAddr && p.pktinfo4.Ifindex == uint32(rtm.Index) {
						p.logger.Info("Deleting default pktinfo4",
							tslog.Addr("oldAddr", p.pktinfo4.Addr),
							tslog.Uint("oldIfindex", p.pktinfo4.Ifindex),
						)
						p.pktinfo4 = conn.Pktinfo{}
						p.pktinfo4p.Store(&conn.Pktinfo{})
					}
				case iface.addr6.IsValid():
					if p.pktinfo6.Addr == iface.addr6 && p.pktinfo6.Ifindex == uint32(rtm.Index) {
						p.logger.Info("Deleting default pktinfo6",
							tslog.Addr("oldAddr", p.pktinfo6.Addr),
							tslog.Uint("oldIfindex", p.pktinfo6.Ifindex),
						)
						p.pktinfo6 = conn.Pktinfo{}
						p.pktinfo6p.Store(&conn.Pktinfo{})
					}
				}

			default:
				panic("unreachable")
			}
		}
	}
}

type ifaceCandidate struct {
	name  string
	addr6 netip.Addr
}

func addrFromSockaddr(sa *unix.RawSockaddr) netip.Addr {
	if sa == nil {
		return netip.Addr{}
	}

	switch sa.Family {
	case unix.AF_INET:
		if sa.Len < unix.SizeofSockaddrInet4 {
			return netip.Addr{}
		}
		sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		return netip.AddrFrom4(sa4.Addr)

	case unix.AF_INET6:
		if sa.Len < unix.SizeofSockaddrInet6 {
			return netip.Addr{}
		}
		sa6 := (*unix.RawSockaddrInet6)(unsafe.Pointer(sa))
		return netip.AddrFrom16(sa6.Addr) // We don't need zone info here.

	default:
		return netip.Addr{}
	}
}

func ifnameFromSockaddr(sa *unix.RawSockaddr) string {
	if sa != nil && sa.Len >= unix.SizeofSockaddrDatalink && sa.Family == unix.AF_LINK {
		if sa := (*unix.RawSockaddrDatalink)(unsafe.Pointer(sa)); int(sa.Nlen) <= len(sa.Data) {
			ifnameBuf := unsafe.Slice((*byte)(unsafe.Pointer(&sa.Data)), sa.Nlen)
			return string(ifnameBuf)
		}
	}
	return ""
}

func (p *picker) stop() error {
	p.wg.Wait()
	p.logger.Info("Stopped interface picker")
	return nil
}

func (*picker) requestPoll() {}

func (p *picker) default4() *atomic.Pointer[conn.Pktinfo] {
	return &p.pktinfo4p
}

func (p *picker) default6() *atomic.Pointer[conn.Pktinfo] {
	return &p.pktinfo6p
}
