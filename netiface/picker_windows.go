package netiface

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/netiface/internal/iphlpapi"
	"github.com/database64128/swgp-go/tslog"
	"golang.org/x/sys/windows"
)

func (*PickerConfig) newPicker(logger *tslog.Logger) (*Picker, error) {
	return &Picker{
		picker: picker{
			logger:          logger,
			ifaceInfoByLuid: make(map[uint64]*ifaceInfo),
		},
	}, nil
}

type picker struct {
	logger                                            *tslog.Logger
	ifaceInfoByLuid                                   map[uint64]*ifaceInfo
	activeIfaceLuid4                                  uint64
	activeIfaceLuid6                                  uint64
	activeIfaceInfo4                                  *ifaceInfo
	activeIfaceInfo6                                  *ifaceInfo
	pktinfo4p                                         atomic.Pointer[conn.Pktinfo]
	pktinfo6p                                         atomic.Pointer[conn.Pktinfo]
	notifyCh                                          chan<- mibNotification
	pinner                                            runtime.Pinner
	wg                                                sync.WaitGroup
	notificationHandleUnicastIpAddressChange          windows.Handle
	notificationHandleRouteChange2                    windows.Handle
	initialNotificationReceivedUnicastIpAddressChange bool
	initialNotificationReceivedRouteChange2           bool
}

type ifaceInfo struct {
	Addr4 netip.Addr
	Addr6 netip.Addr
}

type mibNotification struct {
	InterfaceLuid    uint64
	InterfaceIndex   uint32
	NotificationType uint32
	NextHop          windows.RawSockaddrInet
	Address          windows.RawSockaddrInet // also for DestinationPrefix.Prefix
	PrefixLength     uint8
	Kind             mibNotificationKind
}

type mibNotificationKind uint8

const (
	mibNotificationKindUnicastIpAddressRow mibNotificationKind = iota
	mibNotificationKindIpForwardRow2
)

func (k mibNotificationKind) String() string {
	switch k {
	case mibNotificationKindUnicastIpAddressRow:
		return "UnicastIpAddressRow"
	case mibNotificationKindIpForwardRow2:
		return "IpForwardRow2"
	default:
		return fmt.Sprintf("Invalid(%#x)", uint8(k))
	}
}

var notifyUnicastIpAddressChangeCallback = sync.OnceValue(func() uintptr {
	return syscall.NewCallback(func(callerContext *chan<- mibNotification, row *windows.MibUnicastIpAddressRow, notificationType uint32) uintptr {
		nmsg := mibNotification{
			Kind:             mibNotificationKindUnicastIpAddressRow,
			NotificationType: notificationType,
		}
		if row != nil {
			nmsg.Address = *(*windows.RawSockaddrInet)(unsafe.Pointer(&row.Address))
			nmsg.InterfaceLuid = row.InterfaceLuid
			nmsg.InterfaceIndex = row.InterfaceIndex
		}
		notifyCh := *callerContext
		notifyCh <- nmsg
		return 0
	})
})

var notifyRouteChange2Callback = sync.OnceValue(func() uintptr {
	return syscall.NewCallback(func(callerContext *chan<- mibNotification, row *windows.MibIpForwardRow2, notificationType uint32) uintptr {
		nmsg := mibNotification{
			Kind:             mibNotificationKindIpForwardRow2,
			NotificationType: notificationType,
		}
		if row != nil {
			nmsg.InterfaceLuid = row.InterfaceLuid
			nmsg.InterfaceIndex = row.InterfaceIndex
			nmsg.Address = row.DestinationPrefix.Prefix
			nmsg.PrefixLength = row.DestinationPrefix.PrefixLength
			nmsg.NextHop = row.NextHop
		}
		notifyCh := *callerContext
		notifyCh <- nmsg
		return 0
	})
})

func (p *picker) start(_ context.Context) error {
	notifyCh := make(chan mibNotification)
	p.notifyCh = notifyCh
	p.pinner.Pin(&p.notifyCh)

	// Spin up the consumer goroutine before registering for notifications,
	// because the Notify* functions send initial notifications and blocks
	// until the callback calls return.
	p.wg.Go(func() {
		p.initialNotificationReceivedUnicastIpAddressChange = false
		p.initialNotificationReceivedRouteChange2 = false
		for nmsg := range notifyCh {
			p.handleMibNotification(nmsg)
		}
	})

	if err := windows.NotifyUnicastIpAddressChange(
		windows.AF_UNSPEC,
		notifyUnicastIpAddressChangeCallback(),
		unsafe.Pointer(&p.notifyCh),
		true,
		&p.notificationHandleUnicastIpAddressChange,
	); err != nil {
		return os.NewSyscallError("NotifyUnicastIpAddressChange", err)
	}

	p.logger.Info("Registered for IP address change notifications",
		tslog.Uint("notificationHandle", p.notificationHandleUnicastIpAddressChange),
	)

	if err := windows.NotifyRouteChange2(
		windows.AF_UNSPEC,
		notifyRouteChange2Callback(),
		unsafe.Pointer(&p.notifyCh),
		true,
		&p.notificationHandleRouteChange2,
	); err != nil {
		_ = windows.CancelMibChangeNotify2(p.notificationHandleUnicastIpAddressChange)
		return os.NewSyscallError("NotifyRouteChange2", err)
	}

	p.logger.Info("Registered for route change notifications",
		tslog.Uint("notificationHandle", p.notificationHandleRouteChange2),
	)

	p.logger.Info("Started interface picker")
	return nil
}

func (p *picker) handleMibNotification(nmsg mibNotification) {
	if p.logger.Enabled(slog.LevelDebug) {
		p.logger.Debug("Received change notification",
			tslog.Uint("interfaceLuid", nmsg.InterfaceLuid),
			tslog.Uint("interfaceIndex", nmsg.InterfaceIndex),
			tslog.Uint("notificationType", nmsg.NotificationType),
			slog.Any("kind", nmsg.Kind),
		)
	}

	switch nmsg.Kind {
	case mibNotificationKindUnicastIpAddressRow:
		p.handleMibUnicastIpAddressRowNotification(nmsg)
	case mibNotificationKindIpForwardRow2:
		p.handleMibIpForwardRow2Notification(nmsg)
	default:
		panic("unreachable")
	}
}

func (p *picker) handleMibUnicastIpAddressRowNotification(nmsg mibNotification) {
	switch nmsg.NotificationType {
	case windows.MibParameterNotification, windows.MibAddInstance:
		addr := ipFromSockaddrInet(&nmsg.Address)
		if !addr.IsValid() || addr.IsLinkLocalUnicast() {
			return
		}

		var iface *ifaceInfo
		switch nmsg.InterfaceLuid {
		case p.activeIfaceLuid4:
			iface = p.activeIfaceInfo4
		case p.activeIfaceLuid6:
			iface = p.activeIfaceInfo6
		default:
			iface = p.ifaceInfoByLuid[nmsg.InterfaceLuid]
		}

		switch {
		case iface == nil:
			iface = &ifaceInfo{}
			p.ifaceInfoByLuid[nmsg.InterfaceLuid] = iface
		case addr == iface.Addr4 || addr == iface.Addr6:
			return
		}

		// Retrieve full address information.
		row := windows.MibUnicastIpAddressRow{
			Address:        *(*windows.RawSockaddrInet6)(unsafe.Pointer(&nmsg.Address)),
			InterfaceLuid:  nmsg.InterfaceLuid,
			InterfaceIndex: nmsg.InterfaceIndex,
		}

		if err := windows.GetUnicastIpAddressEntry(&row); err != nil {
			if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_NOT_FOUND {
				if p.logger.Enabled(slog.LevelDebug) {
					p.logger.Debug("Skipping IP address change notification for deleted address",
						tslog.Addr("addr", addr),
						tslog.Uint("interfaceLuid", nmsg.InterfaceLuid),
						tslog.Uint("interfaceIndex", nmsg.InterfaceIndex),
						tslog.Uint("notificationType", nmsg.NotificationType),
					)
				}
				return
			}
			p.logger.Error("Failed to get IP address entry for IP address change notification",
				tslog.Addr("addr", addr),
				tslog.Uint("interfaceLuid", nmsg.InterfaceLuid),
				tslog.Uint("interfaceIndex", nmsg.InterfaceIndex),
				tslog.Uint("notificationType", nmsg.NotificationType),
				tslog.Err(os.NewSyscallError("GetUnicastIpAddressEntry", err)),
			)
			return
		}

		if p.logger.Enabled(slog.LevelDebug) {
			p.logger.Debug("Processing new or changed IP address",
				tslog.Addr("addr", addr),
				tslog.Uint("notificationType", nmsg.NotificationType),
				tslog.Uint("interfaceLuid", row.InterfaceLuid),
				tslog.Uint("interfaceIndex", row.InterfaceIndex),
				tslog.Uint("prefixOrigin", row.PrefixOrigin),
				tslog.Uint("suffixOrigin", row.SuffixOrigin),
				tslog.Uint("validLifetime", row.ValidLifetime),
				tslog.Uint("preferredLifetime", row.PreferredLifetime),
				tslog.Uint("onLinkPrefixLength", row.OnLinkPrefixLength),
				tslog.Uint("skipAsSource", row.SkipAsSource),
				tslog.Uint("dadState", row.DadState),
				tslog.Uint("scopeId", row.ScopeId),
			)
		}

		// Skip temporary and deprecated addresses.
		if row.SuffixOrigin == windows.IpSuffixOriginRandom ||
			row.DadState == windows.IpDadStateDeprecated {
			return
		}

		if addr.Is4() {
			if p.logger.Enabled(slog.LevelDebug) {
				p.logger.Debug("Updating interface IPv4 address",
					tslog.Addr("addr", addr),
					tslog.Uint("interfaceLuid", nmsg.InterfaceLuid),
					tslog.Uint("interfaceIndex", nmsg.InterfaceIndex),
				)
			}
			iface.Addr4 = addr

			if iface == p.activeIfaceInfo4 {
				pktinfo4 := conn.Pktinfo{
					Addr:    addr,
					Ifindex: nmsg.InterfaceIndex,
				}
				p.logger.Info("Updating default pktinfo4 addr",
					tslog.Addrp("addr", &pktinfo4.Addr),
					tslog.Uint("ifindex", pktinfo4.Ifindex),
				)
				p.pktinfo4p.Store(&pktinfo4)
			}
		} else {
			if p.logger.Enabled(slog.LevelDebug) {
				p.logger.Debug("Updating interface IPv6 address",
					tslog.Addr("addr", addr),
					tslog.Uint("interfaceLuid", nmsg.InterfaceLuid),
					tslog.Uint("interfaceIndex", nmsg.InterfaceIndex),
				)
			}
			iface.Addr6 = addr

			if iface == p.activeIfaceInfo6 {
				pktinfo6 := conn.Pktinfo{
					Addr:    addr,
					Ifindex: nmsg.InterfaceIndex,
				}
				p.logger.Info("Updating default pktinfo6 addr",
					tslog.Addrp("addr", &pktinfo6.Addr),
					tslog.Uint("ifindex", pktinfo6.Ifindex),
				)
				p.pktinfo6p.Store(&pktinfo6)
			}
		}

	case windows.MibDeleteInstance:
		addr := ipFromSockaddrInet(&nmsg.Address)
		if !addr.IsValid() || addr.IsLinkLocalUnicast() {
			return
		}

		switch nmsg.InterfaceLuid {
		case p.activeIfaceLuid4:
			if p.activeIfaceInfo4 != nil && addr == p.activeIfaceInfo4.Addr4 {
				p.logger.Info("Deleting default pktinfo4",
					tslog.Addr("oldAddr", addr),
					tslog.Uint("oldIfindex", nmsg.InterfaceIndex),
				)
				p.activeIfaceInfo4.Addr4 = netip.Addr{}
				p.pktinfo4p.Store(nil)
			}

		case p.activeIfaceLuid6:
			if p.activeIfaceInfo6 != nil && addr == p.activeIfaceInfo6.Addr6 {
				p.logger.Info("Deleting default pktinfo6",
					tslog.Addr("oldAddr", addr),
					tslog.Uint("oldIfindex", nmsg.InterfaceIndex),
				)
				p.activeIfaceInfo6.Addr6 = netip.Addr{}
				p.pktinfo6p.Store(nil)
			}

		default:
			iface := p.ifaceInfoByLuid[nmsg.InterfaceLuid]
			if iface != nil {
				switch addr {
				case iface.Addr4:
					if p.logger.Enabled(slog.LevelDebug) {
						p.logger.Debug("Removing interface IPv4 address",
							tslog.Addr("addr", addr),
							tslog.Uint("interfaceLuid", nmsg.InterfaceLuid),
							tslog.Uint("interfaceIndex", nmsg.InterfaceIndex),
						)
					}
					iface.Addr4 = netip.Addr{}

				case iface.Addr6:
					if p.logger.Enabled(slog.LevelDebug) {
						p.logger.Debug("Removing interface IPv6 address",
							tslog.Addr("addr", addr),
							tslog.Uint("interfaceLuid", nmsg.InterfaceLuid),
							tslog.Uint("interfaceIndex", nmsg.InterfaceIndex),
						)
					}
					iface.Addr6 = netip.Addr{}
				}
			}
		}

	case windows.MibInitialNotification:
		// With AF_UNSPEC, NotifyUnicastIpAddressChange sends 2 initial notifications,
		// likely one for AF_INET and one for AF_INET6, but with no way to distinguish
		// between them.
		if p.initialNotificationReceivedUnicastIpAddressChange {
			p.logger.Debug("Skipping subsequent initial IP address change notification")
			return
		}
		p.initialNotificationReceivedUnicastIpAddressChange = true

		var table *iphlpapi.MibUnicastIpAddressTable
		if err := iphlpapi.GetUnicastIpAddressTable(windows.AF_UNSPEC, &table); err != nil {
			p.logger.Error("Failed to get IP address table",
				tslog.Err(os.NewSyscallError("GetUnicastIpAddressTable", err)),
			)
			return
		}

		var (
			currentIfaceLuid uint64
			currentIfaceInfo *ifaceInfo
		)

		rows := table.Rows()
		for i := range rows {
			row := &rows[i]

			// Skip temporary and deprecated addresses.
			if row.SuffixOrigin == windows.IpSuffixOriginRandom ||
				row.DadState == windows.IpDadStateDeprecated {
				continue
			}

			addr := ipFromSockaddrInet((*windows.RawSockaddrInet)(unsafe.Pointer(&row.Address)))
			if !addr.IsValid() || addr.IsLinkLocalUnicast() {
				continue
			}

			if p.logger.Enabled(slog.LevelDebug) {
				p.logger.Debug("Processing IP address from initial IP address table dump",
					tslog.Addr("addr", addr),
					tslog.Uint("interfaceLuid", row.InterfaceLuid),
					tslog.Uint("interfaceIndex", row.InterfaceIndex),
					tslog.Uint("prefixOrigin", row.PrefixOrigin),
					tslog.Uint("suffixOrigin", row.SuffixOrigin),
					tslog.Uint("validLifetime", row.ValidLifetime),
					tslog.Uint("preferredLifetime", row.PreferredLifetime),
					tslog.Uint("onLinkPrefixLength", row.OnLinkPrefixLength),
					tslog.Uint("skipAsSource", row.SkipAsSource),
					tslog.Uint("dadState", row.DadState),
					tslog.Uint("scopeId", row.ScopeId),
				)
			}

			if row.InterfaceLuid != currentIfaceLuid {
				currentIfaceLuid = row.InterfaceLuid
				currentIfaceInfo = p.ifaceInfoByLuid[currentIfaceLuid]
				if currentIfaceInfo == nil {
					currentIfaceInfo = &ifaceInfo{}
					p.ifaceInfoByLuid[currentIfaceLuid] = currentIfaceInfo
				}
			}

			if addr.Is4() {
				currentIfaceInfo.Addr4 = addr
			} else {
				currentIfaceInfo.Addr6 = addr
			}
		}

		windows.FreeMibTable(unsafe.Pointer(table))

	default:
		p.logger.Warn("Received IP address change notification with unknown type",
			tslog.Uint("interfaceLuid", nmsg.InterfaceLuid),
			tslog.Uint("interfaceIndex", nmsg.InterfaceIndex),
			tslog.Uint("notificationType", nmsg.NotificationType),
		)
	}
}

func (p *picker) handleMibIpForwardRow2Notification(nmsg mibNotification) {
	switch nmsg.NotificationType {
	case windows.MibParameterNotification, windows.MibAddInstance:
		p.handleNewMibIpForwardRow2(
			nmsg.InterfaceLuid,
			nmsg.InterfaceIndex,
			&nmsg.NextHop,
			&nmsg.Address,
			nmsg.PrefixLength,
		)

	case windows.MibDeleteInstance:
		switch getMibIpForwardRow2Kind(&nmsg.NextHop, &nmsg.Address, nmsg.PrefixLength) {
		case mibIpForwardRow2KindDefaultWithNextHop4:
			if nmsg.InterfaceLuid == p.activeIfaceLuid4 {
				if p.activeIfaceInfo4 != nil && p.activeIfaceInfo4.Addr4.IsValid() {
					p.logger.Info("Removing default pktinfo4",
						tslog.Addr("oldAddr", p.activeIfaceInfo4.Addr4),
						tslog.Uint("oldIfindex", nmsg.InterfaceIndex),
					)
					p.pktinfo4p.Store(nil)
				}

				p.logger.Info("Removing default IPv4 interface",
					tslog.Uint("interfaceLuid", nmsg.InterfaceLuid),
					tslog.Uint("interfaceIndex", nmsg.InterfaceIndex),
				)
				p.activeIfaceLuid4 = 0
				p.activeIfaceInfo4 = nil
			}

		case mibIpForwardRow2KindDefaultWithNextHop6:
			if nmsg.InterfaceLuid == p.activeIfaceLuid6 {
				if p.activeIfaceInfo6 != nil && p.activeIfaceInfo6.Addr6.IsValid() {
					p.logger.Info("Removing default pktinfo6",
						tslog.Addr("oldAddr", p.activeIfaceInfo6.Addr6),
						tslog.Uint("oldIfindex", nmsg.InterfaceIndex),
					)
					p.pktinfo6p.Store(nil)
				}

				p.logger.Info("Removing default IPv6 interface",
					tslog.Uint("interfaceLuid", nmsg.InterfaceLuid),
					tslog.Uint("interfaceIndex", nmsg.InterfaceIndex),
				)
				p.activeIfaceLuid6 = 0
				p.activeIfaceInfo6 = nil
			}
		}

	case windows.MibInitialNotification:
		// With AF_UNSPEC, NotifyRouteChange2 sends 2 initial notifications,
		// likely one for AF_INET and one for AF_INET6, but with no way to
		// distinguish between them.
		if p.initialNotificationReceivedRouteChange2 {
			p.logger.Debug("Skipping subsequent initial route change notification")
			return
		}
		p.initialNotificationReceivedRouteChange2 = true

		var table *windows.MibIpForwardTable2
		if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil {
			p.logger.Error("Failed to get route table",
				tslog.Err(os.NewSyscallError("GetIpForwardTable2", err)),
			)
			return
		}

		rows := table.Rows()
		for i := range rows {
			row := &rows[i]

			p.handleNewMibIpForwardRow2(
				row.InterfaceLuid,
				row.InterfaceIndex,
				&row.NextHop,
				&row.DestinationPrefix.Prefix,
				row.DestinationPrefix.PrefixLength,
			)
		}

		windows.FreeMibTable(unsafe.Pointer(table))

	default:
		p.logger.Warn("Received route change notification with unknown type",
			tslog.Uint("interfaceLuid", nmsg.InterfaceLuid),
			tslog.Uint("interfaceIndex", nmsg.InterfaceIndex),
			tslog.Uint("notificationType", nmsg.NotificationType),
		)
	}
}

func (p *picker) handleNewMibIpForwardRow2(
	interfaceLuid uint64,
	interfaceIndex uint32,
	nextHop *windows.RawSockaddrInet,
	destinationPrefix *windows.RawSockaddrInet,
	destinationPrefixLength uint8,
) {
	switch getMibIpForwardRow2Kind(nextHop, destinationPrefix, destinationPrefixLength) {
	case mibIpForwardRow2KindDefaultWithNextHop4:
		if interfaceLuid != p.activeIfaceLuid4 {
			p.logger.Info("Updating default IPv4 interface",
				tslog.Uint("oldInterfaceLuid", p.activeIfaceLuid4),
				tslog.Uint("newInterfaceLuid", interfaceLuid),
			)
			p.activeIfaceLuid4 = interfaceLuid

			p.activeIfaceInfo4 = p.ifaceInfoByLuid[interfaceLuid]
			switch {
			case p.activeIfaceInfo4 == nil:
				p.activeIfaceInfo4 = &ifaceInfo{}
				p.ifaceInfoByLuid[interfaceLuid] = p.activeIfaceInfo4
			case p.activeIfaceInfo4.Addr4.IsValid():
				pktinfo4 := conn.Pktinfo{
					Addr:    p.activeIfaceInfo4.Addr4,
					Ifindex: interfaceIndex,
				}
				p.logger.Info("Updating default pktinfo4",
					tslog.Addrp("addr", &pktinfo4.Addr),
					tslog.Uint("ifindex", pktinfo4.Ifindex),
				)
				p.pktinfo4p.Store(&pktinfo4)
			}
		}

	case mibIpForwardRow2KindDefaultWithNextHop6:
		if interfaceLuid != p.activeIfaceLuid6 {
			p.logger.Info("Updating default IPv6 interface",
				tslog.Uint("oldInterfaceLuid", p.activeIfaceLuid6),
				tslog.Uint("newInterfaceLuid", interfaceLuid),
			)
			p.activeIfaceLuid6 = interfaceLuid

			p.activeIfaceInfo6 = p.ifaceInfoByLuid[interfaceLuid]
			switch {
			case p.activeIfaceInfo6 == nil:
				p.activeIfaceInfo6 = &ifaceInfo{}
				p.ifaceInfoByLuid[interfaceLuid] = p.activeIfaceInfo6
			case p.activeIfaceInfo6.Addr6.IsValid():
				pktinfo6 := conn.Pktinfo{
					Addr:    p.activeIfaceInfo6.Addr6,
					Ifindex: interfaceIndex,
				}
				p.logger.Info("Updating default pktinfo6",
					tslog.Addrp("addr", &pktinfo6.Addr),
					tslog.Uint("ifindex", pktinfo6.Ifindex),
				)
				p.pktinfo6p.Store(&pktinfo6)
			}
		}
	}
}

type mibIpForwardRow2Kind uint8

const (
	mibIpForwardRow2KindOther mibIpForwardRow2Kind = iota
	mibIpForwardRow2KindDefaultWithNextHop4
	mibIpForwardRow2KindDefaultWithNextHop6
)

func (k mibIpForwardRow2Kind) String() string {
	switch k {
	case mibIpForwardRow2KindOther:
		return "Other"
	case mibIpForwardRow2KindDefaultWithNextHop4:
		return "DefaultWithNextHop4"
	case mibIpForwardRow2KindDefaultWithNextHop6:
		return "DefaultWithNextHop6"
	default:
		return fmt.Sprintf("Invalid(%#x)", uint8(k))
	}
}

func getMibIpForwardRow2Kind(
	nextHop *windows.RawSockaddrInet,
	destinationPrefix *windows.RawSockaddrInet,
	destinationPrefixLength uint8,
) mibIpForwardRow2Kind {
	if destinationPrefixLength != 0 {
		return mibIpForwardRow2KindOther
	}

	prefixAddr := ipFromSockaddrInet(destinationPrefix)
	if !prefixAddr.IsUnspecified() {
		return mibIpForwardRow2KindOther
	}

	nextHopAddr := ipFromSockaddrInet(nextHop)
	// A WireGuard interface's default route has an all-zero next hop address.
	if !nextHopAddr.IsValid() || nextHopAddr.IsUnspecified() {
		return mibIpForwardRow2KindOther
	}
	if nextHopAddr.Is4() {
		return mibIpForwardRow2KindDefaultWithNextHop4
	}
	return mibIpForwardRow2KindDefaultWithNextHop6
}

func ipFromSockaddrInet(sa *windows.RawSockaddrInet) netip.Addr {
	switch sa.Family {
	case windows.AF_INET:
		sa4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa))
		return netip.AddrFrom4(sa4.Addr)
	case windows.AF_INET6:
		sa6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(sa))
		return netip.AddrFrom16(sa6.Addr)
	default:
		return netip.Addr{}
	}
}

func (p *picker) stop() error {
	if err := windows.CancelMibChangeNotify2(p.notificationHandleRouteChange2); err != nil {
		return os.NewSyscallError("CancelMibChangeNotify2(p.notificationHandleRouteChange2)", err)
	}

	p.logger.Info("Unregistered for route change notifications")

	if err := windows.CancelMibChangeNotify2(p.notificationHandleUnicastIpAddressChange); err != nil {
		return os.NewSyscallError("CancelMibChangeNotify2(p.notificationHandleUnicastIpAddressChange)", err)
	}

	p.logger.Info("Unregistered for IP address change notifications")

	p.pinner.Unpin()
	close(p.notifyCh)
	p.wg.Wait()

	p.logger.Info("Stopped interface picker")
	return nil
}

func (p *picker) default4() *atomic.Pointer[conn.Pktinfo] {
	return &p.pktinfo4p
}

func (p *picker) default6() *atomic.Pointer[conn.Pktinfo] {
	return &p.pktinfo6p
}
