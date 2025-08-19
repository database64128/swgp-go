package bsdroute

import (
	"strconv"

	"golang.org/x/sys/unix"
)

/*
	RTM_ADD                           = 0x1
	RTM_DELETE                        = 0x2
	RTM_CHANGE                        = 0x3
	RTM_GET                           = 0x4
	RTM_LOSING                        = 0x5
	RTM_REDIRECT                      = 0x6
	RTM_MISS                          = 0x7
	RTM_LOCK                          = 0x8
	RTM_RESOLVE                       = 0xb
	RTM_NEWADDR                       = 0xc
	RTM_DELADDR                       = 0xd
	RTM_IFINFO                        = 0xe
	RTM_NEWMADDR                      = 0xf
	RTM_DELMADDR                      = 0x10
	RTM_IFANNOUNCE                    = 0x11
	RTM_IEEE80211                     = 0x12
*/

func (m MsgType) string() string {
	switch m {
	case unix.RTM_ADD:
		return "RTM_ADD"
	case unix.RTM_DELETE:
		return "RTM_DELETE"
	case unix.RTM_CHANGE:
		return "RTM_CHANGE"
	case unix.RTM_GET:
		return "RTM_GET"
	case unix.RTM_LOSING:
		return "RTM_LOSING"
	case unix.RTM_REDIRECT:
		return "RTM_REDIRECT"
	case unix.RTM_MISS:
		return "RTM_MISS"
	case unix.RTM_LOCK:
		return "RTM_LOCK"
	case unix.RTM_RESOLVE:
		return "RTM_RESOLVE"
	case unix.RTM_NEWADDR:
		return "RTM_NEWADDR"
	case unix.RTM_DELADDR:
		return "RTM_DELADDR"
	case unix.RTM_IFINFO:
		return "RTM_IFINFO"
	case unix.RTM_NEWMADDR:
		return "RTM_NEWMADDR"
	case unix.RTM_DELMADDR:
		return "RTM_DELMADDR"
	case unix.RTM_IFANNOUNCE:
		return "RTM_IFANNOUNCE"
	case unix.RTM_IEEE80211:
		return "RTM_IEEE80211"
	default:
		return strconv.Itoa(int(m))
	}
}

// Source: https://github.com/DragonFlyBSD/DragonFlyBSD/blob/master/sbin/route/show.c
//
// /*
//  * Definitions for showing gateway flags.
//  */
// struct bits {
// 	int	b_mask;
// 	char	b_val;
// };
// static const struct bits bits[] = {
// 	{ RTF_UP,	'U' },
// 	{ RTF_GATEWAY,	'G' },
// 	{ RTF_HOST,	'H' },
// 	{ RTF_REJECT,	'R' },
// 	{ RTF_BLACKHOLE, 'B' },
// 	{ RTF_DYNAMIC,	'D' },
// 	{ RTF_MODIFIED,	'M' },
// 	{ RTF_DONE,	'd' }, /* Completed -- for routing messages only */
// 	{ RTF_CLONING,	'C' },
// 	{ RTF_XRESOLVE,	'X' },
// 	{ RTF_LLINFO,	'L' },
// 	{ RTF_STATIC,	'S' },
// 	{ RTF_PROTO1,	'1' },
// 	{ RTF_PROTO2,	'2' },
// 	{ RTF_PROTO3,	'3' },
// 	{ 0, 0 }
// };

var routeFlagNames = [...]struct {
	mask RouteFlags
	name byte
}{
	{unix.RTF_UP, 'U'},
	{unix.RTF_GATEWAY, 'G'},
	{unix.RTF_HOST, 'H'},
	{unix.RTF_REJECT, 'R'},
	{unix.RTF_BLACKHOLE, 'B'},
	{unix.RTF_DYNAMIC, 'D'},
	{unix.RTF_MODIFIED, 'M'},
	{unix.RTF_DONE, 'd'},
	{unix.RTF_CLONING, 'C'},
	{unix.RTF_XRESOLVE, 'X'},
	{unix.RTF_LLINFO, 'L'},
	{unix.RTF_STATIC, 'S'},
	{unix.RTF_PROTO1, '1'},
	{unix.RTF_PROTO2, '2'},
	{unix.RTF_PROTO3, '3'},
}

/*
	IFF_UP                            = 0x1
	IFF_BROADCAST                     = 0x2
	IFF_DEBUG                         = 0x4
	IFF_LOOPBACK                      = 0x8
	IFF_POINTOPOINT                   = 0x10
	IFF_SMART                         = 0x20
	IFF_RUNNING                       = 0x40
	IFF_NOARP                         = 0x80
	IFF_PROMISC                       = 0x100
	IFF_ALLMULTI                      = 0x200
	IFF_OACTIVE                       = 0x400
	IFF_OACTIVE_COMPAT                = 0x400
	IFF_SIMPLEX                       = 0x800
	IFF_LINK0                         = 0x1000
	IFF_LINK1                         = 0x2000
	IFF_LINK2                         = 0x4000
	IFF_ALTPHYS                       = 0x4000
	IFF_MULTICAST                     = 0x8000
	IFF_POLLING                       = 0x10000
	IFF_POLLING_COMPAT                = 0x10000
	IFF_PPROMISC                      = 0x20000
	IFF_MONITOR                       = 0x40000
	IFF_STATICARP                     = 0x80000
	IFF_NPOLLING                      = 0x100000
	IFF_IDIRECT                       = 0x200000
	IFF_CANTCHANGE                    = 0x318e72
*/

var ifaceFlagNames = [...]struct {
	mask IfaceFlags
	name string
}{
	{unix.IFF_UP, "UP"},
	{unix.IFF_BROADCAST, "BROADCAST"},
	{unix.IFF_DEBUG, "DEBUG"},
	{unix.IFF_LOOPBACK, "LOOPBACK"},
	{unix.IFF_POINTOPOINT, "POINTOPOINT"},
	{unix.IFF_SMART, "SMART"},
	{unix.IFF_RUNNING, "RUNNING"},
	{unix.IFF_NOARP, "NOARP"},
	{unix.IFF_PROMISC, "PROMISC"},
	{unix.IFF_ALLMULTI, "ALLMULTI"},
	{unix.IFF_OACTIVE, "OACTIVE"},
	{unix.IFF_SIMPLEX, "SIMPLEX"},
	{unix.IFF_LINK0, "LINK0"},
	{unix.IFF_LINK1, "LINK1"},
	{unix.IFF_LINK2, "LINK2"},
	{unix.IFF_MULTICAST, "MULTICAST"},
	{unix.IFF_POLLING, "POLLING"},
	{unix.IFF_PPROMISC, "PPROMISC"},
	{unix.IFF_MONITOR, "MONITOR"},
	{unix.IFF_STATICARP, "STATICARP"},
	{unix.IFF_NPOLLING, "NPOLLING"},
	{unix.IFF_IDIRECT, "IDIRECT"},
}

// Constants for interface IPv6 address flags (ia6_flags, ifru_flags6).
//
// Source: https://github.com/DragonFlyBSD/DragonFlyBSD/blob/master/sys/netinet6/in6_var.h
const (
	IN6_IFF_ANYCAST    = 0x0001 // anycast address
	IN6_IFF_TENTATIVE  = 0x0002 // tentative address
	IN6_IFF_DUPLICATED = 0x0004 // DAD detected duplicate
	IN6_IFF_DETACHED   = 0x0008 // may be detached from the link
	IN6_IFF_DEPRECATED = 0x0010 // deprecated address
	IN6_IFF_NODAD      = 0x0020 // don't perform DAD on this address (used only at first SIOC* call)
	IN6_IFF_AUTOCONF   = 0x0040 // autoconfigurable address.
	IN6_IFF_TEMPORARY  = 0x0080 // temporary (anonymous) address.
	IN6_IFF_NOPFX      = 0x8000 // skip kernel prefix management. XXX: this should be temporary.
)

var ifaFlags6Names = [...]struct {
	mask IfaFlags6
	name string
}{
	{IN6_IFF_ANYCAST, "anycast"},
	{IN6_IFF_TENTATIVE, "tentative"},
	{IN6_IFF_DUPLICATED, "duplicated"},
	{IN6_IFF_DETACHED, "detached"},
	{IN6_IFF_DEPRECATED, "deprecated"},
	{IN6_IFF_NODAD, "nodad"},
	{IN6_IFF_AUTOCONF, "autoconf"},
	{IN6_IFF_TEMPORARY, "temporary"},
	{IN6_IFF_NOPFX, "nopfx"},
}
