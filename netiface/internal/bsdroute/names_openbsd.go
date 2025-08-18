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
	RTM_RESOLVE                       = 0xb
	RTM_NEWADDR                       = 0xc
	RTM_DELADDR                       = 0xd
	RTM_IFINFO                        = 0xe
	RTM_IFANNOUNCE                    = 0xf
	RTM_DESYNC                        = 0x10
	RTM_INVALIDATE                    = 0x11
	RTM_BFD                           = 0x12
	RTM_PROPOSAL                      = 0x13
	RTM_CHGADDRATTR                   = 0x14
	RTM_80211INFO                     = 0x15
	RTM_SOURCE                        = 0x16
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
	case unix.RTM_RESOLVE:
		return "RTM_RESOLVE"
	case unix.RTM_NEWADDR:
		return "RTM_NEWADDR"
	case unix.RTM_DELADDR:
		return "RTM_DELADDR"
	case unix.RTM_IFINFO:
		return "RTM_IFINFO"
	case unix.RTM_IFANNOUNCE:
		return "RTM_IFANNOUNCE"
	case unix.RTM_DESYNC:
		return "RTM_DESYNC"
	case unix.RTM_INVALIDATE:
		return "RTM_INVALIDATE"
	case unix.RTM_BFD:
		return "RTM_BFD"
	case unix.RTM_PROPOSAL:
		return "RTM_PROPOSAL"
	case unix.RTM_CHGADDRATTR:
		return "RTM_CHGADDRATTR"
	case unix.RTM_80211INFO:
		return "RTM_80211INFO"
	case unix.RTM_SOURCE:
		return "RTM_SOURCE"
	default:
		return strconv.Itoa(int(m))
	}
}

/*
struct bits {
	int	b_mask;
	char	b_val;
};
static const struct bits bits[] = {
	{ RTF_UP,	'U' },
	{ RTF_GATEWAY,	'G' },
	{ RTF_HOST,	'H' },
	{ RTF_REJECT,	'R' },
	{ RTF_DYNAMIC,	'D' },
	{ RTF_MODIFIED,	'M' },
	{ RTF_CLONING,	'C' },
	{ RTF_MULTICAST,'m' },
	{ RTF_LLINFO,	'L' },
	{ RTF_STATIC,	'S' },
	{ RTF_BLACKHOLE,'B' },
	{ RTF_PROTO3,	'3' },
	{ RTF_PROTO2,	'2' },
	{ RTF_PROTO1,	'1' },
	{ RTF_CLONED,	'c' },
	{ RTF_CACHED,	'h' },
	{ RTF_MPATH,	'P' },
	{ RTF_MPLS,	'T' },
	{ RTF_LOCAL,	'l' },
	{ RTF_BFD,	'F' },
	{ RTF_BROADCAST,'b' },
	{ RTF_CONNECTED,'n' },
	{ 0 }
};
*/

var routeFlagNames = [...]struct {
	mask RouteFlags
	name byte
}{
	{unix.RTF_UP, 'U'},
	{unix.RTF_GATEWAY, 'G'},
	{unix.RTF_HOST, 'H'},
	{unix.RTF_REJECT, 'R'},
	{unix.RTF_DYNAMIC, 'D'},
	{unix.RTF_MODIFIED, 'M'},
	{unix.RTF_CLONING, 'C'},
	{unix.RTF_MULTICAST, 'm'},
	{unix.RTF_LLINFO, 'L'},
	{unix.RTF_STATIC, 'S'},
	{unix.RTF_BLACKHOLE, 'B'},
	{unix.RTF_PROTO3, '3'},
	{unix.RTF_PROTO2, '2'},
	{unix.RTF_PROTO1, '1'},
	{unix.RTF_CLONED, 'c'},
	{unix.RTF_CACHED, 'h'},
	{unix.RTF_MPATH, 'P'},
	{unix.RTF_MPLS, 'T'},
	{unix.RTF_LOCAL, 'l'},
	{unix.RTF_BFD, 'F'},
	{unix.RTF_BROADCAST, 'b'},
	{unix.RTF_CONNECTED, 'n'},
}

/*
	IFF_UP                            = 0x1
	IFF_BROADCAST                     = 0x2
	IFF_DEBUG                         = 0x4
	IFF_LOOPBACK                      = 0x8
	IFF_POINTOPOINT                   = 0x10
	IFF_STATICARP                     = 0x20
	IFF_RUNNING                       = 0x40
	IFF_NOARP                         = 0x80
	IFF_PROMISC                       = 0x100
	IFF_ALLMULTI                      = 0x200
	IFF_OACTIVE                       = 0x400
	IFF_SIMPLEX                       = 0x800
	IFF_LINK0                         = 0x1000
	IFF_LINK1                         = 0x2000
	IFF_LINK2                         = 0x4000
	IFF_MULTICAST                     = 0x8000
	IFF_CANTCHANGE                    = 0x8e52
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
	{unix.IFF_STATICARP, "STATICARP"},
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
	{unix.IFF_CANTCHANGE, "CANTCHANGE"},
}
