package bsdroute

import (
	"strconv"

	"golang.org/x/sys/unix"
)

/*
	RTM_ADD                        = 0x1
	RTM_DELETE                     = 0x2
	RTM_CHANGE                     = 0x3
	RTM_GET                        = 0x4
	RTM_LOSING                     = 0x5
	RTM_REDIRECT                   = 0x6
	RTM_MISS                       = 0x7
	RTM_LOCK                       = 0x8
	RTM_RESOLVE                    = 0xb
	RTM_NEWADDR                    = 0xc
	RTM_DELADDR                    = 0xd
	RTM_IFINFO                     = 0xe
	RTM_NEWMADDR                   = 0xf
	RTM_DELMADDR                   = 0x10
	RTM_IFANNOUNCE                 = 0x11
	RTM_IEEE80211                  = 0x12
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

/*
struct bits rt_bits[] = {
	{ RTF_UP,	'U', "up" },
	{ RTF_GATEWAY,	'G', "gateway" },
	{ RTF_HOST,	'H', "host" },
	{ RTF_REJECT,	'R', "reject" },
	{ RTF_DYNAMIC,	'D', "dynamic" },
	{ RTF_MODIFIED,	'M', "modified" },
	{ RTF_DONE,	'd', "done" },
	{ RTF_XRESOLVE,	'X', "xresolve" },
	{ RTF_STATIC,	'S', "static" },
	{ RTF_PROTO1,	'1', "proto1" },
	{ RTF_PROTO2,	'2', "proto2" },
	{ RTF_PROTO3,	'3', "proto3" },
	{ RTF_BLACKHOLE,'B', "blackhole" },
	{ RTF_BROADCAST,'b', "broadcast" },
#ifdef RTF_LLINFO
	{ RTF_LLINFO,	'L', "llinfo" },
#endif
	{ 0 , 0, NULL }
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
	{unix.RTF_DONE, 'd'},
	{unix.RTF_XRESOLVE, 'X'},
	{unix.RTF_STATIC, 'S'},
	{unix.RTF_PROTO1, '1'},
	{unix.RTF_PROTO2, '2'},
	{unix.RTF_PROTO3, '3'},
	{unix.RTF_BLACKHOLE, 'B'},
	{unix.RTF_BROADCAST, 'b'},
	{unix.RTF_LLINFO, 'L'},
}

/*
	IFF_UP                         = 0x1
	IFF_BROADCAST                  = 0x2
	IFF_DEBUG                      = 0x4
	IFF_LOOPBACK                   = 0x8
	IFF_POINTOPOINT                = 0x10
	IFF_RUNNING                    = 0x40
	IFF_DRV_RUNNING                = 0x40
	IFF_NOARP                      = 0x80
	IFF_PROMISC                    = 0x100
	IFF_ALLMULTI                   = 0x200
	IFF_OACTIVE                    = 0x400
	IFF_DRV_OACTIVE                = 0x400
	IFF_SIMPLEX                    = 0x800
	IFF_LINK0                      = 0x1000
	IFF_LINK1                      = 0x2000
	IFF_LINK2                      = 0x4000
	IFF_ALTPHYS                    = 0x4000
	IFF_MULTICAST                  = 0x8000
	IFF_CANTCONFIG                 = 0x10000
	IFF_PPROMISC                   = 0x20000
	IFF_MONITOR                    = 0x40000
	IFF_STATICARP                  = 0x80000
	IFF_DYING                      = 0x200000
	IFF_CANTCHANGE                 = 0x218f52
	IFF_RENAMING                   = 0x400000
	IFF_NOGROUP                    = 0x800000
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
	{unix.IFF_CANTCONFIG, "CANTCONFIG"},
	{unix.IFF_PPROMISC, "PPROMISC"},
	{unix.IFF_MONITOR, "MONITOR"},
	{unix.IFF_STATICARP, "STATICARP"},
	{unix.IFF_DYING, "DYING"},
	{unix.IFF_RENAMING, "RENAMING"},
	{unix.IFF_NOGROUP, "NOGROUP"},
}
