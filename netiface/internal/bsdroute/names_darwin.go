package bsdroute

import (
	"strconv"

	"golang.org/x/sys/unix"
)

/*
	RTM_ADD                                 = 0x1
	RTM_DELETE                              = 0x2
	RTM_CHANGE                              = 0x3
	RTM_GET                                 = 0x4
	RTM_LOSING                              = 0x5
	RTM_REDIRECT                            = 0x6
	RTM_MISS                                = 0x7
	RTM_LOCK                                = 0x8
	RTM_OLDADD                              = 0x9
	RTM_OLDDEL                              = 0xa
	RTM_RESOLVE                             = 0xb
	RTM_NEWADDR                             = 0xc
	RTM_DELADDR                             = 0xd
	RTM_IFINFO                              = 0xe
	RTM_NEWMADDR                            = 0xf
	RTM_DELMADDR                            = 0x10
	RTM_IFINFO2                             = 0x12
	RTM_NEWMADDR2                           = 0x13
	RTM_GET2                                = 0x14
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
	case unix.RTM_OLDADD:
		return "RTM_OLDADD"
	case unix.RTM_OLDDEL:
		return "RTM_OLDDEL"
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
	case unix.RTM_IFINFO2:
		return "RTM_IFINFO2"
	case unix.RTM_NEWMADDR2:
		return "RTM_NEWMADDR2"
	case unix.RTM_GET2:
		return "RTM_GET2"
	default:
		return strconv.Itoa(int(m))
	}
}

/*
struct bits {
	uint32_t	b_mask;
	char	b_val;
} bits[] = {
	{ RTF_UP,	'U' },
	{ RTF_GATEWAY,	'G' },
	{ RTF_HOST,	'H' },
	{ RTF_REJECT,	'R' },
	{ RTF_DYNAMIC,	'D' },
	{ RTF_MODIFIED,	'M' },
	{ RTF_MULTICAST,'m' },
	{ RTF_DONE,	'd' },
	{ RTF_CLONING,	'C' },
	{ RTF_XRESOLVE,	'X' },
	{ RTF_LLINFO,	'L' },
	{ RTF_STATIC,	'S' },
	{ RTF_PROTO1,	'1' },
	{ RTF_PROTO2,	'2' },
	{ RTF_WASCLONED,'W' },
	{ RTF_PRCLONING,'c' },
	{ RTF_PROTO3,	'3' },
	{ RTF_BLACKHOLE,'B' },
	{ RTF_BROADCAST,'b' },
	{ RTF_IFSCOPE,	'I' },
	{ RTF_IFREF,	'i' },
	{ RTF_PROXY,	'Y' },
	{ RTF_ROUTER,	'r' },
#ifdef RTF_GLOBAL
	{ RTF_GLOBAL,	'g' },
#endif
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
	{unix.RTF_MULTICAST, 'm'},
	{unix.RTF_DONE, 'd'},
	{unix.RTF_CLONING, 'C'},
	{unix.RTF_XRESOLVE, 'X'},
	{unix.RTF_LLINFO, 'L'},
	{unix.RTF_STATIC, 'S'},
	{unix.RTF_PROTO1, '1'},
	{unix.RTF_PROTO2, '2'},
	{unix.RTF_WASCLONED, 'W'},
	{unix.RTF_PRCLONING, 'c'},
	{unix.RTF_PROTO3, '3'},
	{unix.RTF_BLACKHOLE, 'B'},
	{unix.RTF_BROADCAST, 'b'},
	{unix.RTF_IFSCOPE, 'I'},
	{unix.RTF_IFREF, 'i'},
	{unix.RTF_PROXY, 'Y'},
	{unix.RTF_ROUTER, 'r'},
	{unix.RTF_GLOBAL, 'g'},
}

/*
	IFF_UP                                  = 0x1
	IFF_BROADCAST                           = 0x2
	IFF_DEBUG                               = 0x4
	IFF_LOOPBACK                            = 0x8
	IFF_POINTOPOINT                         = 0x10
	IFF_NOTRAILERS                          = 0x20
	IFF_RUNNING                             = 0x40
	IFF_NOARP                               = 0x80
	IFF_PROMISC                             = 0x100
	IFF_ALLMULTI                            = 0x200
	IFF_OACTIVE                             = 0x400
	IFF_SIMPLEX                             = 0x800
	IFF_LINK0                               = 0x1000
	IFF_LINK1                               = 0x2000
	IFF_LINK2                               = 0x4000
	IFF_ALTPHYS                             = 0x4000
	IFF_MULTICAST                           = 0x8000
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
	{unix.IFF_NOTRAILERS, "NOTRAILERS"},
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
}
