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
	RTM_OLDADD                        = 0x9
	RTM_OLDDEL                        = 0xa
	RTM_RESOLVE                       = 0xb
	RTM_NEWADDR                       = 0xc
	RTM_DELADDR                       = 0xd
	RTM_OOIFINFO                      = 0xe
	RTM_OIFINFO                       = 0xf
	RTM_IFANNOUNCE                    = 0x10
	RTM_IEEE80211                     = 0x11
	RTM_SETGATE                       = 0x12
	RTM_LLINFO_UPD                    = 0x13
	RTM_IFINFO                        = 0x14
	RTM_CHGADDR                       = 0x15
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
	case unix.RTM_OOIFINFO:
		return "RTM_OOIFINFO"
	case unix.RTM_OIFINFO:
		return "RTM_OIFINFO"
	case unix.RTM_IFANNOUNCE:
		return "RTM_IFANNOUNCE"
	case unix.RTM_IEEE80211:
		return "RTM_IEEE80211"
	case unix.RTM_SETGATE:
		return "RTM_SETGATE"
	case unix.RTM_LLINFO_UPD:
		return "RTM_LLINFO_UPD"
	case unix.RTM_IFINFO:
		return "RTM_IFINFO"
	case unix.RTM_CHGADDR:
		return "RTM_CHGADDR"
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
	{ RTF_BLACKHOLE, 'B' },
	{ RTF_DYNAMIC,	'D' },
	{ RTF_MODIFIED,	'M' },
	{ RTF_DONE,	'd' },
	{ RTF_MASK,	'm' },
	{ RTF_CONNECTED, 'C' },
	{ RTF_LLDATA,	'L' },
	{ RTF_STATIC,	'S' },
	{ RTF_PROTO1,	'1' },
	{ RTF_PROTO2,	'2' },
	{ RTF_ANNOUNCE,	'p' },
	{ RTF_LOCAL, 'l'},
	{ RTF_BROADCAST, 'b'},
	{ 0, 0 }
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
	{unix.RTF_BLACKHOLE, 'B'},
	{unix.RTF_DYNAMIC, 'D'},
	{unix.RTF_MODIFIED, 'M'},
	{unix.RTF_DONE, 'd'},
	{unix.RTF_MASK, 'm'},
	// {unix.RTF_CONNECTED, 'C'},
	// {unix.RTF_LLDATA, 'L'},
	{unix.RTF_STATIC, 'S'},
	{unix.RTF_PROTO1, '1'},
	{unix.RTF_PROTO2, '2'},
	{unix.RTF_ANNOUNCE, 'p'},
	// {unix.RTF_LOCAL, 'l'},
	// {unix.RTF_BROADCAST, 'b'},
}

/*
	IFF_UP                            = 0x1
	IFF_BROADCAST                     = 0x2
	IFF_DEBUG                         = 0x4
	IFF_LOOPBACK                      = 0x8
	IFF_POINTOPOINT                   = 0x10
	IFF_NOTRAILERS                    = 0x20
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
	IFF_CANTCHANGE                    = 0x8f52
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
