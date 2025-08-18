//go:build darwin || dragonfly || freebsd || netbsd

package bsdroute

const sizeofMsghdr = 4 // int(unsafe.Sizeof(msghdr{}))

type msghdr struct {
	Msglen  uint16
	Version uint8
	Type    uint8
}

func (*msghdr) HeaderLen() uint16 {
	panic("unreachable")
}

func (*msghdr) AddrsBuf(msgBuf []byte, hdrlen int) ([]byte, bool) {
	return msgBuf[hdrlen:], true
}
