//go:build openbsd

package bsdroute

const sizeofMsghdr = 6 // int(unsafe.Sizeof(msghdr{}))

type msghdr struct {
	Msglen  uint16
	Version uint8
	Type    uint8
	Hdrlen  uint16
}

func (m *msghdr) HeaderLen() uint16 {
	return m.Hdrlen
}

func (m *msghdr) AddrsBuf(msgBuf []byte, _ int) ([]byte, bool) {
	if int(m.Hdrlen) > len(msgBuf) {
		return nil, false
	}
	return msgBuf[m.Hdrlen:], true
}
