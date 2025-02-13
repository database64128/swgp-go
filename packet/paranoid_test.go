package packet

import (
	"crypto/rand"
	"strconv"
	"testing"
)

func newParanoidHandler(t *testing.T) Handler {
	t.Helper()

	psk := make([]byte, 32)
	rand.Read(psk)

	h, err := NewParanoidHandler(psk, 1452)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestParanoidHandler(t *testing.T) {
	h := newParanoidHandler(t)

	for _, msg := range []struct {
		name    string
		msgType byte
	}{
		{"HandshakeInitiation", WireGuardMessageTypeHandshakeInitiation},
		{"HandshakeResponse", WireGuardMessageTypeHandshakeResponse},
		{"HandshakeCookieReply", WireGuardMessageTypeHandshakeCookieReply},
		{"Data", WireGuardMessageTypeData},
	} {
		t.Run(msg.name, func(t *testing.T) {
			for _, length := range []int{0, 1, 16, 128, 1280} {
				t.Run(strconv.Itoa(length), func(t *testing.T) {
					testHandler(t, msg.msgType, length, h, nil, nil, nil)
				})
			}
		})
	}
}
