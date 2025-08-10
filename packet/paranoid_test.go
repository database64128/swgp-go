package packet

import (
	"crypto/rand"
	"strconv"
	"testing"

	"github.com/database64128/swgp-go/internal/wireguard"
)

func newParanoidHandler(t *testing.T) Handler {
	t.Helper()

	psk := make([]byte, 32)
	rand.Read(psk)

	h, err := NewParanoidHandler(psk, 1452)
	if err != nil {
		t.Fatalf("NewParanoidHandler failed: %v", err)
	}
	return h
}

func TestParanoidHandler(t *testing.T) {
	h := newParanoidHandler(t)

	for _, msg := range []struct {
		name    string
		msgType byte
	}{
		{"HandshakeInitiation", wireguard.MessageTypeHandshakeInitiation},
		{"HandshakeResponse", wireguard.MessageTypeHandshakeResponse},
		{"HandshakeCookieReply", wireguard.MessageTypeHandshakeCookieReply},
		{"Data", wireguard.MessageTypeData},
	} {
		t.Run(msg.name, func(t *testing.T) {
			for _, length := range []int{0, 1, 16, 128, 1280} {
				t.Run(strconv.Itoa(length), func(t *testing.T) {
					testHandler(t, msg.msgType, length, h, nil)
				})
			}
		})
	}
}
