package packet

import (
	"bytes"
	"crypto/rand"
	"strconv"
	"testing"
)

func newZeroOverheadHandler(t *testing.T) Handler {
	t.Helper()

	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}

	h, err := NewZeroOverheadHandler(psk, 1452)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func verifyZeroOverheadHandlerPacket(t *testing.T, wgPacket, swgpPacket, decryptedWgPacket []byte) {
	if len(wgPacket) < 16 {
		if !bytes.Equal(wgPacket, swgpPacket) {
			t.Error("The packet should be untouched.")
		}
		return
	}

	if bytes.Equal(wgPacket[:16], swgpPacket[:16]) {
		t.Error("The first 16 bytes are not encrypted.")
	}

	switch wgPacket[0] {
	case WireGuardMessageTypeHandshakeInitiation, WireGuardMessageTypeHandshakeResponse, WireGuardMessageTypeHandshakeCookieReply:
		if bytes.Equal(wgPacket[16:], swgpPacket[16:]) {
			t.Error("The rest of the packet is not encrypted.")
		}
	default:
		if !bytes.Equal(wgPacket[16:], swgpPacket[16:]) {
			t.Error("The unencrypted part changed.")
		}
	}
}

func TestZeroOverheadHandler(t *testing.T) {
	h := newZeroOverheadHandler(t)

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
					testHandler(t, msg.msgType, length, h, nil, nil, verifyZeroOverheadHandlerPacket)
				})
			}
		})
	}
}
