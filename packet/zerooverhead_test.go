package packet

import (
	"bytes"
	"crypto/rand"
	"strconv"
	"testing"

	"github.com/database64128/swgp-go/internal/wireguard"
)

func newZeroOverheadHandler(t *testing.T) Handler {
	t.Helper()

	psk := make([]byte, 32)
	rand.Read(psk)

	h, err := NewZeroOverheadHandler(psk, 1452)
	if err != nil {
		t.Fatalf("NewZeroOverheadHandler failed: %v", err)
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
	case wireguard.MessageTypeHandshakeInitiation, wireguard.MessageTypeHandshakeResponse, wireguard.MessageTypeHandshakeCookieReply:
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

	for _, msg := range msgTypeCases {
		t.Run(msg.name, func(t *testing.T) {
			for _, length := range msgLengthCases {
				t.Run(strconv.Itoa(length), func(t *testing.T) {
					testHandler(t, msg.msgType, length, h, verifyZeroOverheadHandlerPacket)
				})
			}
		})
	}
}

func newZeroOverhead2026Handler(t *testing.T) Handler {
	t.Helper()

	psk := make([]byte, 32)
	rand.Read(psk)

	h, err := NewZeroOverhead2026Handler(psk, 1452)
	if err != nil {
		t.Fatalf("NewZeroOverhead2026Handler failed: %v", err)
	}
	return h
}

func TestZeroOverhead2026Handler(t *testing.T) {
	h := newZeroOverhead2026Handler(t)

	for _, msg := range msgTypeCases {
		t.Run(msg.name, func(t *testing.T) {
			for _, length := range msgLengthCases {
				t.Run(strconv.Itoa(length), func(t *testing.T) {
					testHandler(t, msg.msgType, length, h, verifyZeroOverheadHandlerPacket)
				})
			}
		})
	}
}

func TestZeroOverhead2026HandlerReplayRepeatedNonce(t *testing.T) {
	h := newZeroOverhead2026Handler(t)

	for _, msg := range replayRepeatedNonceCases {
		t.Run(msg.name, func(t *testing.T) {
			testHandlerReplayRepeatedNonce(t, msg.msgType, msg.length, h)
		})
	}
}
