package packet

import (
	"bytes"
	"crypto/rand"
	"slices"
	"testing"

	"github.com/database64128/swgp-go/internal/replay"
	"github.com/database64128/swgp-go/internal/wireguard"
)

var msgTypeCases = [...]struct {
	name    string
	msgType byte
}{
	{"HandshakeInitiation", wireguard.MessageTypeHandshakeInitiation},
	{"HandshakeResponse", wireguard.MessageTypeHandshakeResponse},
	{"HandshakeCookieReply", wireguard.MessageTypeHandshakeCookieReply},
	{"Data", wireguard.MessageTypeData},
}

var msgLengthCases = [...]int{0, 1, 16, 128, 1280}

func testHandler(
	t *testing.T,
	msgType byte,
	length int,
	h Handler,
	verifyFunc func(t *testing.T, wgPacket, swgpPacket, decryptedWgPacket []byte),
) {
	t.Helper()

	wgPacket := make([]byte, length)
	if length > 0 {
		wgPacket[0] = msgType
		rand.Read(wgPacket[1:])
	}

	swgpPacket, err := h.Encrypt(nil, wgPacket)
	if err != nil {
		t.Fatalf("h.Encrypt failed: %v", err)
	}

	decryptedWgPacket, err := h.Decrypt(nil, swgpPacket)
	if err != nil {
		t.Fatalf("h.Decrypt failed: %v", err)
	}

	if !bytes.Equal(decryptedWgPacket, wgPacket) {
		t.Errorf("decryptedWgPacket = %v, want %v", decryptedWgPacket, wgPacket)
	}

	if verifyFunc != nil {
		verifyFunc(t, wgPacket, swgpPacket, decryptedWgPacket)
	}
}

var replayRepeatedNonceCases = [...]struct {
	name    string
	msgType byte
	length  int
}{
	{"HandshakeInitiation", wireguard.MessageTypeHandshakeInitiation, wireguard.MessageLengthHandshakeInitiation},
	{"HandshakeResponse", wireguard.MessageTypeHandshakeResponse, wireguard.MessageLengthHandshakeResponse},
	{"HandshakeCookieReply", wireguard.MessageTypeHandshakeCookieReply, wireguard.MessageLengthHandshakeCookieReply},
}

func testHandlerReplayRepeatedNonce(t *testing.T, msgType byte, length int, h Handler) {
	t.Helper()

	wgPacket := make([]byte, length)
	if length > 0 {
		wgPacket[0] = msgType
		rand.Read(wgPacket[1:])
	}

	swgpPacket, err := h.Encrypt(nil, wgPacket)
	if err != nil {
		t.Fatalf("h.Encrypt failed: %v", err)
	}
	swgpPacketCopy := slices.Clone(swgpPacket)

	if _, err = h.Decrypt(nil, swgpPacket); err != nil {
		t.Fatalf("h.Decrypt failed: %v", err)
	}

	if _, err = h.Decrypt(nil, swgpPacketCopy); err != replay.ErrRepeatedNonce {
		t.Errorf("h.Decrypt = %v, want %v", err, replay.ErrRepeatedNonce)
	}
}
