package packet

import (
	"bytes"
	"crypto/rand"
	"testing"
)

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
