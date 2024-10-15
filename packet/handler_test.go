package packet

import (
	"bytes"
	"crypto/rand"
	"errors"
	mrand "math/rand/v2"
	"testing"
)

var rng *mrand.ChaCha8

func init() {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic(err)
	}
	rng = mrand.NewChaCha8(seed)
}

func testHandler(
	t *testing.T,
	msgType byte,
	length int,
	h Handler,
	expectedEncryptErr, expectedDecryptErr error,
	verifyFunc func(t *testing.T, wgPacket, swgpPacket, decryptedWgPacket []byte),
) {
	t.Helper()

	wgPacket := make([]byte, length)
	if length > 0 {
		wgPacket[0] = msgType
		_, _ = rng.Read(wgPacket[1:])
	}

	swgpPacket, err := h.Encrypt(nil, wgPacket)
	if !errors.Is(err, expectedEncryptErr) {
		t.Fatalf("h.Encrypt got %v, want %v", err, expectedEncryptErr)
	}
	if err != nil {
		return
	}

	decryptedWgPacket, err := h.Decrypt(nil, swgpPacket)
	if !errors.Is(err, expectedDecryptErr) {
		t.Fatalf("h.Decrypt got %v, want %v", err, expectedDecryptErr)
	}
	if err != nil {
		return
	}

	if !bytes.Equal(decryptedWgPacket, wgPacket) {
		t.Errorf("decryptedWgPacket = %v, want %v", decryptedWgPacket, wgPacket)
	}

	if verifyFunc != nil {
		verifyFunc(t, wgPacket, swgpPacket, decryptedWgPacket)
	}
}
