package packet

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func testNewParanoidHandler(t *testing.T) Handler {
	psk := make([]byte, 32)
	_, err := rand.Read(psk)
	if err != nil {
		t.Fatal(err)
	}

	h, err := NewParanoidHandler(psk)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func testParanoidVerifyPacket(t *testing.T, wgPacket, swgpPacket, decryptedWgPacket []byte) {
	if len(swgpPacket) < chacha20poly1305.NonceSizeX+2+len(wgPacket)+chacha20poly1305.Overhead {
		t.Error("Bad swgpPacket length.")
	}

	if !bytes.Equal(wgPacket, decryptedWgPacket) {
		t.Error("Decrypted packet is different from original packet.")
	}
}

func TestParanoidHandlePacket(t *testing.T) {
	h := testNewParanoidHandler(t)

	for i := 1; i < 128; i++ {
		testHandler(t, WireGuardMessageTypeHandshakeInitiation, i, 0, 0, h, nil, nil, testParanoidVerifyPacket)
		testHandler(t, WireGuardMessageTypeHandshakeResponse, i, 0, 0, h, nil, nil, testParanoidVerifyPacket)
		testHandler(t, WireGuardMessageTypeHandshakeCookieReply, i, 0, 0, h, nil, nil, testParanoidVerifyPacket)
		testHandler(t, WireGuardMessageTypeData, i, 0, 0, h, nil, nil, testParanoidVerifyPacket)
	}
}
