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
		t.Error("bad swgpPacket length")
	}

	if !bytes.Equal(wgPacket, decryptedWgPacket) {
		t.Error("Decrypted packet is different from original packet.")
	}
}

func TestParanoidHandleWireGuardHandshakeInitiationPacket(t *testing.T) {
	h := testNewParanoidHandler(t)
	testHandler(t, WireGuardMessageTypeHandshakeInitiation, WireGuardMessageLengthHandshakeInitiation, h, testParanoidVerifyPacket)
}

func TestParanoidHandleWireGuardHandshakeResponsePacket(t *testing.T) {
	h := testNewParanoidHandler(t)
	testHandler(t, WireGuardMessageTypeHandshakeResponse, WireGuardMessageLengthHandshakeResponse, h, testParanoidVerifyPacket)
}

func TestParanoidHandleWireGuardHandshakeCookieReplyPacket(t *testing.T) {
	h := testNewParanoidHandler(t)
	testHandler(t, WireGuardMessageTypeHandshakeCookieReply, WireGuardMessageLengthHandshakeCookieReply, h, testParanoidVerifyPacket)
}

func TestParanoidHandleWireGuardDataPacket(t *testing.T) {
	h := testNewParanoidHandler(t)
	testHandler(t, WireGuardMessageTypeData, 1452, h, testParanoidVerifyPacket)
}
