package packet

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testNewZeroOverheadHandler(t *testing.T) Handler {
	psk := make([]byte, 32)
	_, err := rand.Read(psk)
	if err != nil {
		t.Fatal(err)
	}

	h, err := NewZeroOverheadHandler(psk)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func testZeroOverheadVerifyPacket(t *testing.T, wgPacket, swgpPacket, decryptedWgPacket []byte) {
	if bytes.Equal(wgPacket[:16], swgpPacket[:16]) {
		t.Error("The first 16 bytes are not encrypted.")
	}

	if !bytes.Equal(wgPacket[16:], swgpPacket[16:len(wgPacket)]) {
		t.Error("The unencrypted part changed.")
	}

	if !bytes.Equal(wgPacket, decryptedWgPacket) {
		t.Error("Decrypted packet is different from original packet.")
	}
}

func TestZeroOverheadHandleWireGuardHandshakeInitiationPacket(t *testing.T) {
	h := testNewZeroOverheadHandler(t)
	testHandler(t, WireGuardMessageTypeHandshakeInitiation, WireGuardMessageLengthHandshakeInitiation, h, testZeroOverheadVerifyPacket)
}

func TestZeroOverheadHandleWireGuardHandshakeResponsePacket(t *testing.T) {
	h := testNewZeroOverheadHandler(t)
	testHandler(t, WireGuardMessageTypeHandshakeResponse, WireGuardMessageLengthHandshakeResponse, h, testZeroOverheadVerifyPacket)
}

func TestZeroOverheadHandleWireGuardHandshakeCookieReplyPacket(t *testing.T) {
	h := testNewZeroOverheadHandler(t)
	testHandler(t, WireGuardMessageTypeHandshakeCookieReply, WireGuardMessageLengthHandshakeCookieReply, h, testZeroOverheadVerifyPacket)
}

func TestZeroOverheadHandleWireGuardDataPacket(t *testing.T) {
	h := testNewZeroOverheadHandler(t)
	testHandler(t, WireGuardMessageTypeData, 1452, h, testZeroOverheadVerifyPacket)
}
