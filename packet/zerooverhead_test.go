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

func testZeroOverheadVerifyUnchangedPacket(t *testing.T, wgPacket, swgpPacket, decryptedWgPacket []byte) {
	if !bytes.Equal(wgPacket, swgpPacket) {
		t.Error("The packet should be untouched.")
	}

	if !bytes.Equal(wgPacket, decryptedWgPacket) {
		t.Error("Decrypted packet is different from original packet.")
	}
}

func testZeroOverheadVerifyHandshakePacket(t *testing.T, wgPacket, swgpPacket, decryptedWgPacket []byte) {
	if bytes.Equal(wgPacket, swgpPacket[:len(wgPacket)]) {
		t.Error("The packet is not encrypted.")
	}

	if len(swgpPacket) < len(wgPacket)+zeroOverheadHandshakePacketMinimumOverhead {
		t.Error("Bad swgpPacket length.")
	}

	if !bytes.Equal(wgPacket, decryptedWgPacket) {
		t.Error("Decrypted packet is different from original packet.")
	}
}

func testZeroOverheadVerifyDataPacket(t *testing.T, wgPacket, swgpPacket, decryptedWgPacket []byte) {
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

func TestZeroOverheadHandleLessThan16Bytes(t *testing.T) {
	h := testNewZeroOverheadHandler(t)

	for i := range 16 {
		testHandler(t, WireGuardMessageTypeHandshakeInitiation, i, 1, 1, h, nil, nil, testZeroOverheadVerifyUnchangedPacket)
		testHandler(t, WireGuardMessageTypeHandshakeResponse, i, 1, 1, h, nil, nil, testZeroOverheadVerifyUnchangedPacket)
		testHandler(t, WireGuardMessageTypeHandshakeCookieReply, i, 1, 1, h, nil, nil, testZeroOverheadVerifyUnchangedPacket)
		testHandler(t, WireGuardMessageTypeData, i, 1, 1, h, nil, nil, testZeroOverheadVerifyUnchangedPacket)
	}
}

func TestZeroOverheadHandleEncryptErrPacketSize(t *testing.T) {
	h := testNewZeroOverheadHandler(t)

	for i := range zeroOverheadHandshakePacketMinimumOverhead {
		testHandler(t, WireGuardMessageTypeHandshakeInitiation, WireGuardMessageLengthHandshakeInitiation, 1, i, h, ErrPacketSize, nil, testZeroOverheadVerifyUnchangedPacket)
		testHandler(t, WireGuardMessageTypeHandshakeResponse, WireGuardMessageLengthHandshakeResponse, 1, i, h, ErrPacketSize, nil, testZeroOverheadVerifyUnchangedPacket)
		testHandler(t, WireGuardMessageTypeHandshakeCookieReply, WireGuardMessageLengthHandshakeCookieReply, 1, i, h, ErrPacketSize, nil, testZeroOverheadVerifyUnchangedPacket)
	}
}

func TestZeroOverheadHandleHandshakePacket(t *testing.T) {
	h := testNewZeroOverheadHandler(t)

	for i := 16; i < 128; i++ {
		testHandler(t, WireGuardMessageTypeHandshakeInitiation, i, 1, zeroOverheadHandshakePacketMinimumOverhead, h, nil, nil, testZeroOverheadVerifyHandshakePacket)
		testHandler(t, WireGuardMessageTypeHandshakeResponse, i, 1, zeroOverheadHandshakePacketMinimumOverhead, h, nil, nil, testZeroOverheadVerifyHandshakePacket)
		testHandler(t, WireGuardMessageTypeHandshakeCookieReply, i, 1, zeroOverheadHandshakePacketMinimumOverhead, h, nil, nil, testZeroOverheadVerifyHandshakePacket)
	}
}

func TestZeroOverheadHandleDataPacket(t *testing.T) {
	h := testNewZeroOverheadHandler(t)

	for i := 16; i < 128; i++ {
		testHandler(t, WireGuardMessageTypeData, i, 1, 1, h, nil, nil, testZeroOverheadVerifyDataPacket)
	}
}
