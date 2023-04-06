package packet

import (
	"crypto/rand"
	"errors"
	"testing"
)

func testHandler(
	t *testing.T,
	msgType byte,
	length, extraFrontHeadroom, extraRearHeadroom int,
	h Handler,
	expectedEncryptErr, expectedDecryptErr error,
	verifyFunc func(t *testing.T, wgPacket, swgpPacket, decryptedWgPacket []byte),
) {
	headroom := h.Headroom()
	headroom.Front += extraFrontHeadroom
	headroom.Rear += extraRearHeadroom

	// Prepare buffer.
	buf := make([]byte, headroom.Front+length+headroom.Rear)
	_, err := rand.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	buf[headroom.Front] = msgType

	var wgPacket, swgpPacket, decryptedWgPacket []byte

	// Save original packet.
	wgPacket = append(wgPacket, buf[headroom.Front:headroom.Front+length]...)

	// Encrypt.
	swgpPacketStart, swgpPacketLength, err := h.EncryptZeroCopy(buf, headroom.Front, length)
	if !errors.Is(err, expectedEncryptErr) {
		t.Fatalf("Expected encryption error: %s\nGot: %s", expectedEncryptErr, err)
	}
	if err != nil {
		return
	}

	// Save encrypted packet.
	swgpPacket = append(swgpPacket, buf[swgpPacketStart:swgpPacketStart+swgpPacketLength]...)

	// Decrypt.
	wgPacketStart, wgPacketLength, err := h.DecryptZeroCopy(buf, swgpPacketStart, swgpPacketLength)
	if !errors.Is(err, expectedDecryptErr) {
		t.Fatalf("Expected decryption error: %s\nGot: %s", expectedDecryptErr, err)
	}
	if err != nil {
		return
	}
	decryptedWgPacket = buf[wgPacketStart : wgPacketStart+wgPacketLength]

	verifyFunc(t, wgPacket, swgpPacket, decryptedWgPacket)
}
