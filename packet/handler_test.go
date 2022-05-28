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
	var frontHeadroom, rearHeadroom int
	frontOverhead, rearOverhead := h.FrontOverhead(), h.RearOverhead()
	if frontOverhead > frontHeadroom {
		frontHeadroom = frontOverhead
	}
	frontHeadroom += extraFrontHeadroom
	if rearOverhead > rearHeadroom {
		rearHeadroom = rearOverhead
	}
	rearHeadroom += extraRearHeadroom

	// Prepare buffer.
	buf := make([]byte, frontHeadroom+length+rearHeadroom)
	_, err := rand.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	buf[frontHeadroom] = msgType

	var wgPacket, swgpPacket, decryptedWgPacket []byte

	// Save original packet.
	wgPacket = append(wgPacket, buf[frontHeadroom:frontHeadroom+length]...)

	// Encrypt.
	swgpPacketStart, swgpPacketLength, err := h.EncryptZeroCopy(buf, frontHeadroom, length)
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
