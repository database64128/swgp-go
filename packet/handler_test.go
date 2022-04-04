package packet

import "testing"

func testHandler(t *testing.T, msgType byte, length int, h Handler, verifyFunc func(t *testing.T, wgPacket, swgpPacket, decryptedWgPacket []byte)) {
	// Reserve a minimum of 24 bytes to ensure code can handle extra headroom.
	frontHeadroom, rearHeadroom := 24, 24
	frontOverhead, rearOverhead := h.FrontOverhead(), h.RearOverhead()
	if frontOverhead > frontHeadroom {
		frontHeadroom = frontOverhead
	}
	if rearOverhead > rearHeadroom {
		rearHeadroom = rearOverhead
	}

	buf := make([]byte, frontHeadroom+length+rearHeadroom)
	buf[frontHeadroom] = msgType

	var wgPacket, swgpPacket, decryptedWgPacket []byte

	// Save original packet.
	wgPacket = append(wgPacket, buf[frontHeadroom:frontHeadroom+length]...)

	// Encrypt.
	pkt, err := h.EncryptZeroCopy(buf, frontHeadroom, length, length+rearHeadroom-rearOverhead)
	if err != nil {
		t.Fatal(err)
	}

	// Save encrypted packet.
	swgpPacket = append(swgpPacket, pkt...)

	// Decrypt.
	decryptedWgPacket, err = h.DecryptZeroCopy(pkt)
	if err != nil {
		t.Fatal(err)
	}

	verifyFunc(t, wgPacket, swgpPacket, decryptedWgPacket)
}
