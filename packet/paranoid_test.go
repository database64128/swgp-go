package packet

import (
	"crypto/rand"
	"strconv"
	"testing"
)

func newParanoidHandler(t *testing.T) Handler {
	t.Helper()

	psk := make([]byte, 32)
	rand.Read(psk)

	h, err := NewParanoidHandler(psk, 1452)
	if err != nil {
		t.Fatalf("NewParanoidHandler failed: %v", err)
	}
	return h
}

func TestParanoidHandler(t *testing.T) {
	h := newParanoidHandler(t)

	for _, msg := range msgTypeCases {
		t.Run(msg.name, func(t *testing.T) {
			for _, length := range msgLengthCases {
				t.Run(strconv.Itoa(length), func(t *testing.T) {
					testHandler(t, msg.msgType, length, h, nil)
				})
			}
		})
	}
}

func newParanoid2026Handler(t *testing.T) Handler {
	t.Helper()

	psk := make([]byte, 32)
	rand.Read(psk)

	h, err := NewParanoid2026Handler(psk, 1452)
	if err != nil {
		t.Fatalf("NewParanoid2026Handler failed: %v", err)
	}
	return h
}

func TestParanoid2026Handler(t *testing.T) {
	h := newParanoid2026Handler(t)

	for _, msg := range msgTypeCases {
		t.Run(msg.name, func(t *testing.T) {
			for _, length := range msgLengthCases {
				t.Run(strconv.Itoa(length), func(t *testing.T) {
					testHandler(t, msg.msgType, length, h, nil)
				})
			}
		})
	}
}

func TestParanoid2026HandlerReplayRepeatedNonce(t *testing.T) {
	h := newParanoid2026Handler(t)

	for _, msg := range replayRepeatedNonceCases {
		t.Run(msg.name, func(t *testing.T) {
			testHandlerReplayRepeatedNonce(t, msg.msgType, msg.length, h)
		})
	}
}
