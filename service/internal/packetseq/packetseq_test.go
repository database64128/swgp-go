package packetseq

import (
	"crypto/rand"
	"slices"
	"testing"
)

func TestSenderReceiver(t *testing.T) {
	var (
		s Sender
		r Receiver
		b = make([]byte, 1024)
	)

	rand.Read(b)

	// Stamp ID 0.
	s.Stamp(b)

	b0 := slices.Clone(b)

	// Validate ID 0.
	if err := r.Validate(b); err != nil {
		t.Errorf("r.Validate(0) = %v, want nil", err)
	}

	// Bump ID to 959.
	s.pid += windowSize - 2

	// Stamp ID 959.
	s.Stamp(b)

	// Validate ID 959.
	if err := r.Validate(b); err != nil {
		t.Errorf("r.Validate(959) = %v, want nil", err)
	}

	// Validate ID 0 again.
	if err := r.Validate(b0); err != ErrPacketDuplicate {
		t.Errorf("r.Validate(0) = %v, want ErrPacketDuplicate", err)
	}

	// Stamp ID 960.
	s.Stamp(b)

	// Validate ID 960.
	if err := r.Validate(b); err != nil {
		t.Errorf("r.Validate(960) = %v, want nil", err)
	}

	// Validate ID 0 again.
	if err := r.Validate(b0); err != ErrPacketBehindWindow {
		t.Errorf("r.Validate(0) = %v, want ErrPacketBehindWindow", err)
	}

	// Validate bad checksum.
	b0[0] = 0xFF
	if err := r.Validate(b0); err != ErrPacketChecksumMismatch {
		t.Errorf("r.Validate(b0) = %v, want ErrPacketChecksumMismatch", err)
	}

	// Check sender count.
	if got, want := s.Count(), uint64(windowSize+1); got != want {
		t.Errorf("s.Count() = %v, want %v", got, want)
	}

	// Check receiver state.
	if got := r.LastID(); got != windowSize {
		t.Errorf("r.LastID() = %v, want %v", got, windowSize)
	}
	if got := r.Count(); got != 3 {
		t.Errorf("r.Count() = %v, want 3", got)
	}
}

func TestSenderStampPacketTooSmall(t *testing.T) {
	defer func() { _ = recover() }()
	var s Sender
	b := make([]byte, minPacketSize-1)
	s.Stamp(b)
	t.Errorf("s.Stamp(b) did not panic")
}

func TestReceiverValidatePacketTooSmall(t *testing.T) {
	var r Receiver
	b := make([]byte, minPacketSize-1)
	if err := r.Validate(b); err != ErrPacketTooSmall {
		t.Errorf("r.Validate(b) = %v, want ErrPacketTooSmall", err)
	}
}
