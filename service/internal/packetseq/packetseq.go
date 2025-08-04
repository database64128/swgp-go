// Package packetseq provides packet sequencing and validation utilities.
//
// Each packet is stamped with a uint64 sequence ID in native byte order,
// and a CRC-32-IEEE checksum of the preceding bytes in native byte order.
// The receiver validates packets and tracks duplicates using a sliding window.
package packetseq

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math/bits"
)

const minPacketSize = 8 + 4

// Sender stamps packets for sending and keeps track of the number of packets stamped.
type Sender struct {
	pid uint64
}

// Count returns the number of packets stamped.
func (s *Sender) Count() uint64 {
	return s.pid
}

// Stamp stamps the packet for sending.
func (s *Sender) Stamp(b []byte) {
	if len(b) < minPacketSize {
		panic("packetbench: packet too small")
	}
	binary.NativeEndian.PutUint64(b[len(b)-minPacketSize:], s.pid)
	s.pid++
	crc := crc32.ChecksumIEEE(b[:len(b)-4])
	binary.NativeEndian.PutUint32(b[len(b)-4:], crc)
}

const (
	blockBits  = bits.UintSize
	ringBlocks = 1 << 4
	windowSize = (ringBlocks - 1) * blockBits
)

// Receiver validates stamped packets and counts the number of unique packets received.
type Receiver struct {
	last  uint64
	count uint64
	ring  [ringBlocks]uint64
}

// LastID returns the last packet ID received.
func (r *Receiver) LastID() uint64 {
	return r.last
}

// Count returns the number of unique packets received.
func (r *Receiver) Count() uint64 {
	return r.count
}

var (
	ErrPacketTooSmall         = errors.New("packet too small")
	ErrPacketChecksumMismatch = errors.New("packet checksum mismatch")
	ErrPacketBehindWindow     = errors.New("packet ID behind sliding window")
	ErrPacketDuplicate        = errors.New("packet ID already received")
)

// Validate validates the packet and updates the receiver state.
func (r *Receiver) Validate(b []byte) error {
	if len(b) < minPacketSize {
		return ErrPacketTooSmall
	}

	crc := crc32.ChecksumIEEE(b[:len(b)-4])
	if crc != binary.NativeEndian.Uint32(b[len(b)-4:]) {
		return ErrPacketChecksumMismatch
	}

	id := binary.NativeEndian.Uint64(b[len(b)-minPacketSize:])
	unmaskedBlockIndex := id / blockBits
	blockIndex := unmaskedBlockIndex % ringBlocks
	bitIndex := id % blockBits

	switch {
	case id > r.last: // Ahead of window, clear blocks ahead.
		lastBlockIndex := r.last / blockBits
		clearBlockCount := min(int(unmaskedBlockIndex-lastBlockIndex), ringBlocks)
		for range clearBlockCount {
			lastBlockIndex = (lastBlockIndex + 1) % ringBlocks
			r.ring[lastBlockIndex] = 0
		}
		r.last = id

	case r.last-id >= windowSize: // Behind window.
		return ErrPacketBehindWindow

	case r.ring[blockIndex]&(1<<bitIndex) != 0: // Duplicate.
		return ErrPacketDuplicate
	}

	r.count++
	r.ring[blockIndex] |= 1 << bitIndex
	return nil
}
