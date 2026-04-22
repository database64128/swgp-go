package replay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	// MaxEpochDiff is the maximum allowed difference in unix epoch between the sender and receiver.
	MaxEpochDiff = 15

	// MaxTimeDiff is the maximum allowed difference in time between the sender and receiver.
	MaxTimeDiff = MaxEpochDiff * time.Second

	// ReplayWindowDuration is the duration for which nonces are stored in the nonce pool to protect against replay attacks.
	ReplayWindowDuration = MaxTimeDiff * 2
)

var (
	ErrRepeatedNonce = errors.New("detected replay: repeated nonce")
)

type BadTimestampError struct {
	ReceivedEpoch int64
	NowEpoch      int64
}

func (e BadTimestampError) Error() string {
	return fmt.Sprintf("time diff too large: received epoch %d, now epoch %d", e.ReceivedEpoch, e.NowEpoch)
}

// ValidateUnixEpochTimestamp parses the first 8 bytes of b as a little-endian unix epoch timestamp
// and checks if it is within the allowed time difference from the current system time.
func ValidateUnixEpochTimestamp(b []byte, now time.Time) error {
	tsEpoch := int64(binary.LittleEndian.Uint64(b))
	nowEpoch := now.Unix()
	diff := tsEpoch - nowEpoch
	if diff < -MaxEpochDiff || diff > MaxEpochDiff {
		return BadTimestampError{ReceivedEpoch: tsEpoch, NowEpoch: nowEpoch}
	}
	return nil
}
