package replay_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/database64128/swgp-go/internal/replay"
)

func TestNoncePool(t *testing.T) {
	var pool replay.NoncePool
	now := time.Now()
	b := make([]byte, 64)
	rand.Read(b)
	nonce0 := replay.Nonce(b)
	nonce1 := replay.Nonce(b[32:])

	// Clear empty pool.
	pool.Clear()

	// Check nonce0 and nonce1.
	if pool.Contains(nonce0) {
		t.Fatal("pool.Contains(nonce0) = true, want false")
	}
	if pool.TryContains(nonce1) {
		t.Fatal("pool.TryContains(nonce1) = true, want false")
	}

	// Add nonce0.
	if !pool.Add(now, nonce0) {
		t.Fatal("pool.Add(now, nonce0) = false, want true")
	}
	if pool.Add(now, nonce0) {
		t.Fatal("pool.Add(now, nonce0) = true, want false")
	}

	// Advance some time.
	now = now.Add(replay.ReplayWindowDuration / 2)

	// Add nonce1.
	if !pool.Add(now, nonce1) {
		t.Fatal("pool.Add(now, nonce1) = false, want true")
	}
	if pool.Add(now, nonce1) {
		t.Fatal("pool.Add(now, nonce1) = true, want false")
	}

	// Check nonce0 and nonce1.
	if !pool.Contains(nonce0) {
		t.Fatal("pool.Contains(nonce0) = false, want true")
	}
	if !pool.Contains(nonce1) {
		t.Fatal("pool.Contains(nonce1) = false, want true")
	}

	// Advance some time to let nonce0 expire.
	now = now.Add(replay.ReplayWindowDuration / 2)

	// Add nonce0 and nonce1.
	if !pool.Add(now, nonce0) {
		t.Fatal("pool.Add(now, nonce0) = false, want true")
	}
	if pool.Add(now, nonce1) {
		t.Fatal("pool.Add(now, nonce1) = true, want false")
	}

	// Advance some time to let both expire.
	now = now.Add(replay.ReplayWindowDuration)

	// Add nonce0 and nonce1.
	if !pool.Add(now, nonce0) {
		t.Fatal("pool.Add(now, nonce0) = false, want true")
	}
	if !pool.Add(now, nonce1) {
		t.Fatal("pool.Add(now, nonce1) = false, want true")
	}

	// Clear the pool.
	pool.Clear()

	// Check nonce0 and nonce1 again.
	if pool.TryContains(nonce0) {
		t.Fatal("pool.TryContains(nonce0) = true, want false")
	}
	if pool.TryContains(nonce1) {
		t.Fatal("pool.TryContains(nonce1) = true, want false")
	}
}
