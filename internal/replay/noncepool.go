package replay

import (
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type Nonce = [chacha20poly1305.NonceSizeX]byte

// NoncePool stores nonces for [ReplayWindowDuration] to protect against replay attacks
// during the replay window.
//
// The zero value is ready for use.
type NoncePool struct {
	mu          sync.RWMutex
	nodeByNonce map[Nonce]*nonceNode

	// head is the oldest node.
	head *nonceNode
	// tail is the newest node.
	tail *nonceNode
}

type nonceNode struct {
	next      *nonceNode
	nonce     Nonce
	expiresAt time.Time
}

// Contains returns whether the pool contains the given nonce.
func (p *NoncePool) Contains(nonce Nonce) bool {
	p.mu.RLock()
	_, ok := p.nodeByNonce[nonce]
	p.mu.RUnlock()
	return ok
}

// TryContains is like Contains, but it immediately returns false if the pool is contended.
func (p *NoncePool) TryContains(nonce Nonce) bool {
	if p.mu.TryRLock() {
		_, ok := p.nodeByNonce[nonce]
		p.mu.RUnlock()
		return ok
	}
	return false
}

// Add adds the nonce to the pool if it is not already in the pool.
// It returns true if the nonce was added, false if it already exists.
func (p *NoncePool) Add(now time.Time, nonce Nonce) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.pruneExpired(now)
	if _, ok := p.nodeByNonce[nonce]; ok {
		return false
	}
	p.insert(now, nonce)
	return true
}

// Clear removes all nonces from the pool.
func (p *NoncePool) Clear() {
	p.mu.Lock()
	clear(p.nodeByNonce)
	p.head = nil
	p.tail = nil
	p.mu.Unlock()
}

// pruneExpired removes all expired nonces from the pool.
func (p *NoncePool) pruneExpired(now time.Time) {
	node := p.head
	if node == nil || node.expiresAt.After(now) {
		return
	}
	for {
		delete(p.nodeByNonce, node.nonce)
		node = node.next
		if node == nil {
			p.head = nil
			p.tail = nil
			return
		}
		if node.expiresAt.After(now) {
			p.head = node
			return
		}
	}
}

// insert adds the new nonce to the pool.
func (p *NoncePool) insert(now time.Time, nonce Nonce) {
	if p.nodeByNonce == nil {
		p.nodeByNonce = make(map[Nonce]*nonceNode)
	}
	node := &nonceNode{
		nonce:     nonce,
		expiresAt: now.Add(ReplayWindowDuration),
	}
	p.nodeByNonce[nonce] = node
	if p.tail != nil {
		p.tail.next = node
	} else {
		p.head = node
	}
	p.tail = node
}
