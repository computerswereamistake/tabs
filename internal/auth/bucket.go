package auth

import (
	"sync"
	"time"
)

// Bucket is a per-key token bucket: Burst tokens to start, refilling one
// every Every. It limits a rate, so normal use never runs it dry, unlike a
// failure counter that only resets after a quiet spell. State is in memory.
type Bucket struct {
	Burst int
	Every time.Duration
	Now   func() time.Time

	mu      sync.Mutex
	entries map[string]*bucketEntry
}

type bucketEntry struct {
	tokens float64
	last   time.Time
}

// Take spends a token for key, or reports how long until one is available.
func (b *Bucket) Take(key string) (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.Now()
	if b.entries == nil {
		b.entries = make(map[string]*bucketEntry)
	}
	e := b.entries[key]
	if e == nil {
		if len(b.entries) >= maxEntries {
			b.pruneLocked(now)
		}
		e = &bucketEntry{tokens: float64(b.Burst), last: now}
		b.entries[key] = e
	}
	// A clock stepping backwards adds nothing rather than draining tokens.
	if elapsed := now.Sub(e.last); elapsed > 0 {
		e.tokens = min(float64(b.Burst), e.tokens+float64(elapsed)/float64(b.Every))
		e.last = now
	}
	if e.tokens < 1 {
		return false, time.Duration((1 - e.tokens) * float64(b.Every))
	}
	e.tokens--
	return true, 0
}

// Spent reports whether key has used any tokens that haven't refilled.
func (b *Bucket) Spent(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[key]
	if e == nil {
		return false
	}
	return e.tokens+max(0, float64(b.Now().Sub(e.last)))/float64(b.Every) < float64(b.Burst)
}

// Prune drops keys whose bucket has refilled.
func (b *Bucket) Prune() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(b.Now())
}

func (b *Bucket) pruneLocked(now time.Time) {
	full := time.Duration(b.Burst) * b.Every
	for k, e := range b.entries {
		if now.Sub(e.last) >= full {
			delete(b.entries, k)
		}
	}
	// Still full (an active spray): drop the keys with the most tokens
	// left, which lose least by being forgotten, before resetting anyone
	// who is actually being limited.
	if len(b.entries) >= maxEntries {
		half := float64(b.Burst) / 2
		for k, e := range b.entries {
			if e.tokens >= half {
				delete(b.entries, k)
			}
		}
	}
	if len(b.entries) >= maxEntries {
		clear(b.entries)
	}
}
