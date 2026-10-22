package auth

import (
	"sync"
	"time"
)

// Limiter throttles failed login attempts per key (a username or a client
// IP). After Free failures, each further attempt must wait a delay that
// doubles per failure up to Max. It never hard-locks, so an attacker can
// slow but not lock out a real user. State is in memory only.
type Limiter struct {
	Free int           // failures allowed before any delay
	Base time.Duration // first delay
	Max  time.Duration // delay cap
	Now  func() time.Time

	mu      sync.Mutex
	entries map[string]*limitEntry
}

type limitEntry struct {
	failures int
	until    time.Time // no attempt allowed before this
	last     time.Time
}

// NewLimiter returns a Limiter with defaults suitable for logins.
func NewLimiter() *Limiter {
	return &Limiter{Free: 5, Base: 2 * time.Second, Max: 15 * time.Minute, Now: time.Now}
}

// maxEntries bounds memory if someone sprays random usernames.
const maxEntries = 100_000

// Allow reports whether an attempt for key may proceed now, and if not, how
// long until it may.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		return true, 0
	}
	if wait := e.until.Sub(l.Now()); wait > 0 {
		return false, wait
	}
	return true, 0
}

// Fail records a failed attempt for key.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now()
	if l.entries == nil {
		l.entries = make(map[string]*limitEntry)
	}
	e := l.entries[key]
	if e == nil {
		if len(l.entries) >= maxEntries {
			l.pruneLocked(now)
		}
		e = &limitEntry{}
		l.entries[key] = e
	}
	e.failures++
	e.last = now
	if e.failures > l.Free {
		d := l.Base
		for i := l.Free + 1; i < e.failures && d < l.Max; i++ {
			d *= 2
		}
		e.until = now.Add(min(d, l.Max))
	}
}

// Succeed clears key's failures.
func (l *Limiter) Succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// Prune drops entries idle for longer than Max.
func (l *Limiter) Prune() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(l.Now())
}

func (l *Limiter) pruneLocked(now time.Time) {
	for k, e := range l.entries {
		if now.Sub(e.last) > l.Max && now.After(e.until) {
			delete(l.entries, k)
		}
	}
	// Still full (an active spray): drop keys that aren't being delayed yet
	// before anything that is, so a spray can't easily wash out real limits.
	if len(l.entries) >= maxEntries {
		for k, e := range l.entries {
			if e.failures <= l.Free {
				delete(l.entries, k)
			}
		}
	}
	if len(l.entries) >= maxEntries {
		clear(l.entries)
	}
}
