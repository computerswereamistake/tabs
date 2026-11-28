package auth

import (
	"slices"
	"strings"
	"sync"
	"time"
)

// Banner bans client IPs that fail too often: After failures within Window
// bans the IP for Duration. Unlike Limiter's backoff this refuses outright,
// and it is keyed by IP only, so it can't be used to lock a real user out
// of their account from elsewhere. State is in memory; a restart clears it.
type Banner struct {
	After    int
	Window   time.Duration
	Duration time.Duration
	Now      func() time.Time

	maxEntries int // 0 uses maxEntries; overridden in tests

	mu       sync.Mutex
	failures map[string][]time.Time
	bans     map[string]time.Time // ip -> banned until
}

func (b *Banner) limit() int {
	if b.maxEntries > 0 {
		return b.maxEntries
	}
	return maxEntries
}

// NewBanner returns a Banner. after <= 0 disables banning.
func NewBanner(after int, window, duration time.Duration) *Banner {
	return &Banner{After: after, Window: window, Duration: duration, Now: time.Now}
}

// Ban is one active ban, for the admin page.
type Ban struct {
	IP    string
	Until time.Time
}

// Banned reports whether ip is banned now, and until when.
func (b *Banner) Banned(ip string) (bool, time.Time) {
	if b.After <= 0 || ip == "" {
		return false, time.Time{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.bans[ip]
	if !ok {
		return false, time.Time{}
	}
	if !b.Now().Before(until) {
		delete(b.bans, ip)
		return false, time.Time{}
	}
	return true, until
}

// Fail records a failure from ip and reports whether it is now banned.
func (b *Banner) Fail(ip string) bool {
	if b.After <= 0 || ip == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.Now()
	if b.failures == nil {
		b.failures = make(map[string][]time.Time)
		b.bans = make(map[string]time.Time)
	}
	limit := b.limit()
	if len(b.failures) >= limit {
		b.pruneLocked(now)
	}
	fs := b.failures[ip]
	cut := 0
	for cut < len(fs) && now.Sub(fs[cut]) > b.Window {
		cut++
	}
	fs = append(fs[cut:], now)
	if len(fs) >= b.After {
		if _, exists := b.bans[ip]; !exists && len(b.bans) >= limit {
			b.evictBansLocked(now, limit)
		}
		b.bans[ip] = now.Add(b.Duration)
		delete(b.failures, ip)
		return true
	}
	b.failures[ip] = fs
	return false
}

// Unban lifts a ban and forgets ip's failures.
func (b *Banner) Unban(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.bans, ip)
	delete(b.failures, ip)
}

// Bans lists active bans, soonest to expire first.
func (b *Banner) Bans() []Ban {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.Now()
	var out []Ban
	for ip, until := range b.bans {
		if now.Before(until) {
			out = append(out, Ban{IP: ip, Until: until})
		}
	}
	slices.SortFunc(out, compareBan)
	return out
}

func compareBan(x, y Ban) int {
	if c := x.Until.Compare(y.Until); c != 0 {
		return c
	}
	return strings.Compare(x.IP, y.IP)
}

// Prune drops expired bans and stale failures.
func (b *Banner) Prune() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(b.Now())
}

func (b *Banner) pruneLocked(now time.Time) {
	for ip, until := range b.bans {
		if !now.Before(until) {
			delete(b.bans, ip)
		}
	}
	for ip, fs := range b.failures {
		if len(fs) == 0 || now.Sub(fs[len(fs)-1]) > b.Window {
			delete(b.failures, ip)
		}
	}
	if len(b.failures) >= b.limit() {
		clear(b.failures)
	}
}

func (b *Banner) evictBansLocked(now time.Time, limit int) {
	for ip, until := range b.bans {
		if !now.Before(until) {
			delete(b.bans, ip)
		}
	}
	if len(b.bans) < limit {
		return
	}
	// Still full of active bans: drop a soonest-to-expire batch so newer
	// bans stick and sustained sprays don't rescan the map on every insert.
	all := make([]Ban, 0, len(b.bans))
	for ip, until := range b.bans {
		all = append(all, Ban{IP: ip, Until: until})
	}
	slices.SortFunc(all, compareBan)
	drop := min(max(len(b.bans)-limit+1, limit/8), len(all))
	for _, ban := range all[:drop] {
		delete(b.bans, ban.IP)
	}
}
