// Package denylist is the broker's in-memory revocation list (ADR-0006 §3): revoked grants and
// per-subject "issued before" cut-offs, read by the access-token validator on every request.
//
// It is rebuilt from the store's full list of retained revocations on each sync, not from a
// cursor, so a revocation committed late on another replica is still seen. Revocations made on
// this replica take effect at once. When the last good sync is more than MaxStaleness old, every
// token is refused (fail closed), and so it is before the first sync.
package denylist

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/byward-dev/byward/internal/store"
)

// MaxStaleness is how old the list may be before it refuses every token (ADR-0006 §3).
const MaxStaleness = 30 * time.Second

// syncInterval is how often Run refreshes the list; several misses fit in MaxStaleness.
const syncInterval = 5 * time.Second

// errStale is returned by Denied while the list is older than MaxStaleness.
var errStale = errors.New("denylist: revocation list is stale")

// List is safe for concurrent use.
type List struct {
	src store.Revocations
	now func() time.Time

	mu      sync.RWMutex
	grants  map[string]bool
	cutoffs map[string]time.Time // subject → latest Before
	all     time.Time            // latest cut-off for every subject (revoke-all); zero if none
	local   map[string]time.Time // this replica's revoked grants → when, until the store has them
	synced  time.Time            // zero until the first good sync
}

// New returns an empty, stale list over src; now defaults to time.Now.
func New(src store.Revocations, now func() time.Time) *List {
	if now == nil {
		now = time.Now
	}
	return &List{src: src, now: now, grants: map[string]bool{}, cutoffs: map[string]time.Time{}, local: map[string]time.Time{}}
}

// Denied implements token.DenyList: the grant is revoked, or the subject, or every subject, was cut
// off after the token was issued. A stale list returns errStale, which rejects the token.
func (l *List) Denied(grantID, subject string, issuedAt time.Time) (bool, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.synced.IsZero() || l.now().Sub(l.synced) > MaxStaleness {
		return false, errStale
	}
	if l.grants[grantID] {
		return true, nil
	}
	if _, ok := l.local[grantID]; ok {
		return true, nil
	}
	// "Issued at or before the cut-off" (token.DenyList). Tokens carry whole seconds, so one issued
	// just after the cut-off in the same second is denied too (fail safe).
	if c, ok := l.cutoffs[subject]; ok && !issuedAt.After(c) {
		return true, nil
	}
	if !l.all.IsZero() && !issuedAt.After(l.all) {
		return true, nil
	}
	return false, nil
}

// Add denies a grant at once on this replica; the next syncs keep it while the store does.
func (l *List) Add(grantID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.local[grantID] = l.now()
}

// Sync rebuilds the list from the store. On error the list keeps its contents and ages.
func (l *List) Sync(ctx context.Context) error {
	started := l.now() // freshness counts from before the read
	revs, err := l.src.Revocations(ctx)
	if err != nil {
		return err
	}
	grants, cutoffs := map[string]bool{}, map[string]time.Time{}
	var all time.Time
	for _, r := range revs {
		// Only an explicit All revokes every subject; a revocation naming nothing revokes nothing.
		if r.All && r.Before.After(all) {
			all = r.Before
		}
		if r.GrantID != "" {
			grants[r.GrantID] = true
		}
		if r.Subject != "" && r.Before.After(cutoffs[r.Subject]) {
			cutoffs[r.Subject] = r.Before
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, at := range l.local {
		// Once retention has passed, every access token of that grant has expired anyway.
		if grants[id] || started.Sub(at) > store.RevocationRetention {
			delete(l.local, id)
		}
	}
	l.grants, l.cutoffs, l.all, l.synced = grants, cutoffs, all, started
	return nil
}

// Run syncs every syncInterval until ctx ends. Failures are logged; after MaxStaleness without a
// good sync, Denied refuses every token.
func (l *List) Run(ctx context.Context, log *slog.Logger) {
	t := time.NewTicker(syncInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := l.Sync(ctx); err != nil && ctx.Err() == nil {
				log.WarnContext(ctx, "revocation list sync failed", "error", err)
			}
		}
	}
}
