package discovery

import (
	"sort"
	"sync"
	"time"
)

// Peer states, from strongest to weakest.
const (
	StateVerified   = "verified"   // mutual TLS handshake completed
	StateSeen       = "seen"       // valid signed beacon, handshake not done yet
	StateUnverified = "unverified" // beacon or handshake failed: do not trust
	StateOffline    = "offline"    // no beacon for a while
)

// OfflineAfter is how long without a beacon before a peer counts as offline.
const OfflineAfter = 4 * Interval

// Peer is one device as this node currently sees it.
type Peer struct {
	Name        string
	Department  string
	Fingerprint string
	Addr        string // QUIC address from its beacon
	FromIP      string
	State       string
	Problem     string
	FirstSeen   time.Time
	LastSeen    time.Time
	VerifiedAt  time.Time
	Code        string // 6-digit verification code of the current session
}

// Table tracks peers. Trusted peers are keyed by certificate fingerprint;
// rejected claims by source address and claimed name.
type Table struct {
	mu    sync.Mutex
	peers map[string]*Peer
}

// NewTable makes an empty table.
func NewTable() *Table { return &Table{peers: map[string]*Peer{}} }

// Observe records a beacon verdict and reports whether this peer is new
// (or newly rejected), so the caller can announce it once.
func (t *Table) Observe(v Verdict, now time.Time) (p Peer, isNew bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !v.OK {
		key := "bad|" + v.FromIP + "|" + v.Name + "|" + v.Reason
		e, ok := t.peers[key]
		if !ok {
			e = &Peer{Name: v.Name, FromIP: v.FromIP, State: StateUnverified, Problem: v.Reason, FirstSeen: now}
			t.peers[key] = e
		}
		e.LastSeen = now
		return *e, !ok
	}
	e, ok := t.peers[v.Fingerprint]
	if !ok {
		e = &Peer{Fingerprint: v.Fingerprint, FirstSeen: now, State: StateSeen}
		t.peers[v.Fingerprint] = e
	}
	e.Name, e.Department, e.Addr, e.FromIP, e.LastSeen = v.Name, v.Department, v.QUICAddr, v.FromIP, now
	if e.State == StateOffline {
		e.State, isNew = StateSeen, true
		if !e.VerifiedAt.IsZero() {
			e.State = StateVerified
		}
	}
	return *e, !ok || isNew
}

// MarkVerified records a completed mutual TLS handshake with a device.
func (t *Table) MarkVerified(fp, name, dept, fallbackAddr, code string, now time.Time) (wasVerified bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.peers[fp]
	if !ok {
		e = &Peer{Fingerprint: fp, FirstSeen: now, Addr: fallbackAddr}
		t.peers[fp] = e
	}
	wasVerified = e.State == StateVerified
	e.Name, e.Department, e.State, e.Problem, e.VerifiedAt, e.Code = name, dept, StateVerified, "", now, code
	if e.LastSeen.IsZero() {
		e.LastSeen = now
	}
	return wasVerified
}

// MarkFailed records a failed handshake with a beaconing device.
func (t *Table) MarkFailed(fp, problem string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.peers[fp]; ok {
		e.State, e.Problem = StateUnverified, problem
	}
}

// Lookup returns the trusted entry for a device name, preferring the one
// verified most recently.
func (t *Table) Lookup(name string) (Peer, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var best *Peer
	for _, e := range t.peers {
		if e.Name != name || e.Fingerprint == "" || e.State == StateUnverified || e.Addr == "" {
			continue
		}
		if best == nil || e.LastSeen.After(best.LastSeen) {
			best = e
		}
	}
	if best == nil {
		return Peer{}, false
	}
	return *best, true
}

// Sweep marks silent peers offline and forgets old entries. It returns the
// peers that just went offline.
func (t *Table) Sweep(now time.Time) []Peer {
	t.mu.Lock()
	defer t.mu.Unlock()
	var gone []Peer
	for k, e := range t.peers {
		silent := now.Sub(e.LastSeen)
		switch {
		case silent > 10*OfflineAfter:
			delete(t.peers, k)
		case e.State == StateUnverified && silent > 5*OfflineAfter:
			delete(t.peers, k)
		case e.State != StateUnverified && e.State != StateOffline && silent > OfflineAfter:
			e.State = StateOffline
			gone = append(gone, *e)
		}
	}
	return gone
}

// Snapshot lists peers: verified first, then seen, unverified, offline.
func (t *Table) Snapshot() []Peer {
	t.mu.Lock()
	defer t.mu.Unlock()
	rank := map[string]int{StateVerified: 0, StateSeen: 1, StateUnverified: 2, StateOffline: 3}
	out := make([]Peer, 0, len(t.peers))
	for _, e := range t.peers {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].State] != rank[out[j].State] {
			return rank[out[i].State] < rank[out[j].State]
		}
		return out[i].Name < out[j].Name
	})
	return out
}
