// Package meter is the shared per-user traffic accounting + connection registry
// behind R2 (billing) and R3 (kick). One Registry lives per node; every egress
// connection is registered under its user's UUID (resolved via node/userattr +
// the node's usermap), counted on both directions, and unregistered on close.
//
// R2 (billing): CollectStats(reset) returns per-user up/down byte totals. With
// reset=true it reads AND atomically zeroes — that is the BILLING path (each byte
// billed exactly once). With reset=false it is a non-destructive snapshot — the
// OBSERVABILITY path. The two MUST NOT share one reset=true call, or billing
// undercounts (the realm-agent collector's hard rule).
//
// R3 (kick): KickUser(uuid) force-closes every live connection of a user (quota
// expiry / removal). Registration is keyed by UUID so a kick is O(live conns of
// that user).
package meter

import (
	"net"
	"sync"
	"sync/atomic"
)

// UserStat is a user's accumulated traffic since the last reset.
type UserStat struct {
	UUID     string
	Upload   int64 // client -> target bytes
	Download int64 // target -> client bytes
}

type userState struct {
	up   atomic.Int64
	down atomic.Int64
	// conns is the set of live connections for this user, for KickUser.
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
}

// Registry is a node's per-user meter + connection registry. Safe for concurrent
// use.
type Registry struct {
	mu    sync.Mutex
	users map[string]*userState
}

// New builds an empty registry.
func New() *Registry {
	return &Registry{users: map[string]*userState{}}
}

func (r *Registry) state(uuid string) *userState {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.users[uuid]
	if s == nil {
		s = &userState{conns: map[*trackedConn]struct{}{}}
		r.users[uuid] = s
	}
	return s
}

// Track wraps conn so its byte counts accrue to uuid and it is force-closable via
// KickUser(uuid). Call once per accepted egress connection; the returned conn is
// used in place of the original for the bidirectional copy. unregister the conn
// (via the returned conn's Close, which is automatic) when the copy ends.
func (r *Registry) Track(uuid string, conn net.Conn) net.Conn {
	s := r.state(uuid)
	tc := &trackedConn{Conn: conn, state: s}
	s.mu.Lock()
	s.conns[tc] = struct{}{}
	s.mu.Unlock()
	return tc
}

// CollectStats returns every user's up/down totals. reset=true atomically zeroes
// the counters after reading (BILLING path — bill once). reset=false is a
// non-destructive snapshot (OBSERVABILITY path). Never use one reset=true call
// for both.
func (r *Registry) CollectStats(reset bool) []UserStat {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]UserStat, 0, len(r.users))
	for uuid, s := range r.users {
		var up, down int64
		if reset {
			up = s.up.Swap(0)
			down = s.down.Swap(0)
		} else {
			up = s.up.Load()
			down = s.down.Load()
		}
		out = append(out, UserStat{UUID: uuid, Upload: up, Download: down})
	}
	return out
}

// KickUser force-closes all live connections of a user and returns how many were
// closed. Used on quota expiry / user removal (R1 delete linkage / R3).
func (r *Registry) KickUser(uuid string) int {
	r.mu.Lock()
	s := r.users[uuid]
	r.mu.Unlock()
	if s == nil {
		return 0
	}
	s.mu.Lock()
	conns := make([]*trackedConn, 0, len(s.conns))
	for tc := range s.conns {
		conns = append(conns, tc)
	}
	s.mu.Unlock()
	for _, tc := range conns {
		_ = tc.Close() // trackedConn.Close unregisters from the set + closes
	}
	return len(conns)
}

// trackedConn is a net.Conn whose Read/Write increment its user's counters and
// which unregisters itself from the user's live-connection set on Close.
type trackedConn struct {
	net.Conn
	state     *userState
	closeOnce sync.Once
}

// Read counts DOWNLOAD: bytes flowing target -> client are read from the egress
// (outbound) side and written back to the client. In the node egress copy, the
// tracked conn is the CLIENT-side conn, so Write to it == download to client and
// Read from it == upload from client. See node wiring.
func (t *trackedConn) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	if n > 0 {
		t.state.up.Add(int64(n))
	}
	return n, err
}

func (t *trackedConn) Write(b []byte) (int, error) {
	n, err := t.Conn.Write(b)
	if n > 0 {
		t.state.down.Add(int64(n))
	}
	return n, err
}

func (t *trackedConn) Close() error {
	t.closeOnce.Do(func() {
		t.state.mu.Lock()
		delete(t.state.conns, t)
		t.state.mu.Unlock()
	})
	return t.Conn.Close()
}
