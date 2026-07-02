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
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ConnMeta is the per-connection metadata a node supplies when tracking a conn,
// for the observability snapshot (B.2). Destination is proxy metadata (host:port),
// never content; Source is the client address when the handler knows it.
type ConnMeta struct {
	Destination string
	Source      string
}

// ConnInfo is a read-only snapshot of one live connection, for realm-agent's obs
// risk-control (conn_lifecycle / egress_behavior). No payload, only metadata.
type ConnInfo struct {
	UUID        string
	Source      string
	Destination string
	Upload      int64
	Download    int64
	Start       time.Time
}

// UserStat is a user's accumulated traffic since the last reset.
type UserStat struct {
	UUID     string
	Upload   int64 // client -> target bytes
	Download int64 // target -> client bytes
}

// liveConn is a tracked connection (stream or packet) that can be force-closed
// on kick and can report a read-only snapshot. Both trackedConn and
// trackedPacketConn satisfy it.
type liveConn interface {
	Close() error
	info(uuid string) ConnInfo
}

type userState struct {
	up   atomic.Int64
	down atomic.Int64
	// conns is the set of live connections for this user, for KickUser.
	mu    sync.Mutex
	conns map[liveConn]struct{}
}

func (s *userState) add(c liveConn) {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
}

func (s *userState) remove(c liveConn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
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
		s = &userState{conns: map[liveConn]struct{}{}}
		r.users[uuid] = s
	}
	return s
}

// Track wraps a STREAM conn so its byte counts accrue to uuid and it is
// force-closable via KickUser(uuid). meta carries destination/source for the obs
// snapshot (B.2). Call once per accepted egress stream; use the returned conn for
// the bidirectional copy. It unregisters on Close.
func (r *Registry) Track(uuid string, conn net.Conn, meta ConnMeta) net.Conn {
	s := r.state(uuid)
	tc := &trackedConn{Conn: conn, state: s, meta: meta, start: time.Now()}
	s.add(tc)
	return tc
}

// TrackPacket wraps a PACKET conn so its byte counts accrue to uuid (ReadPacket =
// upload from client, WritePacket = download to client) and it is force-closable
// via KickUser(uuid). Symmetric to Track for the UDP path (hy2/tuic). Unregisters
// on Close.
func (r *Registry) TrackPacket(uuid string, conn N.PacketConn, meta ConnMeta) N.PacketConn {
	s := r.state(uuid)
	tp := &trackedPacketConn{PacketConn: conn, state: s, meta: meta, start: time.Now()}
	s.add(tp)
	return tp
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
	conns := make([]liveConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close() // Close unregisters from the set + closes
	}
	return len(conns)
}

// Snapshot returns a read-only view of every live connection across all users,
// for realm-agent's obs risk-control (B.2: conn_lifecycle / egress_behavior). No
// payload, only metadata + per-conn byte counters. Cheap, read-only.
func (r *Registry) Snapshot() []ConnInfo {
	r.mu.Lock()
	states := make(map[string]*userState, len(r.users))
	for uuid, s := range r.users {
		states[uuid] = s
	}
	r.mu.Unlock()
	var out []ConnInfo
	for uuid, s := range states {
		s.mu.Lock()
		for c := range s.conns {
			out = append(out, c.info(uuid))
		}
		s.mu.Unlock()
	}
	return out
}

// EvictUser kicks a user's live connections AND drops its state from the
// registry (so CollectStats no longer returns a ghost row). Used on user removal
// (R1 delete linkage): the removed user must both lose its live tunnels (R3) and
// disappear from billing. Returns the number of connections closed. Any bytes on
// those connections that had not yet been collected are dropped with the state —
// callers that need a final bill should CollectStats(true) before evicting.
func (r *Registry) EvictUser(uuid string) int {
	kicked := r.KickUser(uuid)
	r.mu.Lock()
	delete(r.users, uuid)
	r.mu.Unlock()
	return kicked
}

// trackedConn is a net.Conn whose Read/Write increment its user's counters (and
// its own per-conn counters, for the obs snapshot) and which unregisters itself
// from the user's live-connection set on Close.
type trackedConn struct {
	net.Conn
	state     *userState
	meta      ConnMeta
	start     time.Time
	up        atomic.Int64
	down      atomic.Int64
	closeOnce sync.Once
}

// Read counts UPLOAD: on the CLIENT-side conn, Read pulls bytes the client sent
// toward the target. Write counts DOWNLOAD (target -> client). See node wiring.
func (t *trackedConn) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	if n > 0 {
		t.state.up.Add(int64(n))
		t.up.Add(int64(n))
	}
	return n, err
}

func (t *trackedConn) Write(b []byte) (int, error) {
	n, err := t.Conn.Write(b)
	if n > 0 {
		t.state.down.Add(int64(n))
		t.down.Add(int64(n))
	}
	return n, err
}

func (t *trackedConn) Close() error {
	t.closeOnce.Do(func() { t.state.remove(t) })
	return t.Conn.Close()
}

func (t *trackedConn) info(uuid string) ConnInfo {
	return ConnInfo{
		UUID: uuid, Source: t.meta.Source, Destination: t.meta.Destination,
		Upload: t.up.Load(), Download: t.down.Load(), Start: t.start,
	}
}

// trackedPacketConn is the UDP counterpart of trackedConn: ReadPacket counts
// upload (client -> target), WritePacket counts download (target -> client). It
// wraps the CLIENT-side N.PacketConn in the node's UDP egress copy, so byte
// direction matches trackedConn. Unregisters from the user's live set on Close.
type trackedPacketConn struct {
	N.PacketConn
	state     *userState
	meta      ConnMeta
	start     time.Time
	up        atomic.Int64
	down      atomic.Int64
	closeOnce sync.Once
}

func (t *trackedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	before := buffer.Len()
	dest, err := t.PacketConn.ReadPacket(buffer)
	if n := buffer.Len() - before; n > 0 {
		t.state.up.Add(int64(n))
		t.up.Add(int64(n))
	}
	return dest, err
}

func (t *trackedPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	n := buffer.Len()
	err := t.PacketConn.WritePacket(buffer, destination)
	if err == nil && n > 0 {
		t.state.down.Add(int64(n))
		t.down.Add(int64(n))
	}
	return err
}

func (t *trackedPacketConn) Close() error {
	t.closeOnce.Do(func() { t.state.remove(t) })
	return t.PacketConn.Close()
}

func (t *trackedPacketConn) info(uuid string) ConnInfo {
	return ConnInfo{
		UUID: uuid, Source: t.meta.Source, Destination: t.meta.Destination,
		Upload: t.up.Load(), Download: t.down.Load(), Start: t.start,
	}
}
