package meter

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// TestMeterCountAndReset verifies per-user up/down counting and the reset-vs-
// snapshot semantics (R2 billing correctness).
func TestMeterCountAndReset(t *testing.T) {
	r := New()
	c1, c2 := net.Pipe()
	defer c2.Close()
	tracked := r.Track("userA", c1, ConnMeta{})

	// Write 5 bytes (download to client) and read 3 bytes (upload from client).
	go func() { c2.Read(make([]byte, 5)) }()
	if _, err := tracked.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	go func() { c2.Write([]byte("abc")) }()
	buf := make([]byte, 3)
	if _, err := tracked.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	// Snapshot (reset=false) must not zero.
	snap := statFor(r.CollectStats(false), "userA")
	if snap.Download != 5 || snap.Upload != 3 {
		t.Fatalf("snapshot got up=%d down=%d, want up=3 down=5", snap.Upload, snap.Download)
	}
	// Second snapshot still shows the same (non-destructive).
	if s := statFor(r.CollectStats(false), "userA"); s.Download != 5 || s.Upload != 3 {
		t.Fatalf("snapshot changed the counters")
	}
	// Billing read (reset=true) returns the total then zeroes.
	billed := statFor(r.CollectStats(true), "userA")
	if billed.Download != 5 || billed.Upload != 3 {
		t.Fatalf("billing got up=%d down=%d, want up=3 down=5", billed.Upload, billed.Download)
	}
	if after := statFor(r.CollectStats(true), "userA"); after.Download != 0 || after.Upload != 0 {
		t.Fatalf("counters not zeroed after billing read: up=%d down=%d", after.Upload, after.Download)
	}
}

// TestKickUser verifies KickUser closes a user's live conns and not others'.
func TestKickUser(t *testing.T) {
	r := New()
	a1, _ := net.Pipe()
	b1, _ := net.Pipe()
	ta := r.Track("A", a1, ConnMeta{})
	tb := r.Track("B", b1, ConnMeta{})

	if n := r.KickUser("A"); n != 1 {
		t.Fatalf("KickUser(A)=%d, want 1", n)
	}
	// A's conn is closed; a write should error.
	if _, err := ta.Write([]byte("x")); err == nil {
		t.Fatal("expected A's tracked conn to be closed after kick")
	}
	// B untouched.
	if n := r.KickUser("A"); n != 0 {
		t.Fatalf("second KickUser(A)=%d, want 0 (already gone)", n)
	}
	_ = tb
	if n := r.KickUser("B"); n != 1 {
		t.Fatalf("KickUser(B)=%d, want 1", n)
	}
}

func statFor(stats []UserStat, uuid string) UserStat {
	for _, s := range stats {
		if s.UUID == uuid {
			return s
		}
	}
	return UserStat{}
}

// TestEvictUser verifies R1-delete linkage (review A.1/A.3): evicting a user
// force-closes its live conns AND removes it from CollectStats (no ghost row).
func TestEvictUser(t *testing.T) {
	r := New()
	a1, _ := net.Pipe()
	b1, _ := net.Pipe()
	ta := r.Track("A", a1, ConnMeta{})
	_ = r.Track("B", b1, ConnMeta{})

	// A is present in stats before evict.
	if statFor(r.CollectStats(false), "A").UUID != "A" {
		t.Fatal("A missing from stats before evict")
	}
	if n := r.EvictUser("A"); n != 1 {
		t.Fatalf("EvictUser(A)=%d, want 1", n)
	}
	// A's conn is closed.
	if _, err := ta.Write([]byte("x")); err == nil {
		t.Fatal("A's conn not closed after evict")
	}
	// A no longer appears in stats (ghost row gone).
	for _, s := range r.CollectStats(false) {
		if s.UUID == "A" {
			t.Fatal("A still present in stats after evict (ghost row)")
		}
	}
	// B untouched.
	if statFor(r.CollectStats(false), "B").UUID != "B" {
		t.Fatal("B wrongly affected by evicting A")
	}
}

// TestTrackPacketCount verifies UDP per-user metering (review A.2): ReadPacket
// counts upload, WritePacket counts download.
func TestTrackPacketCount(t *testing.T) {
	r := New()
	fake := &fakePacketConn{readSize: 7}
	tp := r.TrackPacket("U", fake, ConnMeta{})

	// ReadPacket appends 7 bytes -> upload += 7.
	rb := buf.NewSize(64)
	if _, err := tp.ReadPacket(rb); err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	rb.Release()
	// WritePacket of 4 bytes -> download += 4.
	wb := buf.NewSize(64)
	wb.Write([]byte("abcd"))
	if err := tp.WritePacket(wb, M.Socksaddr{}); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	s := statFor(r.CollectStats(false), "U")
	if s.Upload != 7 || s.Download != 4 {
		t.Fatalf("UDP metering got up=%d down=%d, want up=7 down=4", s.Upload, s.Download)
	}
	// Kickable like a stream conn.
	if n := r.KickUser("U"); n != 1 {
		t.Fatalf("KickUser(U)=%d, want 1", n)
	}
}

// fakePacketConn is a minimal N.PacketConn: ReadPacket appends readSize bytes,
// WritePacket discards. Enough to drive the counting wrapper.
type fakePacketConn struct {
	readSize int
	closed   bool
}

func (f *fakePacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	b.Write(make([]byte, f.readSize))
	return M.Socksaddr{}, nil
}
func (f *fakePacketConn) WritePacket(b *buf.Buffer, _ M.Socksaddr) error { b.Release(); return nil }
func (f *fakePacketConn) Close() error                                   { f.closed = true; return nil }
func (f *fakePacketConn) LocalAddr() net.Addr                            { return &net.UDPAddr{} }
func (f *fakePacketConn) SetDeadline(t time.Time) error                  { return nil }
func (f *fakePacketConn) SetReadDeadline(t time.Time) error              { return nil }
func (f *fakePacketConn) SetWriteDeadline(t time.Time) error             { return nil }

// TestSharedRegistryAcrossProtocols is the C.1 core: ONE Registry fed from
// several "protocol sources" (as six egress nodes would share it) exposes a
// unified billing/kick/snapshot surface for a UUID that spans all protocols.
//   - CollectStats sums a UUID's bytes across protocols in one atomic read.
//   - KickUser drops that UUID's conns on ALL protocols in one call.
//   - Snapshot lists every protocol's conns, each tagged with ConnInfo.Protocol.
func TestSharedRegistryAcrossProtocols(t *testing.T) {
	reg := New() // the SHARED registry the six nodes would be given

	// Same user "U" is active on three protocols at once; a different user "V"
	// is active on one. Each Track is a distinct protocol source into one reg.
	uHy, uHyPeer := net.Pipe()
	uTuic, uTuicPeer := net.Pipe()
	uReality, uRealityPeer := net.Pipe()
	vTrojan, vTrojanPeer := net.Pipe()
	defer func() { uHyPeer.Close(); uTuicPeer.Close(); uRealityPeer.Close(); vTrojanPeer.Close() }()

	tU1 := reg.Track("U", uHy, ConnMeta{Destination: "a:1", Protocol: "hysteria2"})
	tU2 := reg.Track("U", uTuic, ConnMeta{Destination: "b:2", Protocol: "tuic"})
	tU3 := reg.Track("U", uReality, ConnMeta{Destination: "c:3", Protocol: "reality"})
	_ = reg.Track("V", vTrojan, ConnMeta{Destination: "d:4", Protocol: "trojan"})

	// Push some bytes so the merged bill is nonzero. Write on U's three conns
	// (download += n each); their sum must land under the single UUID "U".
	drain := func(peer net.Conn, n int) { go func() { peer.Read(make([]byte, n)) }() }
	drain(uHyPeer, 4)
	tU1.Write([]byte("aaaa")) // +4 download
	drain(uTuicPeer, 5)
	tU2.Write([]byte("bbbbb")) // +5 download
	drain(uRealityPeer, 6)
	tU3.Write([]byte("cccccc")) // +6 download

	// 1. Billing合账: one CollectStats returns U's bytes SUMMED across the three
	// protocols (4+5+6 = 15 download), atomically.
	if s := statFor(reg.CollectStats(false), "U"); s.Download != 15 {
		t.Fatalf("merged billing: U download=%d, want 15 (4+5+6 across 3 protocols)", s.Download)
	}

	// 3. Snapshot一次列全协议, each conn tagged with its protocol.
	byProto := map[string]int{}
	for _, ci := range reg.Snapshot() {
		byProto[ci.Protocol]++
		if ci.Protocol == "" {
			t.Fatalf("snapshot conn missing Protocol tag: %+v", ci)
		}
	}
	if byProto["hysteria2"] != 1 || byProto["tuic"] != 1 || byProto["reality"] != 1 || byProto["trojan"] != 1 {
		t.Fatalf("snapshot protocol tally wrong: %v", byProto)
	}

	// 2. 一次踢全协议: KickUser("U") closes all THREE of U's conns in one call;
	// V's trojan conn is untouched.
	if n := reg.KickUser("U"); n != 3 {
		t.Fatalf("KickUser(U)=%d, want 3 (one per protocol)", n)
	}
	for name, c := range map[string]net.Conn{"hysteria2": tU1, "tuic": tU2, "reality": tU3} {
		if _, err := c.Write([]byte("x")); err == nil {
			t.Fatalf("U's %s conn not closed after single KickUser", name)
		}
	}
	// V still present and live.
	if statFor(reg.CollectStats(false), "V").UUID != "V" {
		t.Fatal("V wrongly dropped when kicking U")
	}
	if left := len(reg.Snapshot()); left != 1 {
		t.Fatalf("after kicking U, snapshot len=%d, want 1 (V's trojan conn)", left)
	}
}

// TestActiveUserCount verifies the capacity-watermark metric: distinct users
// with ≥1 live conn, deduped by UUID — NOT the connection count.
//   - 3 conns with UUIDs [A, A, B] → 2 users (dedup within a user);
//   - shared registry, same UUID on two protocols (hy2's A + reality's A) → 1
//     (global cross-protocol dedup, the C.1 aggregation rule);
//   - a user whose conns all closed no longer counts (state kept for billing
//     must not inflate the watermark).
func TestActiveUserCount(t *testing.T) {
	r := New()
	if n := r.ActiveUserCount(); n != 0 {
		t.Fatalf("empty registry ActiveUserCount=%d, want 0", n)
	}

	// UUID A on two protocols (cross-protocol dedup) + a second conn shape,
	// UUID B on one: 3 conns, 2 users.
	a1, a1p := net.Pipe()
	a2, a2p := net.Pipe()
	b1, b1p := net.Pipe()
	defer func() { a1p.Close(); a2p.Close(); b1p.Close() }()
	ta1 := r.Track("A", a1, ConnMeta{Protocol: "hysteria2"})
	ta2 := r.Track("A", a2, ConnMeta{Protocol: "reality"})
	tb1 := r.Track("B", b1, ConnMeta{Protocol: "hysteria2"})

	if got := len(r.Snapshot()); got != 3 {
		t.Fatalf("connection count=%d, want 3 (utilization metric)", got)
	}
	if n := r.ActiveUserCount(); n != 2 {
		t.Fatalf("ActiveUserCount=%d, want 2 (A deduped across hy2+reality, B)", n)
	}

	// Close one of A's conns: A still has one live conn → still 2 users.
	ta1.Close()
	if n := r.ActiveUserCount(); n != 2 {
		t.Fatalf("after closing one of A's conns ActiveUserCount=%d, want 2", n)
	}
	// Close A's last conn: A drops out (billing state remains, must not count).
	ta2.Close()
	if n := r.ActiveUserCount(); n != 1 {
		t.Fatalf("after closing all of A's conns ActiveUserCount=%d, want 1 (only B)", n)
	}
	if statFor(r.CollectStats(false), "A").UUID != "A" {
		t.Fatal("A's billing state unexpectedly gone (EvictUser semantics leaked)")
	}
	tb1.Close()
	if n := r.ActiveUserCount(); n != 0 {
		t.Fatalf("all conns closed ActiveUserCount=%d, want 0", n)
	}
}

// TestSnapshot verifies B.2 ActiveConnections: live conns appear with their
// UUID/Destination and per-conn bytes; closed conns drop from the snapshot.
func TestSnapshot(t *testing.T) {
	r := New()
	c1, peer1 := net.Pipe()
	defer peer1.Close()
	tracked := r.Track("A", c1, ConnMeta{Destination: "example.com:443", Source: "1.2.3.4:5555"})

	// One byte each direction so the snapshot shows nonzero counters.
	go func() { peer1.Read(make([]byte, 3)) }()
	tracked.Write([]byte("abc")) // download += 3
	go func() { peer1.Write([]byte("xy")) }()
	tracked.Read(make([]byte, 2)) // upload += 2

	snap := r.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("Snapshot len=%d, want 1", len(snap))
	}
	ci := snap[0]
	if ci.UUID != "A" || ci.Destination != "example.com:443" || ci.Source != "1.2.3.4:5555" {
		t.Fatalf("snapshot meta wrong: %+v", ci)
	}
	if ci.Download != 3 || ci.Upload != 2 {
		t.Fatalf("snapshot bytes got up=%d down=%d, want up=2 down=3", ci.Upload, ci.Download)
	}
	if ci.Start.IsZero() {
		t.Fatal("snapshot Start is zero")
	}

	// Closing the conn drops it from the snapshot.
	tracked.Close()
	if n := len(r.Snapshot()); n != 0 {
		t.Fatalf("Snapshot after close len=%d, want 0", n)
	}
}
