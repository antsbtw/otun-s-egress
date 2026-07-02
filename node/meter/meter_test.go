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
