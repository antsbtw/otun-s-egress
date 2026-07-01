package meter

import (
	"net"
	"testing"
)

// TestMeterCountAndReset verifies per-user up/down counting and the reset-vs-
// snapshot semantics (R2 billing correctness).
func TestMeterCountAndReset(t *testing.T) {
	r := New()
	c1, c2 := net.Pipe()
	defer c2.Close()
	tracked := r.Track("userA", c1)

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
	ta := r.Track("A", a1)
	tb := r.Track("B", b1)

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
