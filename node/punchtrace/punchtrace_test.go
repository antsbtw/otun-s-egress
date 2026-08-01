package punchtrace

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/antsbtw/sing-quic/hysteria2/realm"
)

func mustAddr(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

func testMetadata() realm.PunchMetadata {
	var m realm.PunchMetadata
	for i := range m.Nonce {
		m.Nonce[i] = byte(i)
	}
	return m
}

// Full happy path: request → hello received → ack sent → success. The record
// must carry nonce as the join key, first_recv/ack_sent stamps, and ok=true.
func TestObserverAssemblesSuccessRecord(t *testing.T) {
	var got []Record
	o := New("hysteria2", func(r Record) { got = append(got, r) })

	peer := mustAddr(t, "203.0.113.9:41000")
	local := mustAddr(t, "198.51.100.2:443")
	o.PunchRequested("a1", testMetadata(), []netip.AddrPort{peer}, []netip.AddrPort{local})
	o.PunchPacketReceived("a1", peer, realm.PunchHello)
	o.PunchPacketReceived("a1", peer, realm.PunchAck) // later packet must not overwrite first_recv
	o.PunchAckSent("a1", peer)
	o.PunchFinished("a1", realm.PunchResult{PeerAddr: peer, Type: realm.PunchHello}, nil)

	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	r := got[0]
	wantNonce := "000102030405060708090a0b0c0d0e0f"
	if r.Nonce != wantNonce || r.AttemptID != wantNonce {
		t.Errorf("nonce join key: attempt_id=%q nonce=%q want %q", r.AttemptID, r.Nonce, wantNonce)
	}
	if r.LocalAttemptID != "a1" || r.Protocol != "hysteria2" || r.RespondMode != "punch" {
		t.Errorf("identity fields wrong: %+v", r)
	}
	if r.FirstRecvTS == "" || r.FirstRecvType != "hello" || r.ObservedPeerAddr != peer.String() {
		t.Errorf("first_recv fields wrong: %+v", r)
	}
	if r.RecvCount != 2 {
		t.Errorf("recv_count = %d, want 2", r.RecvCount)
	}
	if r.AckSentTS == "" || r.AckSentTo != peer.String() {
		t.Errorf("ack_sent fields wrong: %+v", r)
	}
	if !r.OK || r.ResultPeerAddr != peer.String() || r.Error != "" {
		t.Errorf("result fields wrong: %+v", r)
	}
	if len(r.PeerCandidates) != 1 || len(r.LocalSrflx) != 1 {
		t.Errorf("candidates wrong: %+v", r)
	}
}

// Timeout path: no packet ever arrives — the record must still be emitted,
// with ok=false, an error, and NO first_recv/ack_sent (that absence is the H1
// signal).
func TestObserverAssemblesTimeoutRecord(t *testing.T) {
	var got []Record
	o := New("reality", func(r Record) { got = append(got, r) })

	o.PunchRequested("a2", testMetadata(), []netip.AddrPort{mustAddr(t, "203.0.113.9:41000")}, nil)
	o.PunchFinished("a2", realm.PunchResult{}, errors.New("punch respond timeout"))

	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	r := got[0]
	if r.OK || r.Error == "" {
		t.Errorf("timeout record should be ok=false with error: %+v", r)
	}
	if r.FirstRecvTS != "" || r.AckSentTS != "" {
		t.Errorf("timeout record must have no recv/ack stamps: %+v", r)
	}
}

// A nil Observer (sink off) and events for unknown attempts must both be
// silent no-ops — this is what "production default = zero behavior change"
// rests on.
func TestObserverNilAndUnknownAttemptAreNoOps(t *testing.T) {
	var o *Observer // nil receiver
	o.PunchRequested("x", testMetadata(), nil, nil)
	o.PunchPacketReceived("x", netip.AddrPort{}, realm.PunchHello)
	o.PunchAckSent("x", netip.AddrPort{})
	o.PunchFinished("x", realm.PunchResult{}, nil)

	if New("hysteria2", nil) != nil {
		t.Error("New with nil sink must return nil")
	}

	fired := false
	live := New("hysteria2", func(Record) { fired = true })
	live.PunchPacketReceived("never-requested", netip.AddrPort{}, realm.PunchHello)
	live.PunchAckSent("never-requested", netip.AddrPort{})
	live.PunchFinished("never-requested", realm.PunchResult{}, nil)
	if fired {
		t.Error("events for unknown attempt must not emit a record")
	}
}

// The pending map must stay bounded even if finishes never arrive.
func TestObserverEvictsWhenFlooded(t *testing.T) {
	o := New("hysteria2", func(Record) {})
	for i := 0; i < maxPending+10; i++ {
		o.PunchRequested(string(rune('A'+i%26))+string(rune('0'+i/26)), testMetadata(), nil, nil)
	}
	o.mu.Lock()
	n := len(o.pending)
	o.mu.Unlock()
	if n > maxPending {
		t.Errorf("pending grew to %d, cap is %d", n, maxPending)
	}
}
