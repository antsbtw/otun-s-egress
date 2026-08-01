// Package punchtrace assembles receiver-side hole-punch traces.
//
// It implements realm.PunchObserver (the nil-safe observation interface of the
// antsbtw/sing-quic punch engine) and turns the four engine callbacks of one
// answer attempt into a single Record, handed to a Sink when the attempt ends.
// The engine knows nothing about reporting; this package knows nothing about
// transport — the embedding binary (otun-realm-agent) supplies a Sink that
// ships Records as punch_trace_egress payloads over /obs/ingest.
//
// Purpose (PUNCH_TRACE_DUAL_END_DESIGN §3.1/§4): joined with the initiator's
// trace by nonce, a Record answers "did the initiator's packets reach us?"
// (first_recv_*) and "did we answer?" (ack_sent_*) — the two facts needed to
// prove or refute H1, one-way false success.
package punchtrace

import (
	"encoding/hex"
	"net/netip"
	"sync"
	"time"

	"github.com/antsbtw/sing-quic/hysteria2/realm"
)

// Record is one completed answer attempt, shaped for the punch_trace_egress
// payload (ops-collector stores it verbatim as JSONB; node/realm/region/ts
// ride on the envelope, not here).
//
// AttemptID duplicates Nonce so the collector's pre-built
// payload->>'attempt_id' index serves double-end joins; LocalAttemptID is the
// engine-local answer ID, debug only.
type Record struct {
	AttemptID      string `json:"attempt_id"`
	Nonce          string `json:"nonce"`
	LocalAttemptID string `json:"local_attempt_id"`
	Protocol       string `json:"protocol"`
	// RespondMode is always "punch": the production engine has no direct
	// (passive-only) mode. The field exists so direct-mode data can join the
	// same table without a schema change.
	RespondMode string `json:"respond_mode"`

	StartTS        string   `json:"start_ts"`
	LocalSrflx     []string `json:"local_srflx"`
	PeerCandidates []string `json:"peer_candidates"`

	// first_recv_* prove the peer's traffic reached us; an initiator-side
	// success with no first_recv here is the H1 false-success set.
	// ObservedPeerAddr is the peer's NAT mapping as we saw it.
	FirstRecvTS      string `json:"first_recv_ts,omitempty"`
	FirstRecvType    string `json:"first_recv_type,omitempty"` // "hello" | "ack"
	ObservedPeerAddr string `json:"observed_peer_addr,omitempty"`
	RecvCount        int    `json:"recv_count"`

	// ack_sent_* prove we answered a Hello.
	AckSentTS string `json:"ack_sent_ts,omitempty"`
	AckSentTo string `json:"ack_sent_to,omitempty"`

	OK             bool   `json:"ok"`
	ResultPeerAddr string `json:"result_peer_addr,omitempty"`
	ResultRecvType string `json:"result_recv_type,omitempty"`
	Error          string `json:"error,omitempty"`
	FinishTS       string `json:"finish_ts"`
	DurationMS     int64  `json:"duration_ms"`
}

// Sink receives each finished Record. Called synchronously from the punch
// engine's finish path — implementations must only enqueue, never block.
type Sink func(Record)

// maxPending bounds the in-flight map. The engine's answer timeout guarantees
// PunchFinished fires within ~10s, so this is pure defense against an engine
// bug flooding requests; when hit, the stalest attempt is evicted unsent.
const maxPending = 512

// Observer implements realm.PunchObserver for one protocol node. All methods
// are nil-receiver-safe: a nil *Observer is a no-op, mirroring the kernel's
// probe_trace convention, so callers never need to branch.
type Observer struct {
	protocol string
	sink     Sink

	mu      sync.Mutex
	pending map[string]*pendingAttempt
}

type pendingAttempt struct {
	start  time.Time
	record Record
}

// New builds an Observer labeling records with protocol. A nil sink yields a
// nil Observer (observation off) so wiring code can pass the result through
// unconditionally.
func New(protocol string, sink Sink) *Observer {
	if sink == nil {
		return nil
	}
	return &Observer{
		protocol: protocol,
		sink:     sink,
		pending:  make(map[string]*pendingAttempt),
	}
}

// PunchRequested opens a pending record for the attempt.
func (o *Observer) PunchRequested(attemptID string, metadata realm.PunchMetadata, peerAddresses []netip.AddrPort, localAddresses []netip.AddrPort) {
	if o == nil {
		return
	}
	now := time.Now()
	nonce := hex.EncodeToString(metadata.Nonce[:])
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.pending) >= maxPending {
		o.evictStalestLocked()
	}
	o.pending[attemptID] = &pendingAttempt{
		start: now,
		record: Record{
			AttemptID:      nonce,
			Nonce:          nonce,
			LocalAttemptID: attemptID,
			Protocol:       o.protocol,
			RespondMode:    "punch",
			StartTS:        rfc3339(now),
			LocalSrflx:     formatAddrs(localAddresses),
			PeerCandidates: formatAddrs(peerAddresses),
		},
	}
}

// PunchPacketReceived stamps first_recv_* on the first valid packet and counts
// the rest.
func (o *Observer) PunchPacketReceived(attemptID string, from netip.AddrPort, packetType byte) {
	if o == nil {
		return
	}
	now := time.Now()
	o.mu.Lock()
	defer o.mu.Unlock()
	p := o.pending[attemptID]
	if p == nil {
		return
	}
	p.record.RecvCount++
	if p.record.FirstRecvTS == "" {
		p.record.FirstRecvTS = rfc3339(now)
		p.record.FirstRecvType = typeName(packetType)
		p.record.ObservedPeerAddr = from.String()
	}
}

// PunchAckSent stamps ack_sent_* once (first answer).
func (o *Observer) PunchAckSent(attemptID string, to netip.AddrPort) {
	if o == nil {
		return
	}
	now := time.Now()
	o.mu.Lock()
	defer o.mu.Unlock()
	p := o.pending[attemptID]
	if p == nil || p.record.AckSentTS != "" {
		return
	}
	p.record.AckSentTS = rfc3339(now)
	p.record.AckSentTo = to.String()
}

// PunchFinished finalizes the record and hands it to the sink (outside the
// lock; the sink only enqueues).
func (o *Observer) PunchFinished(attemptID string, result realm.PunchResult, err error) {
	if o == nil {
		return
	}
	now := time.Now()
	o.mu.Lock()
	p := o.pending[attemptID]
	delete(o.pending, attemptID)
	o.mu.Unlock()
	if p == nil {
		return
	}
	p.record.FinishTS = rfc3339(now)
	p.record.DurationMS = now.Sub(p.start).Milliseconds()
	if err != nil {
		p.record.Error = err.Error()
	} else {
		p.record.OK = true
		p.record.ResultPeerAddr = result.PeerAddr.String()
		p.record.ResultRecvType = typeName(result.Type)
	}
	o.sink(p.record)
}

// evictStalestLocked drops the oldest pending attempt. Caller holds o.mu.
func (o *Observer) evictStalestLocked() {
	var (
		stalestID string
		stalestAt time.Time
	)
	for id, p := range o.pending {
		if stalestID == "" || p.start.Before(stalestAt) {
			stalestID = id
			stalestAt = p.start
		}
	}
	if stalestID != "" {
		delete(o.pending, stalestID)
	}
}

func typeName(packetType byte) string {
	switch packetType {
	case realm.PunchHello:
		return "hello"
	case realm.PunchAck:
		return "ack"
	default:
		return "unknown"
	}
}

func formatAddrs(addresses []netip.AddrPort) []string {
	if len(addresses) == 0 {
		return nil
	}
	out := make([]string, 0, len(addresses))
	for _, address := range addresses {
		out = append(out, address.String())
	}
	return out
}

func rfc3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

var _ realm.PunchObserver = (*Observer)(nil)
