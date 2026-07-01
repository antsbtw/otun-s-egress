// Package underlay is OTun's overlay/underlay seam: it turns a punched UDP hole
// (transport/realm.PunchedConn) into something an overlay protocol engine can
// run on top of, WITHOUT that engine knowing it is riding a hole punch.
//
// This is the layer that lets OTun "own the glue" while reusing sing-quic /
// sing-box protocol engines as libraries (no fork). The engines accept an
// N.Dialer; we hand them a Dialer whose DialContext returns the punched hole
// presented as a connected net.Conn. The engine then does its normal QUIC/TLS
// handshake over the hole, none the wiser.
//
// Aligns with the blueprint target-interfaces/rendezvous.go `Underlay` seam:
// the datagram path (this package) is what UDP-family overlays (Hy2, TUIC) ride
// directly. The reliable Stream() wrapping for TCP-family overlays is M4.
package underlay

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/antsbtw/otun-s-egress/transport/realm"

	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// PunchedConn presents a punched UDP hole as a connected net.Conn: Read receives
// datagrams from the punched peer, Write sends to it, RemoteAddr is the peer.
// This is exactly the shape sing-quic's bufio.NewUnbindPacketConn expects, so a
// protocol engine's qtls.Dial(bufio.NewUnbindPacketConn(conn), conn.RemoteAddr())
// runs its handshake straight over the hole.
//
// NOTE on filtering: the underlying realm.PunchedConn is an unconnected
// PacketConn. We do NOT filter by source here — once punched, the only party
// sending to this socket is the peer, and the QUIC/TLS layer above authenticates
// anyway. Late punch-protocol packets (HYRLMv1) may arrive briefly; the QUIC
// parser discards non-QUIC datagrams, matching how the welded path behaved.
type PunchedConn struct {
	pc   net.PacketConn
	peer M.Socksaddr
}

// FromPunch wraps a realm.PunchedConn as a connected net.Conn.
func FromPunch(p *realm.PunchedConn) *PunchedConn {
	return &PunchedConn{pc: p.PacketConn, peer: p.PeerAddr}
}

func (c *PunchedConn) Read(b []byte) (int, error) {
	n, _, err := c.pc.ReadFrom(b)
	return n, err
}

func (c *PunchedConn) Write(b []byte) (int, error) {
	return c.pc.WriteTo(b, c.peer.UDPAddr())
}

func (c *PunchedConn) Close() error                       { return c.pc.Close() }
func (c *PunchedConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *PunchedConn) RemoteAddr() net.Addr               { return c.peer.UDPAddr() }
func (c *PunchedConn) SetDeadline(t time.Time) error      { return c.pc.SetReadDeadline(t) }
func (c *PunchedConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *PunchedConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }

// PacketConn exposes the raw punched PacketConn, for overlays that prefer the
// datagram form directly.
func (c *PunchedConn) PacketConn() net.PacketConn { return c.pc }

// Peer is the punched peer endpoint.
func (c *PunchedConn) Peer() M.Socksaddr { return c.peer }

// Dialer is an N.Dialer that hands a protocol engine a single pre-punched hole.
// Construct via NewDialer with the result of realm.Punch. The engine's
// DialContext(ctx,"udp",serverAddr) call (TUIC, Hy2, …) receives the punched
// conn; the serverAddr argument is ignored because the destination is already
// the punched peer.
//
// One Dialer serves ONE punched hole (one connection attempt). It is not a
// general-purpose dialer; a fresh Punch + Dialer is made per offer, mirroring
// how realm offers one punched conn per QUIC connection.
type Dialer struct {
	conn *PunchedConn
	used bool
}

// NewDialer builds a one-shot Dialer over a punched hole.
func NewDialer(p *realm.PunchedConn) *Dialer {
	return &Dialer{conn: FromPunch(p)}
}

// DialContext returns the punched hole as a connected net.Conn. network must be
// a UDP variant (the hole is UDP); destination is ignored. Returns an error if
// called twice — the hole is single-use.
func (d *Dialer) DialContext(_ context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkUDP:
	default:
		return nil, E.New("underlay: punched hole is UDP-only, got network ", network)
	}
	if d.used {
		return nil, E.New("underlay: punched hole already consumed")
	}
	d.used = true
	return d.conn, nil
}

// ListenPacket returns the punched hole as a PacketConn (for overlays that listen
// rather than dial). Single-use, like DialContext.
func (d *Dialer) ListenPacket(_ context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	if d.used {
		return nil, E.New("underlay: punched hole already consumed")
	}
	d.used = true
	return d.conn.pc, nil
}

// compile-time check: Dialer satisfies N.Dialer.
var _ N.Dialer = (*Dialer)(nil)

// LazyDialer punches the hole when the engine actually dials, rather than up
// front. This matters for overlays whose engine is given the dialer at
// construction time but only dials lazily (TUIC): with the eager Dialer, the
// punch happens at NewClient/init and a punch failure surfaces synchronously —
// fatal for a client that builds outbounds at startup. LazyDialer defers the
// punch to dial time, so init never blocks or fails on a punch, matching the
// WrapStream protocols' lazy behavior.
//
// It RE-PUNCHES on each call (it does NOT cache a result/failure): TUIC's client
// makes a fresh offer → fresh DialContext every time there is no live QUIC
// connection (e.g. after a failed attempt or a network change), so the dialer
// must be retryable. Each call punches a new hole; the previous hole (if any) is
// closed first. The most recent punched conn is exposed via Punched() so the
// caller can close it on teardown.
type LazyDialer struct {
	cfg     Config
	realmID string
	punchFn func(context.Context, Config, string) (*realm.PunchedConn, error)

	mu      sync.Mutex
	punched *realm.PunchedConn // most recent successful punch
}

// Config and the punch function are injected so underlay does not import
// transport/realm directly (avoids an import cycle: realm has no underlay dep,
// but keeping the seam explicit lets callers pass realm.Punch).
type Config = realm.Config

// NewLazyDialer builds a lazy, retryable dialer. punchFn is normally realm.Punch.
func NewLazyDialer(cfg Config, realmID string, punchFn func(context.Context, Config, string) (*realm.PunchedConn, error)) *LazyDialer {
	return &LazyDialer{cfg: cfg, realmID: realmID, punchFn: punchFn}
}

// punch opens a fresh hole, closing any previous one. Retryable: a failure is
// returned to the engine (which surfaces it as a per-connection error and may
// retry on the next dial), never cached.
func (d *LazyDialer) punch(ctx context.Context) (*PunchedConn, error) {
	p, err := d.punchFn(ctx, d.cfg, d.realmID)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	old := d.punched
	d.punched = p
	d.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return FromPunch(p), nil
}

// DialContext punches a fresh hole and returns it as a connected net.Conn.
func (d *LazyDialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkUDP:
	default:
		return nil, E.New("underlay: punched hole is UDP-only, got network ", network)
	}
	conn, err := d.punch(ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// ListenPacket punches a fresh hole and returns it as a PacketConn.
func (d *LazyDialer) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	conn, err := d.punch(ctx)
	if err != nil {
		return nil, err
	}
	return conn.pc, nil
}

// Punched returns the most recent punched conn (nil before any dial), so the
// caller can close it when tearing down.
func (d *LazyDialer) Punched() *realm.PunchedConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.punched
}

var _ N.Dialer = (*LazyDialer)(nil)

// ConnectedPacketConn presents the dialer's hole the same way sing-quic does
// internally (bufio.NewUnbindPacketConn over the connected conn), for callers
// that want the N.PacketConn form with the peer pre-bound.
func (c *PunchedConn) ConnectedPacketConn() N.NetPacketConn {
	return bufio.NewUnbindPacketConn(c)
}
