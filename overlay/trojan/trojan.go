// Package trojan is OTun's glue for running the Trojan overlay over a
// realm-punched hole — the TCP-family substitution proof following Reality
// (DEV M5).
//
// Like Reality, Trojan is a TCP-family protocol: it speaks its handshake over a
// reliable, ordered net.Conn, NOT the raw datagram hole. M4's WrapStream
// provides exactly that net.Conn (a QUIC stream over the punched hole), and this
// package feeds it to Trojan's client handshake — the SAME entry point Reality
// uses, just a different inner protocol.
//
// One simplification vs. a normal Trojan outbound: a wire Trojan client wraps an
// OUTER TLS around the TCP conn (Trojan-over-TLS). Here the OUTER transport is
// already WrapStream (QUIC, which carries TLS), so Trojan runs DIRECTLY over the
// reliable stream with NO additional TLS layer. Trojan itself is just a 56-byte
// key + CRLF + destination header followed by the proxied payload — no TLS, no
// uTLS — so this overlay (and its test) need no build tag.
//
// Trojan engine is reused from sing-box as a LIBRARY (no fork): we call
// trojan.Key + trojan.NewClientConn from sing-box/transport/trojan. The egress
// node performs the proxied dial, so the destination is known only at DialConn
// time: Dial establishes punch+wrap, and DialConn wraps that stream as a Trojan
// client conn to a specific destination (mirrors overlay/tuic's DialConn shape).
//
// CONTEXT §10 caveat: once Trojan is wrapped inside QUIC over the hole, its own
// network-facing properties no longer face the wire directly — if this underlay
// crosses the GFW, the wrap (QUIC) must carry obfs. DEPLOYMENT concern; M5 only
// proves Trojan handshakes and carries data over the wrap.
package trojan

import (
	"context"
	"net"

	"github.com/antsbtw/otun-s-egress/transport/realm"
	"github.com/antsbtw/otun-s-egress/underlay"

	"github.com/sagernet/sing-box/transport/trojan"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	aTLS "github.com/sagernet/sing/common/tls"
)

// Options configures a Trojan-over-realm client.
type Options struct {
	// Realm is the rendezvous + STUN config used to punch the hole.
	Realm   realm.Config
	RealmID string

	// WrapTLS is the QUIC/TLS client config for the WrapStream layer (the
	// reliable stream that carries Trojan). Caller-built; this is the OUTER
	// transport's TLS. Trojan adds NO inner TLS of its own here.
	WrapTLS aTLS.Config

	// Password is the Trojan credential; the 56-byte key is derived from it.
	Password string
}

// Conn is a Trojan-over-realm client bound to one punched hole + WrapStream.
// It carries no traffic until DialConn opens a proxied stream to a destination
// (Trojan multiplexes nothing here — one hole carries one Trojan stream).
type Conn struct {
	wrap net.Conn // the WrapStream reliable conn carrying Trojan
	key  [trojan.KeyLength]byte
}

// Dial punches a hole to RealmID and wraps it in a reliable QUIC stream, leaving
// the Trojan client conn unbuilt until DialConn names a destination (the Trojan
// header carries the destination, written lazily on the first DialConn write).
func Dial(ctx context.Context, opts Options) (*Conn, error) {
	if opts.WrapTLS == nil {
		return nil, E.New("trojan-over-realm: WrapTLS (outer QUIC TLS) is required")
	}
	if opts.Password == "" {
		return nil, E.New("trojan-over-realm: password is required")
	}
	punched, err := realm.Punch(ctx, opts.Realm, opts.RealmID)
	if err != nil {
		return nil, E.Cause(err, "punch")
	}
	// M4: reliable stream over the hole. Trojan runs directly over it (no inner TLS).
	wrap, err := underlay.WrapStreamFromPunch(ctx, underlay.FromPunch(punched), opts.WrapTLS)
	if err != nil {
		_ = punched.Close()
		return nil, E.Cause(err, "wrap stream")
	}
	return &Conn{wrap: wrap, key: trojan.Key(opts.Password)}, nil
}

// DialConn returns a net.Conn that proxies to destination through Trojan over
// the WrapStream. The Trojan request header (key + CRLF + destination) is
// written lazily on the first Write; the egress node reads it, dials the
// destination, and splices the payload. Single-use: one hole = one Trojan stream.
func (c *Conn) DialConn(_ context.Context, destination M.Socksaddr) (net.Conn, error) {
	return trojan.NewClientConn(c.wrap, c.key, destination), nil
}

// Close tears down the underlying WrapStream (and with it the punched hole).
func (c *Conn) Close() error {
	return c.wrap.Close()
}
