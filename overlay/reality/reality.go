// Package reality is OTun's glue for running the Reality (VLESS+Reality) TLS
// transport over a realm-punched hole — the TCP-family proof (DEV M5).
//
// TCP-family overlays (Reality/Trojan/SS-TCP/VMess) need a reliable, ordered
// net.Conn (not a datagram path). M4's WrapStream provides exactly that: a QUIC
// stream over the punched hole, presented as net.Conn. M5 feeds that net.Conn to
// Reality's TLS handshake — and the SAME net.Conn entry point works for the
// other three TCP-family protocols (they all just want a net.Conn to handshake
// over). DEV M5: prove Reality first, the rest follow by substitution.
//
// Reality engine is reused from sing-box as a LIBRARY (no fork): it is an
// aTLS.Config that handshakes over any net.Conn. We supply the punched+wrapped
// net.Conn; Reality does its borrowed-cert TLS over it.
//
// Reality is ONLY the TLS layer; the proxied destination travels in the VLESS
// request header carried INSIDE the Reality TLS stream ("VLESS+Reality"). So
// this client layers VLESS over the Reality conn — DialConn(dest) writes the
// VLESS header for dest, exactly as a normal VLESS+Reality outbound does. The
// VLESS engine is likewise reused as a library (sing-vmess/vless).
//
// CONTEXT §10 caveat: once Reality is wrapped inside QUIC over the hole, its own
// network-facing anti-probing no longer faces the wire directly — if this
// underlay crosses the GFW, the wrap (QUIC) must carry obfs. DEPLOYMENT concern;
// M5 only proves Reality handshakes and carries data over the wrap.
package reality

import (
	"context"
	"net"

	"github.com/antsbtw/otun-s-egress/transport/realm"
	"github.com/antsbtw/otun-s-egress/underlay"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-vmess/vless"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	aTLS "github.com/sagernet/sing/common/tls"
)

// Options configures a Reality-over-realm client.
type Options struct {
	// Realm is the rendezvous + STUN config used to punch the hole.
	Realm   realm.Config
	RealmID string

	// WrapTLS is the QUIC/TLS client config for the WrapStream layer (the
	// reliable stream that carries Reality). Caller-built; this is the OUTER
	// transport's TLS, distinct from the inner Reality TLS.
	WrapTLS aTLS.Config

	// Reality is the Reality TLS client config (built via sbtls.NewRealityClient
	// with public_key / short_id / server_name / uTLS). This is the INNER TLS
	// the VLESS session speaks over. Caller-built.
	Reality aTLS.Config

	// UUID is the VLESS user id (the inner protocol Reality carries). Must match
	// the egress node's realitynode UUID.
	UUID string
}

// Client is a Reality+VLESS overlay bound to one punched hole. Build with Dial;
// each Client carries one VLESS session (one hole = one connection, mirroring
// the other TCP-family overlays). DialConn opens the proxied stream to a target.
type Client struct {
	vless *vless.Client
	tls   net.Conn // Reality TLS conn over the wrap
	wrap  net.Conn // the underlying WrapStream conn (closed with this)
}

// Dial punches a hole to RealmID, wraps it in a reliable QUIC stream, runs the
// Reality TLS client handshake over that stream, and prepares the VLESS client.
// DialConn then opens a proxied stream to a destination — the punch invisible to
// both the Reality and VLESS engines.
func Dial(ctx context.Context, opts Options) (*Client, error) {
	if opts.WrapTLS == nil {
		return nil, E.New("reality-over-realm: WrapTLS (outer QUIC TLS) is required")
	}
	if opts.Reality == nil {
		return nil, E.New("reality-over-realm: Reality TLS config is required")
	}
	vlessClient, err := vless.NewClient(opts.UUID, "", logger.NOP()) // empty flow
	if err != nil {
		return nil, E.Cause(err, "create vless client")
	}
	punched, err := realm.Punch(ctx, opts.Realm, opts.RealmID)
	if err != nil {
		return nil, E.Cause(err, "punch")
	}
	// M4: reliable stream over the hole.
	wrap, err := underlay.WrapStreamFromPunch(ctx, underlay.FromPunch(punched), opts.WrapTLS)
	if err != nil {
		_ = punched.Close()
		return nil, E.Cause(err, "wrap stream")
	}
	// M5: Reality TLS over the reliable stream.
	tlsConn, err := sbtls.ClientHandshake(ctx, wrap, opts.Reality)
	if err != nil {
		_ = wrap.Close()
		return nil, E.Cause(err, "reality handshake")
	}
	return &Client{vless: vlessClient, tls: tlsConn, wrap: wrap}, nil
}

// DialConn opens a proxied stream to destination through VLESS+Reality (which
// itself rides the reliable wrap over the punched hole). It uses DialEarlyConn so
// the VLESS request header is sent lazily with the first write, exactly like a
// normal VLESS outbound.
func (c *Client) DialConn(_ context.Context, destination M.Socksaddr) (net.Conn, error) {
	return c.vless.DialEarlyConn(c.tls, destination)
}

// Close tears down the Reality conn and the underlying wrap (QUIC over the hole).
func (c *Client) Close() error {
	return E.Errors(c.tls.Close(), c.wrap.Close())
}
