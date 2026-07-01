// Package tuic is OTun's thin glue that runs the TUIC overlay protocol over a
// realm-punched UDP hole — the first proof that "UDP-family protocols all ride
// the hole with zero encapsulation" (DEV M3).
//
// It does NOT reimplement TUIC. It reuses sing-quic's tuic.Client engine as a
// library (no fork) and feeds it OTun's punched hole via an underlay.Dialer:
// realm.Punch() opens the hole, the engine's normal QUIC/TLS handshake runs over
// it. The split "punch" + "protocol" (M2 + this) replaces the old
// "punch→QUIC welded" path.
//
// TLS is the CALLER's concern: pass the same aTLS.Config you would give a normal
// TUIC outbound. The glue stays dependency-light (sing-quic + sing only) and free
// of any opinion about certificates.
package tuic

import (
	"context"
	"net"

	"github.com/antsbtw/otun-s-egress/transport/realm"
	"github.com/antsbtw/otun-s-egress/underlay"

	"github.com/sagernet/sing-quic/tuic"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	aTLS "github.com/sagernet/sing/common/tls"
)

// Options configures a TUIC-over-realm client. Realm carries the rendezvous
// coordinates (protocol-agnostic); the rest are TUIC's own parameters, passed
// straight through to the sing-quic engine.
type Options struct {
	// Realm is the rendezvous + STUN config used to punch the hole.
	Realm realm.Config
	// RealmID is the slot to connect to.
	RealmID string

	// TLSConfig is the TUIC TLS client config (caller-built, e.g. via
	// sing-box's tls.NewClient). Required — TUIC runs over QUIC/TLS.
	TLSConfig aTLS.Config
	// UUID and Password are the TUIC credentials.
	UUID     [16]byte
	Password string
	// CongestionControl: "cubic" (default) | "new_reno" | "bbr".
	CongestionControl string
	// UDPStream / ZeroRTTHandshake mirror TUIC's options.
	UDPStream        bool
	ZeroRTTHandshake bool
}

// Client is a TUIC overlay bound to one (lazily) punched hole. Build with Dial.
type Client struct {
	inner *tuic.Client
	lazy  *underlay.LazyDialer
}

// Dial stands up a TUIC client whose QUIC handshake will run over a realm-punched
// hole. The punch is LAZY: it does not happen here but on the TUIC engine's first
// actual dial (offer). This is deliberate — TUIC is given its dialer at
// construction, and an eager punch here would make a punch failure surface
// synchronously at outbound init, which is fatal in a client that builds
// outbounds at startup (a single STUN/rendezvous hiccup would crash the
// extension). Deferring matches the WrapStream protocols' lazy behavior. The
// returned Client's DialConn / ListenPacket carry traffic out the punched peer.
func Dial(ctx context.Context, opts Options) (*Client, error) {
	if opts.TLSConfig == nil {
		return nil, E.New("tuic-over-realm: TLS config is required")
	}
	// Lazy dialer: punches on first use. TUIC reads the real peer from the
	// returned conn's RemoteAddr, so the static ServerAddress is just a
	// placeholder the dialer ignores.
	lazy := underlay.NewLazyDialer(opts.Realm, opts.RealmID, realm.Punch)
	inner, err := tuic.NewClient(tuic.ClientOptions{
		Context:           ctx,
		Dialer:            lazy,
		ServerAddress:     M.Socksaddr{Fqdn: "otun-realm.invalid", Port: 443}, // ignored by lazy dialer
		TLSConfig:         opts.TLSConfig,
		UUID:              opts.UUID,
		Password:          opts.Password,
		CongestionControl: opts.CongestionControl,
		UDPStream:         opts.UDPStream,
		ZeroRTTHandshake:  opts.ZeroRTTHandshake,
	})
	if err != nil {
		return nil, E.Cause(err, "create tuic client")
	}
	return &Client{inner: inner, lazy: lazy}, nil
}

// DialConn opens a TCP-like proxied stream to destination through the TUIC
// tunnel (which itself rides the punched UDP hole).
func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return c.inner.DialConn(ctx, destination)
}

// ListenPacket opens a UDP-associated session through the TUIC tunnel.
func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return c.inner.ListenPacket(ctx)
}

// Close tears down the TUIC client and the underlying punched hole (if a punch
// has happened — the lazy dialer may never have been used).
func (c *Client) Close() error {
	err := c.inner.CloseWithError(net.ErrClosed)
	if p := c.lazy.Punched(); p != nil {
		err = E.Errors(err, p.Close())
	}
	return err
}
