// WrapStream — the reliable-stream face of the Underlay (M4).
//
// The punched UDP hole (transport/realm.Punch) is a datagram path. UDP-family
// overlays (Hy2, TUIC) ride it directly (see overlay/tuic, M3). TCP-family
// overlays (Reality, Trojan, SS-TCP, VMess) need a RELIABLE, ORDERED byte
// stream — a net.Conn. M4 provides that by running QUIC over the hole and
// handing up a single QUIC stream presented as net.Conn:
//
//	WrapStream(ctx, pc, peer, tls) (net.Conn, error)   // dialer side
//	ListenStream(pc, tls) (*StreamListener, error)     // node side
//
// WrapStream selection (decided with the human): QUIC stream — same stack as
// M1–M3 (sing-quic / quic-go), zero new dependency, most mature, and a QUIC
// stream already IS a net.Conn-shaped object. KCP / uTP remain swappable behind
// this same interface if a future measurement calls for it.
//
// NOTE (CONTEXT §10): once a TCP-family protocol is wrapped inside QUIC over the
// hole, the inner protocol's own anti-probing properties no longer face the
// network directly. If this underlay crosses the GFW, the wrapping layer must
// carry obfs. That is a DEPLOYMENT concern — out of scope for M4, which only
// proves the wrap carries a reliable stream.
package underlay

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

// streamConn adapts a *quic.Stream into a full net.Conn by borrowing the QUIC
// connection's local/remote addresses (a quic.Stream has everything a net.Conn
// needs except the addresses). Closing it tears down the whole QUIC connection,
// because WrapStream owns exactly one connection carrying exactly one stream.
type streamConn struct {
	*quic.Stream
	conn *quic.Conn
}

func (c *streamConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *streamConn) Close() error {
	_ = c.Stream.Close()
	return c.conn.CloseWithError(0, "")
}

var _ net.Conn = (*streamConn)(nil)

// reliableQUICConfig is the QUIC config used for the wrap. Datagrams are not
// needed (we only carry a stream); generous stream limits keep a long-lived
// reliable connection healthy.
func reliableQUICConfig() *quic.Config {
	return &quic.Config{
		MaxIncomingStreams:    1 << 16,
		MaxIncomingUniStreams: 1 << 16,
		KeepAlivePeriod:       15 * time.Second,
		EnableDatagrams:       false,
	}
}

// WrapStream runs QUIC over a punched PacketConn (dialer side) and returns one
// reliable, ordered net.Conn stream. peer is the punched peer endpoint; tlsConfig
// is the caller's QUIC/TLS client config (TCP-family overlays bring their own).
//
// This is the dialer counterpart to ListenStream. The returned net.Conn is what
// a TCP-family overlay (Reality/Trojan/SS/VMess) hands its handshake to (M5).
func WrapStream(ctx context.Context, pc net.PacketConn, peer M.Socksaddr, tlsConfig aTLS.Config) (net.Conn, error) {
	if pc == nil {
		return nil, E.New("underlay: nil packet conn")
	}
	if tlsConfig == nil {
		return nil, E.New("underlay: WrapStream requires a TLS config (QUIC needs TLS)")
	}
	quicConn, err := qtls.Dial(ctx, pc, peer.UDPAddr(), tlsConfig, reliableQUICConfig())
	if err != nil {
		return nil, E.Cause(err, "wrap stream: dial QUIC over hole")
	}
	stream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		_ = quicConn.CloseWithError(0, "")
		return nil, E.Cause(err, "wrap stream: open stream")
	}
	// Write a single byte so the server's AcceptStream fires immediately —
	// quic-go opens streams lazily (no frame until first write), so without
	// this the peer's Accept blocks until we send real data. One leading byte
	// is cheap and the listener side strips it.
	if _, err := stream.Write([]byte{streamOpenByte}); err != nil {
		_ = quicConn.CloseWithError(0, "")
		return nil, E.Cause(err, "wrap stream: prime stream")
	}
	return &streamConn{Stream: stream, conn: quicConn}, nil
}

// WrapStreamFromPunch is a convenience over WrapStream for a realm.PunchedConn:
// it uses the punched peer automatically.
func WrapStreamFromPunch(ctx context.Context, p *PunchedConn, tlsConfig aTLS.Config) (net.Conn, error) {
	return WrapStream(ctx, p.PacketConn(), p.Peer(), tlsConfig)
}

const streamOpenByte = 0x00 // priming byte; see WrapStream / StreamListener.Accept

// StreamListener accepts reliable net.Conn streams over QUIC on a punched
// PacketConn (node side). Mirrors WrapStream for the egress/node end (M5 uses it
// to feed TCP-family overlays their net.Conn).
type StreamListener struct {
	listener qtls.Listener
}

// ListenStream runs a QUIC listener over a punched PacketConn. serverTLS is the
// caller's QUIC/TLS server config.
func ListenStream(pc net.PacketConn, serverTLS aTLS.ServerConfig) (*StreamListener, error) {
	if pc == nil {
		return nil, E.New("underlay: nil packet conn")
	}
	if serverTLS == nil {
		return nil, E.New("underlay: ListenStream requires a TLS server config")
	}
	if err := qtls.ConfigureHTTP3(serverTLS); err != nil {
		// ConfigureHTTP3 only sets a default ALPN if none; harmless for raw QUIC,
		// but tolerate callers that set their own ALPN.
		_ = err
	}
	listener, err := qtls.Listen(pc, serverTLS, reliableQUICConfig())
	if err != nil {
		return nil, E.Cause(err, "listen stream: QUIC listen over hole")
	}
	return &StreamListener{listener: listener}, nil
}

// Accept waits for the next reliable stream and returns it as a net.Conn.
func (l *StreamListener) Accept(ctx context.Context) (net.Conn, error) {
	quicConn, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, E.Cause(err, "accept QUIC connection")
	}
	stream, err := quicConn.AcceptStream(ctx)
	if err != nil {
		_ = quicConn.CloseWithError(0, "")
		return nil, E.Cause(err, "accept stream")
	}
	// Consume the single priming byte WrapStream sent (see WrapStream).
	var prime [1]byte
	if _, err := stream.Read(prime[:]); err != nil {
		_ = quicConn.CloseWithError(0, "")
		return nil, E.Cause(err, "read stream priming byte")
	}
	return &streamConn{Stream: stream, conn: quicConn}, nil
}

// Close stops the listener.
func (l *StreamListener) Close() error {
	return l.listener.Close()
}

// StreamDialer is an N.Dialer that hands a TCP-family protocol engine the
// WrapStream reliable net.Conn over a punched hole. It is the single reuse point
// for Trojan / Shadowsocks-TCP / VMess (and Reality): give the engine this
// dialer; its DialContext(ctx,"tcp",serverAddr) call receives the wrapped
// stream, and the engine runs its handshake over a reliable, ordered conn — none
// the wiser that it rides a hole. Single-use (one hole = one connection).
type StreamDialer struct {
	stream net.Conn
	used   bool
}

// NewStreamDialer wraps an already-established WrapStream net.Conn as a one-shot
// dialer for a TCP-family engine. Build the stream via WrapStream/WrapStreamFromPunch.
func NewStreamDialer(stream net.Conn) *StreamDialer {
	return &StreamDialer{stream: stream}
}

// DialContext returns the wrapped reliable stream. network must be TCP (the
// stream is a reliable byte stream); destination is ignored. Single-use.
func (d *StreamDialer) DialContext(_ context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
	default:
		return nil, E.New("underlay: wrapped stream is TCP-only, got network ", network)
	}
	if d.used {
		return nil, E.New("underlay: wrapped stream already consumed")
	}
	d.used = true
	return d.stream, nil
}

// ListenPacket is unsupported for the reliable-stream dialer (TCP-family).
func (d *StreamDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("underlay: stream dialer does not support packet listen")
}

var (
	_ N.Dialer = (*StreamDialer)(nil)
)
