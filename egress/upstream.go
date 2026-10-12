package egress

import (
	"context"
	"net"
	"net/url"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

// upstreamHandshakeTimeout bounds TCP connect + SOCKS5 handshake to the upstream
// proxy, so a stalled proxy fails the user's dial instead of hanging it.
const upstreamHandshakeTimeout = 10 * time.Second

// UpstreamConfig routes this node's proxied user traffic through an upstream
// SOCKS5 proxy (e.g. a static residential/ISP IP) instead of out the node's own
// IP. Only the USER egress leg is affected: rendezvous / STUN / punching / relay
// / heartbeat keep using the node's own sockets.
//
// Fail-closed: when the upstream is unreachable or rejects us, the user's
// connection fails. There is NO fallback to a direct dial — the only direct
// dials are destinations explicitly listed in DirectDomains.
type UpstreamConfig struct {
	// URL is socks5://user:pass@host:port (scheme "socks" is accepted too).
	URL string
	// DirectDomains are domain suffixes that bypass the upstream and dial
	// directly from this node (bandwidth relief for heavy CDNs). "example.com"
	// matches example.com and *.example.com. Matching is by the destination's
	// domain only; destinations the client sent as a bare IP always go upstream.
	DirectDomains []string
}

// UpstreamDialer is the N.Dialer injected as Config.Egress.
type UpstreamDialer struct {
	server   M.Socksaddr
	username string
	password string
	direct   []string
}

// NewUpstreamDialer validates cfg and builds the dialer. It does not contact the
// proxy (health checking is the caller's job).
func NewUpstreamDialer(cfg UpstreamConfig) (*UpstreamDialer, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, E.Cause(err, "upstream: parse url")
	}
	switch u.Scheme {
	case "socks5", "socks":
	default:
		return nil, E.New("upstream: unsupported scheme ", u.Scheme, " (want socks5)")
	}
	server := M.ParseSocksaddr(u.Host)
	if !server.IsValid() || server.Port == 0 {
		return nil, E.New("upstream: invalid host:port ", u.Host)
	}
	d := &UpstreamDialer{server: server}
	if u.User != nil {
		d.username = u.User.Username()
		d.password, _ = u.User.Password()
	}
	for _, s := range cfg.DirectDomains {
		s = strings.Trim(strings.ToLower(strings.TrimSpace(s)), ".")
		if s != "" {
			d.direct = append(d.direct, s)
		}
	}
	return d, nil
}

// Server returns the upstream host:port (for logs; never includes credentials).
func (d *UpstreamDialer) Server() string { return d.server.String() }

// DirectDomains returns the normalized bypass suffix list.
func (d *UpstreamDialer) DirectDomains() []string { return d.direct }

func (d *UpstreamDialer) isDirect(destination M.Socksaddr) bool {
	if len(d.direct) == 0 || !destination.IsFqdn() {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(destination.Fqdn), ".")
	for _, s := range d.direct {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

func (d *UpstreamDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.New("upstream: DialContext supports tcp only, got ", network)
	}
	if d.isDirect(destination) {
		return (&net.Dialer{Timeout: upstreamHandshakeTimeout}).DialContext(ctx, N.NetworkTCP, destination.String())
	}
	conn, _, err := d.handshake(ctx, socks5.CommandConnect, destination)
	return conn, err
}

func (d *UpstreamDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if d.isDirect(destination) {
		var lc net.ListenConfig
		return lc.ListenPacket(ctx, N.NetworkUDP, ":0")
	}
	tcpConn, resp, err := d.handshake(ctx, socks5.CommandUDPAssociate, destination)
	if err != nil {
		return nil, err
	}
	// Some proxies answer UDP ASSOCIATE with an unspecified BND.ADDR (0.0.0.0
	// / ::), meaning "same host as the TCP control connection".
	relay := resp.Bind
	if !relay.IsValid() || (relay.IsIP() && relay.Addr.IsUnspecified()) {
		relay = M.Socksaddr{Addr: remoteAddrOf(tcpConn, d.server).Addr, Port: resp.Bind.Port}
	}
	udpConn, err := (&net.Dialer{Timeout: upstreamHandshakeTimeout}).DialContext(ctx, N.NetworkUDP, relay.String())
	if err != nil {
		_ = tcpConn.Close()
		return nil, E.Cause(err, "upstream: dial udp relay ", relay)
	}
	// Closing the packet conn also closes the TCP control conn (ends the association).
	return socks.NewAssociatePacketConn(udpConn, destination, tcpConn), nil
}

// handshake dials the proxy and runs the SOCKS5 handshake under a deadline.
func (d *UpstreamDialer) handshake(ctx context.Context, command byte, destination M.Socksaddr) (net.Conn, socks5.Response, error) {
	conn, err := (&net.Dialer{Timeout: upstreamHandshakeTimeout}).DialContext(ctx, N.NetworkTCP, d.server.String())
	if err != nil {
		return nil, socks5.Response{}, E.Cause(err, "upstream: dial proxy ", d.server)
	}
	_ = conn.SetDeadline(time.Now().Add(upstreamHandshakeTimeout))
	resp, err := socks.ClientHandshake5(conn, command, destination, d.username, d.password)
	if err != nil {
		_ = conn.Close()
		return nil, socks5.Response{}, E.Cause(err, "upstream: socks5 handshake via ", d.server)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, resp, nil
}

func remoteAddrOf(conn net.Conn, fallback M.Socksaddr) M.Socksaddr {
	if a := M.SocksaddrFromNet(conn.RemoteAddr()); a.IsIP() {
		return a
	}
	return fallback
}

var _ N.Dialer = (*UpstreamDialer)(nil)
