// Package ssnode is OTun's Shadowsocks (TCP) egress node agent — the server-side
// mirror of overlay/shadowsocks (TCP-family, alongside realitynode).
//
// Shape (same "OTun owns the glue, engine is a library" pattern as realitynode):
//
//	realm.Server          registers on OTun-S, answers punches -> punched hole
//	underlay.ListenStream  QUIC reliable-stream listener on the hole (M4)
//	shadowaead.Service     (sing-shadowsocks lib, no fork) decodes each accepted
//	                       stream: reads the SS AEAD header, yields the proxied
//	                       (destination, payload-conn)
//	Handler               gets (destination, decrypted net.Conn) and decides what
//	                       to do: echo (tests), or dial the destination (egress)
//
// The client (overlay/shadowsocks) speaks sing-shadowsocks2's Method.DialEarlyConn;
// this node decodes it with sing-shadowsocks's wire-compatible AEAD Service. Both
// are pure imports (zero fork). The same "aes-128-gcm" + password must be set on
// both ends.
package ssnode

import (
	"context"
	"net"
	"net/http"
	"sync"

	squic "github.com/sagernet/sing-quic/hysteria2/realm"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/antsbtw/otun-s-egress/node/meter"
	"github.com/antsbtw/otun-s-egress/node/userattr"
	"github.com/antsbtw/otun-s-egress/node/usermap"
	"github.com/antsbtw/otun-s-egress/underlay"
)

// ConnHandler receives each decoded Shadowsocks stream: the proxied destination
// and a net.Conn carrying the decrypted payload. The caller decides what to do:
// echo (tests), or dial destination and pipe (egress).
type ConnHandler func(ctx context.Context, conn net.Conn, destination M.Socksaddr)

// udpTimeoutSeconds is the UDP NAT timeout for the SS service. SS-TCP only uses
// the TCP path here, but shadowaead.NewService requires a value.
const udpTimeoutSeconds = 300

// Options configures a Shadowsocks egress node.
type Options struct {
	// Rendezvous coordinates.
	ServerURL   string
	Token       string
	RealmID     string
	STUNServers []string
	Resolver    squic.Resolver
	HTTPClient  *http.Client

	// WrapTLS is the outer QUIC/TLS server config for WrapStream (the reliable
	// stream carrying Shadowsocks). Caller-built.
	WrapTLS aTLS.ServerConfig

	// Method is the Shadowsocks AEAD cipher, e.g. "aes-128-gcm"; Password derives
	// the key. Must match the client's overlay/shadowsocks config.
	Method   string
	Password string

	// Handler processes each decoded SS stream. Required.
	Handler ConnHandler
	Logger  logger.Logger
}

// Node is a running Shadowsocks egress node.
type Node struct {
	realm *squic.Server
	// service is the MULTI-user SS service. R1 required switching from the
	// single-user shadowaead.NewService to NewMultiService[int]: only the multi
	// service supports UpdateUsers AND stashes the matched user into the handler
	// context via auth.ContextWithUser (the single service does neither), so it is
	// the prerequisite for per-user hot-reload (R1), attribution (R2a), metering
	// (R2) and kick (R3).
	service  *shadowaead.MultiService[int]
	opts     Options
	logger   logger.Logger
	listener *underlay.StreamListener
	cancel   context.CancelFunc

	meter   *meter.Registry
	usersMu sync.Mutex
	users   *usermap.Map
}

// CollectStats returns per-user traffic; reset=true zeroes after reading (billing
// path). reset=false is a non-destructive snapshot.
func (n *Node) CollectStats(reset bool) []meter.UserStat { return n.meter.CollectStats(reset) }

// KickUser force-closes all live connections of a user, returning the count.
func (n *Node) KickUser(uuid string) int { return n.meter.KickUser(uuid) }

// New builds (does not start) a Shadowsocks egress node.
func New(opts Options) (*Node, error) {
	if opts.WrapTLS == nil {
		return nil, E.New("ssnode: WrapTLS (outer QUIC TLS) is required")
	}
	if opts.Method == "" {
		return nil, E.New("ssnode: Method is required")
	}
	if opts.Handler == nil {
		return nil, E.New("ssnode: Handler is required")
	}
	if opts.Logger == nil {
		opts.Logger = logger.NOP()
	}
	realmServer, err := squic.NewServer(squic.Options{
		ServerURL:   opts.ServerURL,
		Token:       opts.Token,
		RealmID:     opts.RealmID,
		STUNServers: opts.STUNServers,
		Resolver:    opts.Resolver,
		HTTPClient:  opts.HTTPClient,
		Logger:      opts.Logger,
	})
	if err != nil {
		return nil, E.Cause(err, "create realm server")
	}
	node := &Node{realm: realmServer, opts: opts, logger: opts.Logger, users: usermap.New(), meter: meter.New()}
	// Multi-user SS service: decodes the SS AEAD wire (wire-compatible with the
	// client's sing-shadowsocks2 Method) and, per user, hands us the decoded
	// (destination, payload-conn) plus the matched user in ctx.
	service, err := shadowaead.NewMultiService[int](opts.Method, udpTimeoutSeconds, ssHandler{node: node})
	if err != nil {
		return nil, E.Cause(err, "create shadowsocks service")
	}
	node.service = service
	// Seed the initial single user from static config (back-compat): SS is
	// password-only, seed UUID is the synthetic "default".
	if err := node.UpdateUsers([]userattr.User{{UUID: "default", Password: opts.Password}}); err != nil {
		return nil, E.Cause(err, "seed users")
	}
	return node, nil
}

// UpdateUsers replaces the whole online user set (whole-set semantics). For SS
// the per-user key is derived from Password (via the multi service's
// UpdateUsersWithPasswords); indices are stable per UUID (node/usermap) and the
// service swaps its user cipher map atomically so existing streams are not
// dropped. Method is fixed at construction (all users share the cipher).
func (n *Node) UpdateUsers(users []userattr.User) error {
	n.usersMu.Lock()
	defer n.usersMu.Unlock()
	pwByUUID := make(map[string]string, len(users))
	uuids := make([]string, len(users))
	for i, u := range users {
		uuids[i] = u.UUID
		pwByUUID[u.UUID] = u.Password
	}
	diff := n.users.Reconcile(uuids)
	passwords := make([]string, len(diff.UUIDs))
	for i, id := range diff.UUIDs {
		passwords[i] = pwByUUID[id]
	}
	if err := n.service.UpdateUsersWithPasswords(diff.Indices, passwords); err != nil {
		return err
	}
	for _, uuid := range diff.Removed {
		n.meter.EvictUser(uuid) // R1 delete → force-close + drop from billing
	}
	return nil
}

// UUIDForIndex reverse-resolves an authenticated index to its UUID (R2 metering).
func (n *Node) UUIDForIndex(index int) (string, bool) {
	n.usersMu.Lock()
	defer n.usersMu.Unlock()
	return n.users.UUIDForIndex(index)
}

// Start brings the node online: registers on the rendezvous, then runs the QUIC
// reliable-stream listener on the punched hole and SS-decodes each accepted
// stream before handing (destination, conn) to Handler.
func (n *Node) Start(ctx context.Context, conn net.PacketConn) error {
	runCtx, cancel := context.WithCancel(ctx)
	n.cancel = cancel
	punchConn, err := n.realm.Start(runCtx, conn)
	if err != nil {
		cancel()
		return E.Cause(err, "start realm server")
	}
	listener, err := underlay.ListenStream(punchConn, n.opts.WrapTLS)
	if err != nil {
		cancel()
		_ = n.realm.Close()
		return E.Cause(err, "listen stream on hole")
	}
	n.listener = listener
	go n.acceptLoop(runCtx)
	return nil
}

func (n *Node) acceptLoop(ctx context.Context) {
	for {
		stream, err := n.listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			n.logger.Warn(E.Cause(err, "accept reliable stream"))
			continue
		}
		go n.handleStream(ctx, stream)
	}
}

func (n *Node) handleStream(ctx context.Context, stream net.Conn) {
	// shadowaead.Service.NewConnection reads the SS AEAD header off the stream,
	// decodes the destination, and calls ssHandler.NewConnection with a payload
	// conn — see ssHandler below. It blocks until the SS session ends.
	err := n.service.NewConnection(ctx, stream, M.Metadata{Source: M.SocksaddrFromNet(stream.RemoteAddr())})
	if err != nil {
		n.logger.Warn(E.Cause(err, "shadowsocks decode"))
		_ = stream.Close()
	}
}

// Close stops the node.
func (n *Node) Close() error {
	if n.cancel != nil {
		n.cancel()
	}
	var listenerErr error
	if n.listener != nil {
		listenerErr = n.listener.Close()
	}
	return E.Errors(listenerErr, n.realm.Close())
}

// ssHandler adapts shadowsocks.Handler (the deprecated metadata-carrying
// interface shadowaead.Service calls) to ssnode's ConnHandler: it forwards the
// decoded (destination, payload-conn) to the caller's Handler.
type ssHandler struct {
	node *Node
}

//nolint:staticcheck // shadowaead.Service requires the legacy metadata Handler.
func (h ssHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	h.node.logger.Info("shadowsocks stream user=", userattr.Label(ctx), " -> ", metadata.Destination)
	if idx, ok := userattr.IndexFromContext(ctx); ok {
		if uuid, ok := h.node.UUIDForIndex(idx); ok {
			conn = h.node.meter.Track(uuid, conn) // R2/R3
		}
	}
	h.node.opts.Handler(ctx, conn, metadata.Destination)
	return nil
}

//nolint:staticcheck // SS-TCP node does not handle UDP-associated packets.
func (h ssHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	_ = conn.Close()
	return E.New("ssnode: UDP-associated packets are not supported")
}

func (h ssHandler) NewError(ctx context.Context, err error) {
	if E.IsClosedOrCanceled(err) {
		return
	}
	h.node.logger.Warn(E.Cause(err, "shadowsocks service"))
}
