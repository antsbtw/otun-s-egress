// Package trojannode is OTun's Trojan egress node agent — the server-side mirror
// of overlay/trojan (DEV M5, TCP-family), following node/realitynode exactly.
//
// Shape (same "OTun owns the glue, engine is a library" pattern):
//
//	realm.Server           registers on OTun-S, answers punches -> punched hole
//	underlay.ListenStream  QUIC reliable-stream listener on the hole (M4)
//	trojan.Service         (sing-box lib, no fork) reads the Trojan request header
//	                       (56-byte key + CRLF + command + destination) off each
//	                       accepted stream and yields (conn, destination)
//	Handler                gets the post-header net.Conn + destination; an egress
//	                       dials the destination and splices the payload
//
// Unlike a wire Trojan inbound, there is NO inner TLS here: the WrapStream (QUIC)
// already provides the encrypted reliable transport, and Trojan rides directly on
// it. We therefore drive the Trojan protocol via trojan.Service directly on the
// accepted stream — the same primitive sing-box's Trojan inbound uses, minus the
// TLS/listener/router scaffolding.
package trojannode

import (
	"context"
	"net"
	"net/http"
	"sync"

	"github.com/sagernet/sing-box/transport/trojan"
	squic "github.com/sagernet/sing-quic/hysteria2/realm"
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

// ConnHandler receives each Trojan stream after its request header is read: the
// post-header net.Conn carrying the proxied payload, plus the destination the
// client asked for. An egress dials destination and splices; tests can echo.
type ConnHandler func(ctx context.Context, conn net.Conn, destination M.Socksaddr)

// Options configures a Trojan egress node.
type Options struct {
	// Rendezvous coordinates.
	ServerURL   string
	Token       string
	RealmID     string
	STUNServers []string
	Resolver    squic.Resolver
	HTTPClient  *http.Client

	// WrapTLS is the outer QUIC/TLS server config for WrapStream (the reliable
	// stream carrying Trojan). Caller-built. Trojan adds no inner TLS here.
	WrapTLS aTLS.ServerConfig
	// Password is the Trojan credential; the accepted key must match it.
	Password string

	// Handler processes each Trojan stream + destination. Required.
	Handler ConnHandler
	Logger  logger.Logger
}

// Node is a running Trojan egress node.
type Node struct {
	realm    *squic.Server
	opts     Options
	logger   logger.Logger
	service  *trojan.Service[int]
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

// New builds (does not start) a Trojan egress node.
func New(opts Options) (*Node, error) {
	if opts.WrapTLS == nil {
		return nil, E.New("trojannode: WrapTLS (outer QUIC TLS) is required")
	}
	if opts.Password == "" {
		return nil, E.New("trojannode: password is required")
	}
	if opts.Handler == nil {
		return nil, E.New("trojannode: Handler is required")
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
	node := &Node{realm: realmServer, opts: opts, logger: opts.Logger, meter: meter.New()}
	// One-user Trojan service: index 0 keyed by the configured password. The
	// service reads the request header and routes via the handler below; no
	// fallback (a bad key just fails the stream).
	service := trojan.NewService[int]((*serviceHandler)(node), nil, contextLogger(opts.Logger))
	node.service = service
	node.users = usermap.New()
	// Seed the initial single user from static config (back-compat): trojan is
	// password-only, seed UUID is the synthetic "default".
	if err := node.UpdateUsers([]userattr.User{{UUID: "default", Password: opts.Password}}); err != nil {
		return nil, E.Cause(err, "seed users")
	}
	return node, nil
}

// UpdateUsers replaces the whole online user set (whole-set semantics). Trojan
// authenticates by a password hash; indices are stable per UUID (node/usermap)
// and the Service swaps its auth map atomically (existing streams not dropped).
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
	return n.service.UpdateUsers(diff.Indices, passwords)
}

// UUIDForIndex reverse-resolves an authenticated index to its UUID (R2 metering).
func (n *Node) UUIDForIndex(index int) (string, bool) {
	n.usersMu.Lock()
	defer n.usersMu.Unlock()
	return n.users.UUIDForIndex(index)
}

// Start brings the node online: registers on the rendezvous, then runs the QUIC
// reliable-stream listener on the punched hole and drives the Trojan request
// header off each accepted stream before handing (conn, destination) to Handler.
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
	// trojan.Service reads the request header (key + CRLF + command + destination)
	// and calls our serviceHandler with the post-header conn + destination.
	err := n.service.NewConnection(ctx, stream, M.Socksaddr{}, func(it error) {
		if it != nil && ctx.Err() == nil {
			n.logger.Warn(E.Cause(it, "trojan stream closed"))
		}
	})
	if err != nil {
		n.logger.Warn(E.Cause(err, "trojan request handshake"))
		_ = stream.Close()
	}
}

// serviceHandler adapts the Node to trojan.Service's Handler interface. Only TCP
// is wired (Trojan-over-realm carries TCP-family proxied streams); UDP-associate
// is rejected here since the egress contract is a net.Conn to a destination.
type serviceHandler Node

var _ trojan.Handler = (*serviceHandler)(nil)

func (h *serviceHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _ M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	n := (*Node)(h)
	n.logger.Info("trojan stream user=", userattr.Label(ctx), " to ", destination)
	if idx, ok := userattr.IndexFromContext(ctx); ok {
		if uuid, ok := n.UUIDForIndex(idx); ok {
			conn = n.meter.Track(uuid, conn) // R2/R3: count + make kickable
		}
	}
	n.opts.Handler(ctx, conn, destination)
	if onClose != nil {
		onClose(nil)
	}
}

func (h *serviceHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _ M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.logger.Warn("trojan UDP-associate to ", destination, " not supported on this egress")
	_ = conn.Close()
	if onClose != nil {
		onClose(E.New("trojannode: UDP-associate not supported"))
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

// contextLogger adapts a logger.Logger to the logger.ContextLogger trojan.Service
// expects. logger.NOP() already satisfies ContextLogger; this keeps the API
// surface (Options.Logger) the same as realitynode/tuicnode.
func contextLogger(l logger.Logger) logger.ContextLogger {
	if cl, ok := l.(logger.ContextLogger); ok {
		return cl
	}
	return logger.NOP()
}
