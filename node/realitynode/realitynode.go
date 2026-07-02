// Package realitynode is OTun's Reality egress node agent — the server-side
// mirror of overlay/reality (DEV M5, TCP-family).
//
// Shape (same "OTun owns the glue, engine is a library" pattern as M3 tuicnode):
//
//	realm.Server          registers on OTun-S, answers punches -> punched hole
//	underlay.ListenStream    QUIC reliable-stream listener on the hole (M4)
//	Reality ServerHandshake  (sing-box lib, no fork) on each accepted stream
//	vless.Service            reads the VLESS request header inside the Reality
//	                         TLS stream to learn the proxied DESTINATION
//	Handler               gets (decrypted net.Conn, destination) and egresses
//
// IMPORTANT: Reality is only the TLS layer. The proxied destination travels in
// the VLESS request header carried INSIDE the Reality TLS stream (Reality is
// always paired with VLESS — "VLESS+Reality"). So a Reality egress that serves
// ARBITRARY destinations must read that VLESS header; doing only the Reality
// handshake leaves the node with a decrypted stream but no idea where to dial.
// This mirrors how the other four TCP/UDP nodes recover destination from their
// own protocol header (Trojan/SS/VMess/TUIC).
package realitynode

import (
	"context"
	"net"
	"net/http"
	"sync"

	sbtls "github.com/sagernet/sing-box/common/tls"
	squic "github.com/sagernet/sing-quic/hysteria2/realm"
	"github.com/sagernet/sing-vmess/vless"
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

// ConnHandler receives each decoded VLESS-over-Reality stream: the proxied
// destination (from the VLESS header) and the decrypted payload net.Conn. The
// caller dials destination and pipes (egress), or echoes (tests).
type ConnHandler func(ctx context.Context, conn net.Conn, destination M.Socksaddr)

// Options configures a Reality egress node.
type Options struct {
	// Rendezvous coordinates.
	ServerURL   string
	Token       string
	RealmID     string
	STUNServers []string
	Resolver    squic.Resolver
	HTTPClient  *http.Client

	// WrapTLS is the outer QUIC/TLS server config for WrapStream (the reliable
	// stream carrying Reality). Caller-built.
	WrapTLS aTLS.ServerConfig
	// Reality is the Reality TLS SERVER config (built via sbtls.NewRealityServer
	// with private_key / short_id / handshake server). Caller-built.
	Reality aTLS.ServerConfig

	// UUID is the VLESS user id (the inner protocol carried by Reality). Must
	// match the client's overlay/reality UUID.
	UUID string

	// Handler processes each decoded VLESS-over-Reality session. Required.
	Handler ConnHandler
	Logger  logger.Logger
}

// Node is a running Reality egress node.
type Node struct {
	realm    *squic.Server
	opts     Options
	logger   logger.Logger
	listener *underlay.StreamListener
	vless    *vless.Service[int]
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

// ActiveConnections returns a read-only snapshot of all live connections for
// realm-agent obs risk-control (B.2).
func (n *Node) ActiveConnections() []meter.ConnInfo { return n.meter.Snapshot() }

// New builds (does not start) a Reality egress node.
func New(opts Options) (*Node, error) {
	if opts.WrapTLS == nil {
		return nil, E.New("realitynode: WrapTLS (outer QUIC TLS) is required")
	}
	if opts.Reality == nil {
		return nil, E.New("realitynode: Reality TLS server config is required")
	}
	if opts.Handler == nil {
		return nil, E.New("realitynode: Handler is required")
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
	// VLESS service decodes the request header (carried inside the Reality TLS
	// stream) and calls vlessHandler with the negotiated destination.
	node.vless = vless.NewService[int](opts.Logger, vlessHandler{node: node})
	node.users = usermap.New()
	if err := node.UpdateUsers([]userattr.User{{UUID: opts.UUID}}); err != nil {
		return nil, E.Cause(err, "seed users")
	}
	return node, nil
}

// UpdateUsers replaces the whole online user set (whole-set semantics). For
// VLESS/Reality the UUID string is the wire identity + billing key; Flow is
// usually empty. Indices are stable per UUID (node/usermap); the vless Service
// swaps its auth map atomically so existing connections are not dropped.
func (n *Node) UpdateUsers(users []userattr.User) error {
	n.usersMu.Lock()
	defer n.usersMu.Unlock()
	flowByUUID := make(map[string]string, len(users))
	uuids := make([]string, len(users))
	for i, u := range users {
		uuids[i] = u.UUID
		flowByUUID[u.UUID] = u.Flow
	}
	diff := n.users.Reconcile(uuids)
	flows := make([]string, len(diff.UUIDs))
	for i, id := range diff.UUIDs {
		flows[i] = flowByUUID[id]
	}
	n.vless.UpdateUsers(diff.Indices, diff.UUIDs, flows)
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

// Start brings the node online: registers on the rendezvous, then runs the
// QUIC reliable-stream listener on the punched hole and Reality-handshakes each
// accepted stream before handing it to Handler.
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
	// 1. Reality TLS server handshake over the reliable stream.
	tlsConn, err := sbtls.ServerHandshake(ctx, stream, n.opts.Reality)
	if err != nil {
		n.logger.Warn(E.Cause(err, "reality server handshake"))
		_ = stream.Close()
		return
	}
	n.logger.Info("reality stream established")
	// 2. VLESS service reads the request header inside the Reality TLS stream,
	// authenticates the UUID, and invokes vlessHandler with the destination.
	// Bind the underlying reliable stream so closing the session tears it down.
	conn := &nodeConn{Conn: tlsConn, raw: stream}
	source := M.SocksaddrFromNet(stream.RemoteAddr())
	if err := n.vless.NewConnection(ctx, conn, source, nil); err != nil {
		n.logger.Warn(E.Cause(err, "vless decode"))
		_ = conn.Close()
	}
}

// vlessHandler adapts vless.Service's Handler (N.TCPConnectionHandlerEx) to the
// node's ConnHandler: it forwards the decoded (destination, payload conn) to the
// caller's Handler.
type vlessHandler struct {
	node *Node
}

func (h vlessHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		h.node.logger.Info("reality(vless) user=", userattr.Label(ctx), " -> ", destination)
		if idx, ok := userattr.IndexFromContext(ctx); ok {
			if uuid, ok := h.node.UUIDForIndex(idx); ok {
				conn = h.node.meter.Track(uuid, conn, meter.ConnMeta{Destination: destination.String()})
			}
		}
		h.node.opts.Handler(ctx, conn, destination)
		if onClose != nil {
			onClose(nil)
		}
	}()
}

// NewPacketConnectionEx rejects UDP-associated VLESS sessions: this egress node
// serves TCP destinations (a net.Conn), matching the other TCP-family nodes.
func (h vlessHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	if onClose != nil {
		onClose(E.New("realitynode: UDP-associated packets are not supported"))
	}
}

// nodeConn closes the underlying reliable stream when the Reality conn closes.
type nodeConn struct {
	net.Conn
	raw net.Conn
}

func (c *nodeConn) Close() error {
	return E.Errors(c.Conn.Close(), c.raw.Close())
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
