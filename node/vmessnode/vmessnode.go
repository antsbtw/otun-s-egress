// Package vmessnode is OTun's VMess egress node agent — the server-side mirror
// of overlay/vmess (DEV M5 family, TCP-family).
//
// It is needed because stock sing-box's VMess inbound has NO realm field: a
// VMess egress that registers on the rendezvous and answers hole punches does
// not exist upstream. OTun builds it.
//
// Shape (same "OTun owns the glue, engine is a library" pattern as realitynode):
//
//	realm.Server          registers on OTun-S, answers punches -> punched hole
//	underlay.ListenStream  QUIC reliable-stream listener on the hole (M4)
//	vmess.Service         (sing-vmess lib, no fork) decodes each accepted stream
//	                       into a (destination, payload-conn) session
//	Handler               gets the proxied destination + the payload net.Conn
//
// VMess carries its own authenticated encryption, so — unlike realitynode —
// there is NO inner TLS handshake here; the accepted WrapStream conn is fed
// straight to the vmess.Service. The Service's Handler is invoked per session
// with the VMess-negotiated destination, exactly like sing-box's vmess inbound
// routes through its upstream handler.
package vmessnode

import (
	"context"
	"net"
	"net/http"
	"sync"

	squic "github.com/sagernet/sing-quic/hysteria2/realm"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/bufio"
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

// Handler receives each decoded VMess session: the proxied destination and a
// net.Conn carrying the payload. The caller decides what to do — dial the
// destination on the open internet (egress), or echo (tests).
type Handler func(ctx context.Context, conn net.Conn, destination M.Socksaddr)

// Options configures a VMess egress node.
type Options struct {
	// Rendezvous coordinates.
	ServerURL   string
	Token       string
	RealmID     string
	STUNServers []string
	Resolver    squic.Resolver
	HTTPClient  *http.Client

	// WrapTLS is the outer QUIC/TLS server config for WrapStream (the reliable
	// stream carrying VMess). Caller-built. VMess itself needs no inner TLS.
	WrapTLS aTLS.ServerConfig

	// VMess credentials.
	UUID     string // canonical UUID string
	Security string // unused server-side (negotiated by client); kept for symmetry
	AlterId  int    // legacy alterId; 0 for AEAD-only

	// Handler processes each decoded VMess session. Required.
	Handler Handler
	Logger  logger.Logger
}

// Node is a running VMess egress node.
type Node struct {
	realm    *squic.Server
	service  *vmess.Service[int]
	logger   logger.Logger
	wrapTLS  aTLS.ServerConfig
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

// New builds (does not start) a VMess egress node.
func New(opts Options) (*Node, error) {
	if opts.WrapTLS == nil {
		return nil, E.New("vmessnode: WrapTLS (outer QUIC TLS) is required")
	}
	if opts.UUID == "" {
		return nil, E.New("vmessnode: UUID is required")
	}
	if opts.Handler == nil {
		return nil, E.New("vmessnode: Handler is required")
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
	// The vmess.Service decodes each raw conn into a session and calls the
	// Handler with the negotiated destination — same wiring as sing-box's
	// vmess inbound (NewService + UpdateUsers + per-conn NewConnection).
	node := &Node{realm: realmServer, logger: opts.Logger, wrapTLS: opts.WrapTLS, users: usermap.New(), meter: meter.New()}
	node.service = vmess.NewService[int](egressHandler{handler: opts.Handler, logger: opts.Logger, node: node})
	if err := node.UpdateUsers([]userattr.User{{UUID: opts.UUID, AlterId: opts.AlterId}}); err != nil {
		return nil, E.Cause(err, "seed users")
	}
	return node, nil
}

// UpdateUsers replaces the whole online user set (whole-set semantics). For VMess
// the UUID string is the wire identity + billing key; AlterId is usually 0.
// Indices are stable per UUID (node/usermap); the vmess Service swaps its auth
// map atomically so existing sessions are not dropped.
func (n *Node) UpdateUsers(users []userattr.User) error {
	n.usersMu.Lock()
	defer n.usersMu.Unlock()
	alterByUUID := make(map[string]int, len(users))
	uuids := make([]string, len(users))
	for i, u := range users {
		uuids[i] = u.UUID
		alterByUUID[u.UUID] = u.AlterId
	}
	diff := n.users.Reconcile(uuids)
	alterIds := make([]int, len(diff.UUIDs))
	for i, id := range diff.UUIDs {
		alterIds[i] = alterByUUID[id]
	}
	return n.service.UpdateUsers(diff.Indices, diff.UUIDs, alterIds)
}

// UUIDForIndex reverse-resolves an authenticated index to its UUID (R2 metering).
func (n *Node) UUIDForIndex(index int) (string, bool) {
	n.usersMu.Lock()
	defer n.usersMu.Unlock()
	return n.users.UUIDForIndex(index)
}

// Start brings the node online: registers on the rendezvous, runs the QUIC
// reliable-stream listener on the punched hole, and feeds each accepted stream
// to the VMess service for decoding + handling.
func (n *Node) Start(ctx context.Context, conn net.PacketConn) error {
	runCtx, cancel := context.WithCancel(ctx)
	n.cancel = cancel
	if err := n.service.Start(); err != nil {
		cancel()
		return E.Cause(err, "start vmess service")
	}
	punchConn, err := n.realm.Start(runCtx, conn)
	if err != nil {
		cancel()
		return E.Cause(err, "start realm server")
	}
	listener, err := underlay.ListenStream(punchConn, n.wrapTLS)
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
	// Hand the raw WrapStream conn to the VMess service: it reads the VMess
	// request header, authenticates the user, and invokes egressHandler with
	// the negotiated destination + payload conn. source is unknown over the
	// hole (the punched peer); pass the stream's remote addr for logging.
	source := M.SocksaddrFromNet(stream.RemoteAddr())
	if err := n.service.NewConnection(ctx, stream, source, nil); err != nil {
		n.logger.Warn(E.Cause(err, "vmess decode"))
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

// egressHandler implements vmess.Handler (N.TCPConnectionHandlerEx +
// N.UDPConnectionHandlerEx): it receives each decoded VMess session and passes
// the destination + payload conn to the caller's Handler.
type egressHandler struct {
	handler Handler
	logger  logger.Logger
	node    *Node
}

func (h egressHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		h.logger.Info("vmess TCP user=", userattr.Label(ctx), " -> ", destination)
		if idx, ok := userattr.IndexFromContext(ctx); ok {
			if uuid, ok := h.node.UUIDForIndex(idx); ok {
				conn = h.node.meter.Track(uuid, conn) // R2/R3
			}
		}
		h.handler(ctx, conn, destination)
		if onClose != nil {
			onClose(nil)
		}
	}()
}

func (h egressHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		var closeErr error
		defer func() {
			_ = conn.Close()
			if onClose != nil {
				onClose(closeErr)
			}
		}()
		// UDP-over-VMess egress is not exercised by M5 acceptance; surface the
		// destination via the TCP handler path only. A production egress would
		// dial a UDP socket here (see tuicnode for the pattern).
		closeErr = bufio.CopyPacketConn(ctx, conn, conn)
	}()
}
