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

	squic "github.com/antsbtw/sing-quic/hysteria2/realm"
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

// systemDialer is the default egress: plain OS sockets out this node's IP.
type systemDialer struct{}

func (systemDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, destination.String())
}

func (systemDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, N.NetworkUDP, ":0")
}

var _ N.Dialer = systemDialer{}

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
	// PunchObserver, when non-nil, receives receiver-side punch engine
	// notifications (assembled by node/punchtrace). nil = observation off
	// (production default).
	PunchObserver squic.PunchObserver
	HTTPClient  *http.Client

	// WrapTLS is the outer QUIC/TLS server config for WrapStream (the reliable
	// stream carrying VMess). Caller-built. VMess itself needs no inner TLS.
	WrapTLS aTLS.ServerConfig

	// VMess credentials.
	UUID     string // canonical UUID string
	Security string // unused server-side (negotiated by client); kept for symmetry
	AlterId  int    // legacy alterId; 0 for AEAD-only

	// Egress dials proxied destinations from this node. If nil, a plain
	// net.Dialer is used (exit = this node's default route / public IP).
	Egress N.Dialer

	// Meter is the per-user traffic/connection registry. When non-nil the node
	// SHARES it (C.1: one Registry across the six protocol nodes of a physical
	// egress). When nil the node builds its own (back-compat). usermap stays
	// per-node regardless.
	Meter *meter.Registry

	// Handler processes each decoded VMess TCP session. Required.
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

// ActiveConnections returns a read-only snapshot of all live connections for
// realm-agent obs risk-control (B.2).
func (n *Node) ActiveConnections() []meter.ConnInfo { return n.meter.Snapshot() }

// ActiveUserCount returns the number of distinct users with at least one live
// connection (dedup by UUID) — the capacity-watermark metric, vs
// ActiveConnections() which is the utilization metric (connection count). With
// a shared Registry (C.1) the count spans every node sharing it, deduped
// globally across protocols.
func (n *Node) ActiveUserCount() int { return n.meter.ActiveUserCount() }

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
	egress := opts.Egress
	if egress == nil {
		egress = systemDialer{}
	}
	realmServer, err := squic.NewServer(squic.Options{
		ServerURL:   opts.ServerURL,
		Token:       opts.Token,
		RealmID:     opts.RealmID,
		STUNServers: opts.STUNServers,
		Resolver:    opts.Resolver,
		HTTPClient:  opts.HTTPClient,
		Logger:      opts.Logger,
		Observer:    opts.PunchObserver,
	})
	if err != nil {
		return nil, E.Cause(err, "create realm server")
	}
	// The vmess.Service decodes each raw conn into a session and calls the
	// Handler with the negotiated destination — same wiring as sing-box's
	// vmess inbound (NewService + UpdateUsers + per-conn NewConnection).
	reg := opts.Meter
	if reg == nil {
		reg = meter.New()
	}
	node := &Node{realm: realmServer, logger: opts.Logger, wrapTLS: opts.WrapTLS, users: usermap.New(), meter: reg}
	node.service = vmess.NewService[int](egressHandler{handler: opts.Handler, dialer: egress, logger: opts.Logger, node: node})
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
	if err := n.service.UpdateUsers(diff.Indices, diff.UUIDs, alterIds); err != nil {
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
// N.UDPConnectionHandlerEx): it receives each decoded VMess session and either
// calls the TCP handler (TCP) or dials a real UDP socket on the open internet
// and pipes packets (UDP).
type egressHandler struct {
	handler Handler
	dialer  N.Dialer
	logger  logger.Logger
	node    *Node
}

func (h egressHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		h.logger.Info("vmess TCP user=", userattr.Label(ctx), " -> ", destination)
		if idx, ok := userattr.IndexFromContext(ctx); ok {
			if uuid, ok := h.node.UUIDForIndex(idx); ok {
				conn = h.node.meter.Track(uuid, conn, meter.ConnMeta{Destination: destination.String(), Protocol: "vmess"})
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
		outbound, err := h.dialer.ListenPacket(ctx, destination)
		if err != nil {
			closeErr = E.Cause(err, "egress listen packet")
			h.logger.Warn(closeErr)
			return
		}
		defer outbound.Close()
		h.logger.Info("egress UDP user=", userattr.Label(ctx), " -> ", destination)
		if idx, ok := userattr.IndexFromContext(ctx); ok {
			if uuid, ok := h.node.UUIDForIndex(idx); ok {
				conn = h.node.meter.TrackPacket(uuid, conn, meter.ConnMeta{Destination: destination.String(), Protocol: "vmess"})
			}
		}
		closeErr = bufio.CopyPacketConn(ctx, conn, bufio.NewPacketConn(outbound))
	}()
}
