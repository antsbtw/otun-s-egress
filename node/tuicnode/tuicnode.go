// Package tuicnode is OTun's TUIC egress node agent — the server-side mirror of
// overlay/tuic. It is needed because stock sing-box's TUIC has NO realm field
// (only Hy2 does), so a TUIC egress that registers on the rendezvous and answers
// hole punches does not exist upstream. OTun builds it.
//
// Shape (same "OTun owns the glue, engine is a library" pattern as M3):
//
//	realm.Server  — registers on OTun-S, STUN-discovers, answers punches,
//	                hands up a punched *PunchPacketConn (the UDP hole).
//	tuic.Service  — imported from sing-quic (no fork); its QUIC listener runs
//	                straight on the punched hole.
//	egress handler— dials each proxied destination on the open internet and
//	                pipes bytes both ways (this is what makes it an egress).
//
// A client (overlay/tuic) punches to this node through the same rendezvous and
// gets a TUIC tunnel whose traffic exits this node's IP.
package tuicnode

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/antsbtw/otun-s-egress/node/meter"
	"github.com/antsbtw/otun-s-egress/node/userattr"
	"github.com/antsbtw/otun-s-egress/node/usermap"
	otunrealm "github.com/antsbtw/otun-s-egress/transport/realm"

	squic "github.com/antsbtw/sing-quic/hysteria2/realm"
	singtuic "github.com/antsbtw/sing-quic/tuic"
	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

// Options configures a TUIC egress node.
type Options struct {
	// Rendezvous coordinates (protocol-agnostic).
	ServerURL   string // OTun-S base URL
	Token       string // realm token
	RealmID     string // slot to register under
	STUNServers []string
	// RelayAddresses 非空 → 启用中继回退：收到会合面打洞事件时，本节点在打洞的
	// 同时向这些中继报到（报同一 nonce），供客户端打洞失败时经中继对接。
	// 空 = 不启用，行为与改动前一致。详见 egress.Config.RelayAddresses。
	RelayAddresses []string
	Resolver       squic.Resolver
	// PunchObserver, when non-nil, receives receiver-side punch engine
	// notifications (assembled by node/punchtrace). nil = observation off
	// (production default).
	PunchObserver squic.PunchObserver
	HTTPClient    *http.Client // rendezvous HTTP client; nil => http.DefaultClient

	// TUIC server params.
	TLSConfig         aTLS.ServerConfig // caller-built (cert/key); required
	UUID              [16]byte
	Password          string
	CongestionControl string // "" => cubic

	// Egress dials proxied destinations from this node. If nil, a plain
	// net.Dialer is used (exit = this node's default route / public IP).
	Egress N.Dialer

	// Meter is the per-user traffic/connection registry. When non-nil the node
	// SHARES it (C.1: one Registry across the six protocol nodes of a physical
	// egress). When nil the node builds its own (back-compat). usermap stays
	// per-node regardless.
	Meter *meter.Registry

	Logger logger.Logger
}

// Node is a running TUIC egress node.
type Node struct {
	realm   *squic.Server
	service *singtuic.Service[int]
	logger  logger.Logger
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

// uuidFor resolves the authenticated user's UUID for a handler context.
func (n *Node) uuidFor(ctx context.Context) (string, bool) {
	idx, ok := userattr.IndexFromContext(ctx)
	if !ok {
		return "", false
	}
	return n.UUIDForIndex(idx)
}

// New builds (but does not start) a TUIC egress node.
func New(opts Options) (*Node, error) {
	if opts.TLSConfig == nil {
		return nil, E.New("tuicnode: TLS server config is required")
	}
	if opts.Logger == nil {
		opts.Logger = logger.NOP()
	}
	egress := opts.Egress
	if egress == nil {
		egress = systemDialer{}
	}
	// 中继地址：解析失败即报错而非静默丢弃 —— 配错了要立刻可见，
	// 否则会静默退回纯打洞、在对称 NAT 客户端上表现为"改了没用"，极难排查。
	relayAddrs, err := otunrealm.ParseRelayAddresses(opts.RelayAddresses)
	if err != nil {
		return nil, err
	}
	realmServer, err := squic.NewServer(squic.Options{
		ServerURL:      opts.ServerURL,
		Token:          opts.Token,
		RealmID:        opts.RealmID,
		STUNServers:    opts.STUNServers,
		RelayAddresses: relayAddrs,
		Resolver:       opts.Resolver,
		HTTPClient:     opts.HTTPClient,
		Logger:         opts.Logger,
		Observer:       opts.PunchObserver,
	})
	if err != nil {
		return nil, E.Cause(err, "create realm server")
	}
	reg := opts.Meter
	if reg == nil {
		reg = meter.New()
	}
	n := &Node{realm: realmServer, logger: opts.Logger, users: usermap.New(), meter: reg}
	service, err := singtuic.NewService[int](singtuic.ServiceOptions{
		Context:           context.Background(),
		Logger:            opts.Logger,
		TLSConfig:         opts.TLSConfig,
		CongestionControl: opts.CongestionControl,
		Handler:           egressHandler{dialer: egress, logger: opts.Logger, node: n},
	})
	if err != nil {
		return nil, E.Cause(err, "create tuic service")
	}
	n.service = service
	// Seed the initial single user from static config (back-compat). The TUIC
	// uuid is the billing key; realm-agent later replaces the whole set.
	seedUUID := uuid.FromBytesOrNil(opts.UUID[:]).String()
	if err := n.UpdateUsers([]userattr.User{{UUID: seedUUID, Password: opts.Password}}); err != nil {
		return nil, E.Cause(err, "seed users")
	}
	return n, nil
}

// UpdateUsers replaces the whole online user set (whole-set semantics). Adding/
// removing users does not drop existing connections — the TUIC Service swaps its
// auth map atomically. Indices are stable per UUID (node/usermap). For TUIC the
// UUID string is both the billing key and the wire uuid (parsed to [16]byte).
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
	uuidBytes := make([][16]byte, len(diff.UUIDs))
	passwords := make([]string, len(diff.UUIDs))
	for i, id := range diff.UUIDs {
		parsed, err := uuid.FromString(id)
		if err != nil {
			return E.Cause(err, "tuic uuid ", id)
		}
		uuidBytes[i] = parsed
		passwords[i] = pwByUUID[id]
	}
	n.service.UpdateUsers(diff.Indices, uuidBytes, passwords)
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

// Start brings the node online: opens the UDP socket, registers on the
// rendezvous via realm.Server, and runs the TUIC service on the punched hole.
func (n *Node) Start(ctx context.Context, conn net.PacketConn) error {
	punchConn, err := n.realm.Start(ctx, conn)
	if err != nil {
		return E.Cause(err, "start realm server")
	}
	if err := n.service.Start(punchConn); err != nil {
		_ = n.realm.Close()
		return E.Cause(err, "start tuic service")
	}
	return nil
}

// Close stops the node.
func (n *Node) Close() error {
	return E.Errors(n.service.Close(), n.realm.Close())
}

// egressHandler implements singtuic.ServiceHandler: it dials each proxied
// destination on the open internet and pipes bytes, making this node an egress.
type egressHandler struct {
	dialer N.Dialer
	logger logger.Logger
	node   *Node
}

func (h egressHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		var closeErr error
		defer func() {
			_ = conn.Close()
			if onClose != nil {
				onClose(closeErr)
			}
		}()
		outbound, err := h.dialer.DialContext(ctx, N.NetworkTCP, destination)
		if err != nil {
			closeErr = E.Cause(err, "egress dial ", destination)
			h.logger.Warn(closeErr)
			return
		}
		defer outbound.Close()
		h.logger.Info("egress TCP user=", userattr.Label(ctx), " -> ", destination)
		if uuid, ok := h.node.uuidFor(ctx); ok {
			conn = h.node.meter.Track(uuid, conn, meter.ConnMeta{Destination: destination.String(), Protocol: "tuic"})
		}
		closeErr = bufio.CopyConn(ctx, conn, outbound)
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
		if uuid, ok := h.node.uuidFor(ctx); ok {
			conn = h.node.meter.TrackPacket(uuid, conn, meter.ConnMeta{Destination: destination.String(), Protocol: "tuic"})
		}
		closeErr = bufio.CopyPacketConn(ctx, conn, bufio.NewPacketConn(outbound))
	}()
}

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
var _ = time.Second // reserved for future timeouts
