// Package hy2node is OTun's Hysteria2 egress node agent — the server-side mirror
// of the Hy2-over-realm client. Unlike the other five protocols, stock sing-box
// already has a realm field for Hysteria2, and sing-quic's hysteria2.Service has
// built-in realm support (ServiceOptions.RealmOptions + Service.startWithRealm).
//
// So this node is even thinner than node/tuicnode: there is NO separate
// squic.Server wrapper — the hysteria2 Service owns the rendezvous registration
// and hole punch itself. We only supply:
//
//	hysteria2.Service — imported from sing-quic (no fork); RealmOptions set so it
//	                    registers on OTun-S, answers punches, and runs its QUIC
//	                    listener straight on the punched hole.
//	egress handler    — dials each proxied destination on the open internet and
//	                    pipes bytes both ways (this is what makes it an egress).
//
// A client (Hy2-over-realm, which works on stock sing-box) punches to this node
// through the same rendezvous and gets a Hy2 tunnel whose traffic exits this
// node's IP. This exists so the six-protocol reference system has a uniform,
// same-shape egress node for every protocol including Hy2.
package hy2node

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/antsbtw/otun-s-egress/node/userattr"

	singhy2 "github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing-quic/hysteria2/realm"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

// Options configures a Hysteria2 egress node.
type Options struct {
	// Rendezvous coordinates (protocol-agnostic).
	ServerURL   string // OTun-S base URL
	Token       string // realm token
	RealmID     string // slot to register under
	STUNServers []string
	Resolver    realm.Resolver
	HTTPClient  *http.Client // rendezvous HTTP client; nil => http.DefaultClient

	// Hysteria2 server params.
	TLSConfig aTLS.ServerConfig // caller-built (cert/key); required
	Password  string            // Hy2 auth (password-only; no UUID)

	// Egress dials proxied destinations from this node. If nil, a plain
	// net.Dialer is used (exit = this node's default route / public IP).
	Egress N.Dialer
	Logger logger.Logger
}

// Node is a running Hysteria2 egress node.
type Node struct {
	service *singhy2.Service[int]
	logger  logger.Logger
}

// New builds (but does not start) a Hysteria2 egress node.
func New(opts Options) (*Node, error) {
	if opts.TLSConfig == nil {
		return nil, E.New("hy2node: TLS server config is required")
	}
	if opts.Logger == nil {
		opts.Logger = logger.NOP()
	}
	egress := opts.Egress
	if egress == nil {
		egress = systemDialer{}
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	service, err := singhy2.NewService[int](singhy2.ServiceOptions{
		Context:   context.Background(),
		Logger:    opts.Logger,
		TLSConfig: opts.TLSConfig,
		Handler:   egressHandler{dialer: egress, logger: opts.Logger},
		RealmOptions: &realm.Options{
			ServerURL:   opts.ServerURL,
			Token:       opts.Token,
			RealmID:     opts.RealmID,
			STUNServers: opts.STUNServers,
			Resolver:    opts.Resolver,
			HTTPClient:  httpClient,
			Logger:      opts.Logger,
		},
	})
	if err != nil {
		return nil, E.Cause(err, "create hysteria2 service")
	}
	service.UpdateUsers([]int{0}, []string{opts.Password})
	return &Node{service: service, logger: opts.Logger}, nil
}

// Start brings the node online: the hysteria2 Service registers on the
// rendezvous (RealmOptions) and runs on the punched hole opened from conn.
func (n *Node) Start(ctx context.Context, conn net.PacketConn) error {
	if err := n.service.Start(conn); err != nil {
		return E.Cause(err, "start hysteria2 service")
	}
	return nil
}

// Close stops the node.
func (n *Node) Close() error {
	return n.service.Close()
}

// egressHandler implements singhy2.ServerHandler: it dials each proxied
// destination on the open internet and pipes bytes, making this node an egress.
type egressHandler struct {
	dialer N.Dialer
	logger logger.Logger
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
