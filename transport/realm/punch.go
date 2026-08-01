// Package realm is the protocol-agnostic CLIENT-side "register + hole-punch"
// library: the dialer half of the rendezvous foundation (M2).
//
// It exposes a single primitive:
//
//	Punch(ctx, cfg, realmID) (net.PacketConn, error)
//
// which performs STUN discovery, talks to the rendezvous control plane to swap
// candidate addresses with the target node, races UDP hole punching across
// address families, and returns a RAW, already-punched net.PacketConn. It does
// NOT touch any overlay protocol: no QUIC handshake, no obfs, no TLS. The caller
// (hysteria2 / TUIC / …) takes the returned PacketConn and runs its own
// handshake on top — splitting the old "punch→QUIC welded" path into
// "punch" + "protocol".
//
// This is the client counterpart to OTun-S (the rendezvous engine, server
// side). Together they are the independent, protocol-agnostic rendezvous
// foundation that DEV M1+M2 call for.
//
// IMPLEMENTATION NOTE: the low-level punch primitives (packet codec, STUN,
// control client, symmetric-NAT candidate expansion) are reused verbatim from
// sing-quic's hysteria2/realm package — the exact code already proven on the
// Hy2 path — so behavior matches the regression baseline. What lives HERE is
// only the dialer-side orchestration that sing-quic had tangled inside
// hysteria2's client.go (offerNewRealm), lifted out protocol-free.
package realm

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"

	squic "github.com/antsbtw/sing-quic/hysteria2/realm"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Resolver resolves a STUN server hostname to addresses. Reuses sing-quic's
// signature so callers can pass the same resolver they already wire for Hy2.
type Resolver = squic.Resolver

// Config is the protocol-agnostic input to Punch — the realm coordinates only.
// It carries NOTHING protocol-specific (no password, no SNI, no obfs): those
// belong to the overlay the caller runs on the returned PacketConn.
type Config struct {
	// ServerURL is the rendezvous base URL (e.g. https://host/realm or
	// http://host:9443). The control client appends /v1/{realmID}/…
	ServerURL string
	// Token is the realm bearer credential (per-egress shared).
	Token string
	// STUNServers are host:port (IP recommended) STUN endpoints, ≥1.
	STUNServers []string
	// Resolver resolves STUN hostnames; required (pass a DNS-backed resolver).
	Resolver Resolver
	// HTTPClient talks to the rendezvous. If nil, http.DefaultClient is used;
	// in sing-box this is the managed realm http client (h2/h3 transport).
	HTTPClient *http.Client
	// Dialer opens the local UDP sockets used for STUN + punching. If nil, a
	// plain net.ListenUDP on the unspecified address is used.
	Dialer N.Dialer
	// Logger is optional.
	Logger logger.Logger
}

// PunchedConn is the result of a successful Punch: a raw UDP PacketConn with a
// hole open to PeerAddr. The overlay protocol runs directly on this.
type PunchedConn struct {
	net.PacketConn
	// PeerAddr is the punched peer endpoint (where the overlay should dial).
	PeerAddr M.Socksaddr
}

// Punch performs the full client-side rendezvous + hole-punch for realmID and
// returns a raw, punched PacketConn. On failure the caller falls back to relay
// (out of scope here) or retries; all sockets are closed before returning an
// error.
//
// Flow (mirrors sing-quic hysteria2 client.go offerNewRealm, QUIC/obfs removed):
//  1. open v4 + v6 UDP sockets ("families");
//  2. STUN-discover each family's reflexive candidates;
//  3. control.Connect — push our candidates, get the peer's + shared nonce/obfs;
//  4. race-punch across families; the first to open a hole wins;
//  5. return the winning socket (others closed).
func Punch(ctx context.Context, cfg Config, realmID string) (*PunchedConn, error) {
	if realmID == "" {
		return nil, E.New("realm: realm ID is required")
	}
	if len(cfg.STUNServers) == 0 {
		return nil, E.New("realm: at least one STUN server is required")
	}
	if cfg.Resolver == nil {
		return nil, E.New("realm: resolver is required")
	}
	control, err := squic.NewControlClient(cfg.ServerURL, cfg.Token, cfg.HTTPClient)
	if err != nil {
		return nil, err
	}

	families, err := openFamilies(ctx, cfg)
	if err != nil {
		return nil, err
	}

	surviving, localAddresses, err := discoverFamilies(ctx, cfg, families)
	if err != nil {
		return nil, err // discoverFamilies closed all sockets on error
	}
	closeSurviving := func() {
		for _, f := range surviving {
			_ = f.conn.Close()
		}
	}

	metadata, err := squic.GeneratePunchMetadata()
	if err != nil {
		closeSurviving()
		return nil, E.Cause(err, "generate punch metadata")
	}

	response, err := control.Connect(ctx, realmID, localAddresses, metadata)
	if err != nil {
		closeSurviving()
		return nil, E.Cause(err, "realm connect")
	}

	winner, result, err := racePunch(ctx, surviving, response.Addresses, response.PunchMetadata)
	if err != nil {
		return nil, err // racePunch closed all sockets on error
	}
	return &PunchedConn{
		PacketConn: winner.conn,
		PeerAddr:   M.SocksaddrFromNetIP(result.PeerAddr),
	}, nil
}

// familyConn is one address-family UDP socket plus its discovered candidates.
type familyConn struct {
	family         string
	ipv4           bool
	conn           net.PacketConn
	localAddresses []netip.AddrPort
}

func openFamilies(ctx context.Context, cfg Config) ([]*familyConn, error) {
	specs := []struct {
		family string
		ipv4   bool
		addr   M.Socksaddr
	}{
		{"v4", true, M.SocksaddrFrom(netip.IPv4Unspecified(), 0)},
		{"v6", false, M.SocksaddrFrom(netip.IPv6Unspecified(), 0)},
	}
	conns := make([]*familyConn, len(specs))
	listenErrs := make([]error, len(specs))
	var wg sync.WaitGroup
	for i, spec := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, listenErr := listenPacket(ctx, cfg, spec.addr)
			if listenErr != nil {
				listenErrs[i] = E.Cause(listenErr, spec.family)
				return
			}
			conns[i] = &familyConn{family: spec.family, ipv4: spec.ipv4, conn: conn}
		}()
	}
	wg.Wait()
	var families []*familyConn
	var errs []error
	for i, f := range conns {
		if f != nil {
			families = append(families, f)
			continue
		}
		errs = append(errs, listenErrs[i])
	}
	if len(families) == 0 {
		return nil, E.Cause(E.Errors(errs...), "listen UDP for realm")
	}
	return families, nil
}

func listenPacket(ctx context.Context, cfg Config, addr M.Socksaddr) (net.PacketConn, error) {
	if cfg.Dialer != nil {
		return cfg.Dialer.ListenPacket(ctx, addr)
	}
	return net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr.AddrPort()))
}

func discoverFamilies(ctx context.Context, cfg Config, families []*familyConn) ([]*familyConn, []netip.AddrPort, error) {
	var needIPv4, needIPv6 bool
	for _, f := range families {
		if f.ipv4 {
			needIPv4 = true
		} else {
			needIPv6 = true
		}
	}
	stunServers, err := squic.ResolveSTUNServers(ctx, cfg.STUNServers, cfg.Resolver, needIPv4, needIPv6)
	if err != nil {
		for _, f := range families {
			_ = f.conn.Close()
		}
		return nil, nil, E.Cause(err, "resolve STUN servers")
	}
	type discoverResult struct {
		addrs []netip.AddrPort
		err   error
	}
	results := make([]discoverResult, len(families))
	var wg sync.WaitGroup
	for i, f := range families {
		wg.Add(1)
		go func() {
			defer wg.Done()
			servers := make([]netip.AddrPort, 0, len(stunServers))
			for _, server := range stunServers {
				if server.Addr().Is4() == f.ipv4 {
					servers = append(servers, server)
				}
			}
			addrs, discoverErr := squic.Discover(ctx, f.conn, servers)
			results[i] = discoverResult{addrs: addrs, err: discoverErr}
		}()
	}
	wg.Wait()
	var surviving []*familyConn
	var union []netip.AddrPort
	var errs []error
	for i, f := range families {
		result := results[i]
		if result.err != nil {
			errs = append(errs, E.Cause(result.err, f.family))
			_ = f.conn.Close()
			continue
		}
		f.localAddresses = result.addrs
		surviving = append(surviving, f)
		union = append(union, result.addrs...)
	}
	if len(surviving) == 0 {
		return nil, nil, E.Cause(E.Errors(errs...), "realm STUN discovery")
	}
	return surviving, union, nil
}

func racePunch(
	ctx context.Context,
	families []*familyConn,
	peerAddresses []netip.AddrPort,
	metadata squic.PunchMetadata,
) (*familyConn, squic.PunchResult, error) {
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()
	type outcome struct {
		family *familyConn
		result squic.PunchResult
		err    error
	}
	out := make(chan outcome, len(families))
	for _, family := range families {
		go func() {
			peers := make([]netip.AddrPort, 0, len(peerAddresses))
			for _, peer := range peerAddresses {
				if peer.Addr().Is4() == family.ipv4 {
					peers = append(peers, peer)
				}
			}
			punchResult, punchErr := squic.Punch(raceCtx, family.conn, peers, metadata)
			out <- outcome{family: family, result: punchResult, err: punchErr}
		}()
	}
	var errs []error
	for pending := len(families); pending > 0; pending-- {
		result := <-out
		if result.err == nil {
			for _, family := range families {
				if family != result.family {
					_ = family.conn.Close()
				}
			}
			return result.family, result.result, nil
		}
		errs = append(errs, E.Cause(result.err, result.family.family))
	}
	for _, family := range families {
		_ = family.conn.Close()
	}
	return nil, squic.PunchResult{}, E.Cause(E.Errors(errs...), "realm punch")
}
