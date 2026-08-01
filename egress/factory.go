package egress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/antsbtw/otun-s-egress/node/hy2node"
	"github.com/antsbtw/otun-s-egress/node/punchtrace"
	"github.com/antsbtw/otun-s-egress/node/realitynode"
	"github.com/antsbtw/otun-s-egress/node/ssnode"
	"github.com/antsbtw/otun-s-egress/node/trojannode"
	"github.com/antsbtw/otun-s-egress/node/tuicnode"
	"github.com/antsbtw/otun-s-egress/node/vmessnode"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/gofrs/uuid/v5"

	squic "github.com/antsbtw/sing-quic/hysteria2/realm"
)

// Config selects and parameterizes one egress node. Rendezvous coordinates plus
// the chosen protocol's credentials; irrelevant fields are ignored. This is the
// single struct realm-agent fills (scheme 甲) — it replaces the per-protocol
// node Options and hides the TLS/cert wiring.
type Config struct {
	Protocol string // hysteria2 | tuic | reality | trojan | shadowsocks | vmess

	// Rendezvous.
	ServerURL   string
	Token       string
	RealmID     string
	STUNServers []string

	// RendezvousInsecureTLS skips TLS certificate verification when the egress
	// connects to the rendezvous (会合面). Needed when the rendezvous serves a
	// self-signed cert (pure-IP deployment, no public CA). Default false = verify.
	// NOTE: this is the CONTROL channel to the rendezvous only; it does NOT affect
	// the punched data-plane tunnel's own TLS.
	RendezvousInsecureTLS bool

	// Credentials (protocol-specific).
	Password          string   // hy2/tuic/trojan/ss
	ObfsPassword      string   // hy2 salamander obfs (empty = disabled); must match client's ?obfs=
	Method            string   // ss
	UUID              string   // tuic/vmess/reality
	SNI               string   // hy2/tuic TLS server name (default iptv.local)
	ALPN              []string // hy2/tuic ALPN (default ["h3"])
	CongestionControl string   // tuic

	// Reality.
	PrivateKey      string
	ShortID         string
	ServerName      string
	HandshakeServer string
	HandshakePort   uint16

	// CertPEM/KeyPEM optionally inject a STABLE leaf TLS cert (B.3): when both are
	// set they are used instead of a fresh per-start self-signed cert, so the
	// leaf fingerprint survives restarts (matters only if the client pins it; with
	// insecure client TLS this is not required). Applies to the hy2/tuic outer TLS.
	CertPEM string
	KeyPEM  string

	// Meter optionally injects a SHARED registry (C.1). When set, the built node
	// meters/kicks/snapshots through it instead of a private one — so several
	// protocol nodes given the same *Registry present one unified billing/kick/
	// snapshot surface. Nil keeps the back-compat private-meter behavior. Prefer
	// NewShared for the common "six protocols, one node" case.
	Meter *Registry

	// Logger is optional; a NOP logger is used when nil.
	Logger logger.ContextLogger

	// PunchTraceSink optionally turns on receiver-side punch tracing: when
	// non-nil, every finished punch answer attempt is assembled into a
	// punchtrace.Record (node/punchtrace) and handed to this sink — the H1
	// (one-way false success) measurement. Nil — the production default —
	// leaves the punch engine unobserved.
	PunchTraceSink punchtrace.Sink
}

// New builds (does not Start) an egress Node for cfg.Protocol. TLS is a
// self-signed PoC cert; supply real certs by extending this factory. The
// returned Node is driven via UpdateUsers/CollectStats/KickUser (scheme 甲).
func New(cfg Config) (Node, error) {
	ctx := context.Background()
	lg := cfg.Logger
	if lg == nil {
		lg = logger.NOP()
	}
	hc := &http.Client{}
	if cfg.RendezvousInsecureTLS {
		// Clone DefaultTransport (not a bare &http.Transport{}) so we keep its
		// ForceAttemptHTTP2/timeout defaults — a bare Transport would silently
		// drop h2 ALPN negotiation with the rendezvous. Flip only the verify bit.
		tr := http.DefaultTransport.(*http.Transport).Clone()
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		tr.TLSClientConfig.InsecureSkipVerify = true
		hc = &http.Client{Transport: tr}
	}
	// Declared as the interface (not *punchtrace.Observer) so a nil sink yields
	// a genuinely nil interface — the engine's observer != nil gate stays false.
	var punchObserver squic.PunchObserver
	if cfg.PunchTraceSink != nil {
		punchObserver = punchtrace.New(cfg.Protocol, cfg.PunchTraceSink)
	}

	switch cfg.Protocol {
	case "hysteria2":
		sni, alpn := tlsParams(cfg)
		return hy2node.New(hy2node.Options{
			ServerURL: cfg.ServerURL, Token: cfg.Token, RealmID: cfg.RealmID,
			STUNServers: cfg.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			TLSConfig: buildServerTLS(ctx, lg, sni, alpn, cfg.CertPEM, cfg.KeyPEM), Password: cfg.Password,
			ObfsPassword: cfg.ObfsPassword, Meter: cfg.Meter, Logger: lg,
			PunchObserver: punchObserver,
		})

	case "tuic":
		sni, alpn := tlsParams(cfg)
		userUUID, err := uuid.FromString(cfg.UUID)
		if err != nil {
			return nil, err
		}
		return tuicnode.New(tuicnode.Options{
			ServerURL: cfg.ServerURL, Token: cfg.Token, RealmID: cfg.RealmID,
			STUNServers: cfg.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			TLSConfig: buildServerTLS(ctx, lg, sni, alpn, cfg.CertPEM, cfg.KeyPEM), UUID: userUUID,
			Password: cfg.Password, CongestionControl: cfg.CongestionControl, Meter: cfg.Meter, Logger: lg,
			PunchObserver: punchObserver,
		})

	case "reality":
		hp := cfg.HandshakePort
		if hp == 0 {
			hp = 443
		}
		return realitynode.New(realitynode.Options{
			ServerURL: cfg.ServerURL, Token: cfg.Token, RealmID: cfg.RealmID,
			STUNServers: cfg.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			WrapTLS: buildWrapServerTLS(ctx, lg),
			Reality: buildRealityServer(ctx, lg, cfg, hp),
			UUID:    cfg.UUID,
			Meter:   cfg.Meter,
			Handler: egressPipe{lg: lg}.egress, Logger: lg,
			PunchObserver: punchObserver,
		})

	case "trojan":
		return trojannode.New(trojannode.Options{
			ServerURL: cfg.ServerURL, Token: cfg.Token, RealmID: cfg.RealmID,
			STUNServers: cfg.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			WrapTLS: buildWrapServerTLS(ctx, lg), Password: cfg.Password, Meter: cfg.Meter,
			Handler: trojannode.ConnHandler(egressPipe{lg: lg}.egress), Logger: lg,
			PunchObserver: punchObserver,
		})

	case "shadowsocks":
		return ssnode.New(ssnode.Options{
			ServerURL: cfg.ServerURL, Token: cfg.Token, RealmID: cfg.RealmID,
			STUNServers: cfg.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			WrapTLS: buildWrapServerTLS(ctx, lg), Method: cfg.Method, Password: cfg.Password, Meter: cfg.Meter,
			Handler: ssnode.ConnHandler(egressPipe{lg: lg}.egress), Logger: lg,
			PunchObserver: punchObserver,
		})

	case "vmess":
		return vmessnode.New(vmessnode.Options{
			ServerURL: cfg.ServerURL, Token: cfg.Token, RealmID: cfg.RealmID,
			STUNServers: cfg.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			WrapTLS: buildWrapServerTLS(ctx, lg), UUID: cfg.UUID, Meter: cfg.Meter,
			Handler: vmessnode.Handler(egressPipe{lg: lg}.egress), Logger: lg,
			PunchObserver: punchObserver,
		})

	default:
		return nil, errUnknownProtocol(cfg.Protocol)
	}
}

// NewShared builds one Node per Config, all SHARING a single meter Registry
// (C.1): the "one physical node, six protocols" layout. It returns the built
// nodes (index-aligned with cfgs) and the shared Registry. Operate on that one
// Registry and it covers every returned node at once:
//
//	nodes, reg, err := egress.NewShared(cfgs)   // six protocol Configs
//	// … Start each node …
//	stats := reg.CollectStats(true)   // per-UUID totals summed across all six
//	reg.KickUser(uuid)                // drops the UUID on ALL six protocols
//	conns := reg.Snapshot()           // every live conn; ConnInfo.Protocol tags it
//
// Each Config's own Meter field is overridden with the shared Registry; usermap
// stays per-node (each protocol keeps its own index space). If any Config fails
// to build, the already-built nodes are Closed and the error is returned.
func NewShared(cfgs []Config) ([]Node, *Registry, error) {
	reg := NewRegistry()
	nodes := make([]Node, 0, len(cfgs))
	for _, cfg := range cfgs {
		cfg.Meter = reg
		n, err := New(cfg)
		if err != nil {
			for _, built := range nodes {
				_ = built.Close()
			}
			return nil, nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, reg, nil
}

type unknownProtocolError string

func (e unknownProtocolError) Error() string {
	return "egress: unknown protocol " + string(e) + " (want hysteria2|tuic|reality|trojan|shadowsocks|vmess)"
}
func errUnknownProtocol(p string) error { return unknownProtocolError(p) }

func tlsParams(cfg Config) (sni string, alpn []string) {
	sni = cfg.SNI
	if sni == "" {
		sni = "iptv.local"
	}
	alpn = cfg.ALPN
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	return
}

// egressPipe dials the proxied destination and pipes both ways. Used by the
// TCP-family protocols (reality/trojan/ss/vmess); hy2/tuic egress out directly.
type egressPipe struct{ lg logger.ContextLogger }

func (h egressPipe) egress(ctx context.Context, conn net.Conn, destination M.Socksaddr) {
	defer conn.Close()
	out, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", destination.String())
	if err != nil {
		h.lg.Warn("egress dial ", destination, ": ", err)
		return
	}
	defer out.Close()
	// Downstream (target->client) must fully flush before closing conn, else a
	// fast client half-close races the response (egress race fix).
	up := make(chan struct{})
	go func() { io.Copy(out, conn); _ = out.Close(); close(up) }()
	io.Copy(conn, out)
	<-up
}

func buildServerTLS(ctx context.Context, lg logger.ContextLogger, sni string, alpn []string, injectedCert, injectedKey string) sbtls.ServerConfig {
	certPEM, keyPEM := injectedCert, injectedKey
	if certPEM == "" || keyPEM == "" {
		certPEM, keyPEM = selfSignedCert(sni) // B.3: fall back to a fresh self-signed cert
	}
	cfg, err := sbtls.NewSTDServer(ctx, lg, option.InboundTLSOptions{
		Enabled: true, ServerName: sni, ALPN: alpn,
		Certificate: []string{certPEM}, Key: []string{keyPEM},
	})
	if err != nil {
		panic(err)
	}
	if err := cfg.Start(); err != nil {
		panic(err)
	}
	return cfg
}

func buildWrapServerTLS(ctx context.Context, lg logger.ContextLogger) sbtls.ServerConfig {
	certPEM, keyPEM := selfSignedCert("wrap.local")
	cfg, err := sbtls.NewSTDServer(ctx, lg, option.InboundTLSOptions{
		Enabled: true, ServerName: "wrap.local", ALPN: []string{"h3"},
		Certificate: []string{certPEM}, Key: []string{keyPEM},
	})
	if err != nil {
		panic(err)
	}
	if err := cfg.Start(); err != nil {
		panic(err)
	}
	return cfg
}

func buildRealityServer(ctx context.Context, lg logger.ContextLogger, cfg Config, handshakePort uint16) sbtls.ServerConfig {
	rc, err := sbtls.NewServer(ctx, lg, option.InboundTLSOptions{
		Enabled:    true,
		ServerName: cfg.ServerName,
		Reality: &option.InboundRealityOptions{
			Enabled: true,
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     cfg.HandshakeServer,
					ServerPort: handshakePort,
				},
			},
			PrivateKey: cfg.PrivateKey,
			ShortID:    []string{cfg.ShortID},
		},
	})
	if err != nil {
		panic(err)
	}
	if err := rc.Start(); err != nil {
		panic(err)
	}
	return rc
}

func selfSignedCert(host string) (string, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func systemResolver(ctx context.Context, host string, _, _ bool) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
