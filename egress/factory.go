package egress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	// Logger is optional; a NOP logger is used when nil.
	Logger logger.ContextLogger
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

	switch cfg.Protocol {
	case "hysteria2":
		sni, alpn := tlsParams(cfg)
		return hy2node.New(hy2node.Options{
			ServerURL: cfg.ServerURL, Token: cfg.Token, RealmID: cfg.RealmID,
			STUNServers: cfg.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			TLSConfig: buildServerTLS(ctx, lg, sni, alpn, cfg.CertPEM, cfg.KeyPEM), Password: cfg.Password,
			ObfsPassword: cfg.ObfsPassword, Logger: lg,
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
			Password: cfg.Password, CongestionControl: cfg.CongestionControl, Logger: lg,
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
			Handler: egressPipe{lg: lg}.egress, Logger: lg,
		})

	case "trojan":
		return trojannode.New(trojannode.Options{
			ServerURL: cfg.ServerURL, Token: cfg.Token, RealmID: cfg.RealmID,
			STUNServers: cfg.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			WrapTLS: buildWrapServerTLS(ctx, lg), Password: cfg.Password,
			Handler: trojannode.ConnHandler(egressPipe{lg: lg}.egress), Logger: lg,
		})

	case "shadowsocks":
		return ssnode.New(ssnode.Options{
			ServerURL: cfg.ServerURL, Token: cfg.Token, RealmID: cfg.RealmID,
			STUNServers: cfg.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			WrapTLS: buildWrapServerTLS(ctx, lg), Method: cfg.Method, Password: cfg.Password,
			Handler: ssnode.ConnHandler(egressPipe{lg: lg}.egress), Logger: lg,
		})

	case "vmess":
		return vmessnode.New(vmessnode.Options{
			ServerURL: cfg.ServerURL, Token: cfg.Token, RealmID: cfg.RealmID,
			STUNServers: cfg.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			WrapTLS: buildWrapServerTLS(ctx, lg), UUID: cfg.UUID,
			Handler: vmessnode.Handler(egressPipe{lg: lg}.egress), Logger: lg,
		})

	default:
		return nil, errUnknownProtocol(cfg.Protocol)
	}
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
