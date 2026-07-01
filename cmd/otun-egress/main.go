// Command otun-egress is the UNIFIED OTun egress node: one binary that runs any
// of the six over-realm protocols (hysteria2 / tuic / reality / trojan /
// shadowsocks / vmess) selected by the config's "protocol" field. It folds in
// the three node packages cmd/otun-node already unified (trojan/ss/vmess) plus
// hy2node, tuicnode, and realitynode, so a fleet of egress nodes is N copies of
// ONE binary + N config files (one systemd template instance per realm slot).
//
// This is the deploy-package foundation: instead of scp-ing five different
// binaries to /tmp, ship one otun-egress and a per-slot JSON. Each protocol's
// engine is still reused from sing as a library (no fork).
//
// Build: needs uTLS for Reality, so build with the with_utls tag:
//
//	go build -tags with_utls -o otun-egress ./cmd/otun-egress
//
// Config JSON (fields not relevant to the chosen protocol are ignored):
//
//	{
//	  "protocol": "hysteria2",  // hysteria2|tuic|reality|trojan|shadowsocks|vmess
//	  "server_url": "http://otun-s:9443",
//	  "token": "<realm token>",
//	  "realm_id": "m1-hy2-out",
//	  "stun_servers": ["74.125.250.129:19302","162.159.207.0:3478"],
//	  "listen": ":51820",
//	  "password": "<hy2/tuic/trojan/ss password>",
//	  "method": "aes-128-gcm",     // shadowsocks
//	  "uuid": "<tuic/vmess/reality uuid>",
//	  "sni": "iptv.local",         // hy2/tuic TLS server name (default iptv.local)
//	  "alpn": ["h3"],              // hy2/tuic ALPN (default ["h3"])
//	  "congestion_control": "cubic", // tuic (default cubic)
//	  "private_key": "<reality x25519 private, base64url>",  // reality
//	  "short_id": "0123456789abcdef",                        // reality
//	  "server_name": "www.apple.com",                        // reality borrowed SNI
//	  "handshake_server": "<reality handshake IP>",          // reality (IP, not domain)
//	  "handshake_port": 443                                  // reality (default 443)
//	}
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
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

// rendezvous is one control-plane registration target. A node registers to
// exactly one rendezvous per UDP socket (the realm wire protocol is
// single-realm_id / single-session by design). To survive a rendezvous VPS
// failing, list MORE THAN ONE here: the binary then runs one independent
// egress node per rendezvous (each its own socket + realm.Server), all sharing
// the same protocol + credentials + egress. Client outbounds can point at any
// listed rendezvous; if one VPS dies, the same egress stays reachable via the
// others (problem 1A: rendezvous-VPS failover).
type rendezvous struct {
	ServerURL   string   `json:"server_url"`
	Token       string   `json:"token"`
	RealmID     string   `json:"realm_id"`
	STUNServers []string `json:"stun_servers"`
	Listen      string   `json:"listen"` // local UDP bind for THIS rendezvous; ":0" if empty
}

type config struct {
	Protocol string `json:"protocol"`

	// Single-rendezvous form (back-compat with the per-protocol node configs):
	// server_url / token / realm_id / stun_servers / listen at the top level.
	ServerURL   string   `json:"server_url"`
	Token       string   `json:"token"`
	RealmID     string   `json:"realm_id"`
	STUNServers []string `json:"stun_servers"`
	Listen      string   `json:"listen"`

	// Multi-rendezvous form (problem 1A failover): when non-empty, this REPLACES
	// the top-level server_url/token/realm_id/stun_servers/listen and the binary
	// starts one node per entry. Each entry needs its OWN listen port.
	Rendezvous []rendezvous `json:"rendezvous"`

	// Shared / protocol-specific.
	Password          string   `json:"password"`           // hy2/tuic/trojan/ss
	Method            string   `json:"method"`             // ss
	UUID              string   `json:"uuid"`               // tuic/vmess/reality
	SNI               string   `json:"sni"`                // hy2/tuic TLS server name
	ALPN              []string `json:"alpn"`               // hy2/tuic ALPN
	CongestionControl string   `json:"congestion_control"` // tuic

	// Reality.
	PrivateKey      string `json:"private_key"`
	ShortID         string `json:"short_id"`
	ServerName      string `json:"server_name"`
	HandshakeServer string `json:"handshake_server"`
	HandshakePort   uint16 `json:"handshake_port"`
}

// starter abstracts every node package: they all share Start/Close shapes.
type starter interface {
	Start(ctx context.Context, conn net.PacketConn) error
	Close() error
}

func main() {
	cfgPath := flag.String("config", "node.json", "path to config JSON")
	flag.Parse()
	cfg := loadConfig(*cfgPath)

	ctx := context.Background()
	var lg logger.ContextLogger = stderrLogger{}

	// Normalize to a list: multi-rendezvous (failover) form takes precedence;
	// otherwise wrap the single top-level rendezvous fields into one entry.
	rdvs := cfg.Rendezvous
	if len(rdvs) == 0 {
		rdvs = []rendezvous{{
			ServerURL: cfg.ServerURL, Token: cfg.Token, RealmID: cfg.RealmID,
			STUNServers: cfg.STUNServers, Listen: cfg.Listen,
		}}
	}

	nodes := make([]starter, 0, len(rdvs))
	for i, rdv := range rdvs {
		node := buildNode(ctx, lg, cfg, rdv)
		listen := rdv.Listen
		if listen == "" {
			listen = ":0"
		}
		udpAddr, err := net.ResolveUDPAddr("udp", listen)
		if err != nil {
			log.Fatalf("rendezvous[%d] resolve listen %q: %v", i, listen, err)
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			log.Fatalf("rendezvous[%d] listen udp %q: %v", i, listen, err)
		}
		if err := node.Start(ctx, conn); err != nil {
			// Failover semantics: one rendezvous being down must NOT take the
			// whole egress offline. Log and keep the others.
			lg.Error("rendezvous[", i, "] start (server=", rdv.ServerURL, " realm=", rdv.RealmID, "): ", err)
			_ = conn.Close()
			continue
		}
		log.Printf("OTun egress node started: protocol=%s realm=%s server=%s local=%s",
			cfg.Protocol, rdv.RealmID, rdv.ServerURL, conn.LocalAddr())
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		log.Fatalf("no rendezvous registrations succeeded (all %d failed)", len(rdvs))
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Print("shutting down")
	for _, n := range nodes {
		_ = n.Close()
	}
}

func buildNode(ctx context.Context, lg logger.ContextLogger, cfg config, rdv rendezvous) starter {
	hc := &http.Client{}
	switch cfg.Protocol {
	case "hysteria2":
		sni, alpn := tlsParams(cfg)
		node, err := hy2node.New(hy2node.Options{
			ServerURL: rdv.ServerURL, Token: rdv.Token, RealmID: rdv.RealmID,
			STUNServers: rdv.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			TLSConfig: buildServerTLS(ctx, lg, sni, alpn), Password: cfg.Password, Logger: lg,
		})
		fatalIf(err)
		return node

	case "tuic":
		sni, alpn := tlsParams(cfg)
		userUUID, err := uuid.FromString(cfg.UUID)
		if err != nil {
			log.Fatalf("parse uuid: %v", err)
		}
		node, err := tuicnode.New(tuicnode.Options{
			ServerURL: rdv.ServerURL, Token: rdv.Token, RealmID: rdv.RealmID,
			STUNServers: rdv.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			TLSConfig: buildServerTLS(ctx, lg, sni, alpn), UUID: userUUID,
			Password: cfg.Password, CongestionControl: cfg.CongestionControl, Logger: lg,
		})
		fatalIf(err)
		return node

	case "reality":
		hp := cfg.HandshakePort
		if hp == 0 {
			hp = 443
		}
		node, err := realitynode.New(realitynode.Options{
			ServerURL: rdv.ServerURL, Token: rdv.Token, RealmID: rdv.RealmID,
			STUNServers: rdv.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			WrapTLS: buildWrapServerTLS(ctx, lg),
			Reality: buildRealityServer(ctx, lg, cfg, hp),
			UUID:    cfg.UUID,
			Handler: egressHandler{lg: lg}.egress, Logger: lg,
		})
		fatalIf(err)
		return node

	case "trojan":
		node, err := trojannode.New(trojannode.Options{
			ServerURL: rdv.ServerURL, Token: rdv.Token, RealmID: rdv.RealmID,
			STUNServers: rdv.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			WrapTLS: buildWrapServerTLS(ctx, lg), Password: cfg.Password,
			Handler: trojannode.ConnHandler(egressHandler{lg: lg}.egress), Logger: lg,
		})
		fatalIf(err)
		return node

	case "shadowsocks":
		node, err := ssnode.New(ssnode.Options{
			ServerURL: rdv.ServerURL, Token: rdv.Token, RealmID: rdv.RealmID,
			STUNServers: rdv.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			WrapTLS: buildWrapServerTLS(ctx, lg), Method: cfg.Method, Password: cfg.Password,
			Handler: ssnode.ConnHandler(egressHandler{lg: lg}.egress), Logger: lg,
		})
		fatalIf(err)
		return node

	case "vmess":
		node, err := vmessnode.New(vmessnode.Options{
			ServerURL: rdv.ServerURL, Token: rdv.Token, RealmID: rdv.RealmID,
			STUNServers: rdv.STUNServers, Resolver: systemResolver, HTTPClient: hc,
			WrapTLS: buildWrapServerTLS(ctx, lg), UUID: cfg.UUID,
			Handler: vmessnode.Handler(egressHandler{lg: lg}.egress), Logger: lg,
		})
		fatalIf(err)
		return node

	default:
		log.Fatalf("unknown protocol %q (want hysteria2|tuic|reality|trojan|shadowsocks|vmess)", cfg.Protocol)
		return nil
	}
}

func tlsParams(cfg config) (sni string, alpn []string) {
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

func fatalIf(err error) {
	if err != nil {
		log.Fatalf("build node: %v", err)
	}
}

// egressHandler dials the proxied destination on the open internet and pipes
// both ways. Used by reality/trojan/ss/vmess (hy2/tuic have egress built in).
type egressHandler struct{ lg logger.ContextLogger }

func (h egressHandler) egress(ctx context.Context, conn net.Conn, destination M.Socksaddr) {
	defer conn.Close()
	out, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", destination.String())
	if err != nil {
		h.lg.Warn("egress dial ", destination, ": ", err)
		return
	}
	defer out.Close()
	h.lg.Info("egress -> ", destination)
	// Downstream (target->client) MUST fully flush before closing conn, else a
	// fast client half-close races the response (cmd/otun-node egress race fix).
	up := make(chan struct{})
	go func() { io.Copy(out, conn); _ = out.Close(); close(up) }()
	io.Copy(conn, out)
	<-up
}

func loadConfig(path string) config {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	var c config
	if err := json.Unmarshal(data, &c); err != nil {
		log.Fatalf("parse config: %v", err)
	}
	return c
}

// buildServerTLS builds a plain self-signed TLS server (hy2/tuic).
func buildServerTLS(ctx context.Context, lg logger.ContextLogger, sni string, alpn []string) sbtls.ServerConfig {
	certPEM, keyPEM := selfSignedCert(sni)
	tlsCfg, err := sbtls.NewSTDServer(ctx, lg, option.InboundTLSOptions{
		Enabled: true, ServerName: sni, ALPN: alpn,
		Certificate: []string{certPEM}, Key: []string{keyPEM},
	})
	if err != nil {
		log.Fatalf("build server tls: %v", err)
	}
	if err := tlsCfg.Start(); err != nil {
		log.Fatalf("start server tls: %v", err)
	}
	return tlsCfg
}

// buildWrapServerTLS builds the outer WrapStream (QUIC) TLS for the TCP-family
// protocols (reality/trojan/ss/vmess).
func buildWrapServerTLS(ctx context.Context, lg logger.ContextLogger) sbtls.ServerConfig {
	certPEM, keyPEM := selfSignedCert("wrap.local")
	cfg, err := sbtls.NewSTDServer(ctx, lg, option.InboundTLSOptions{
		Enabled: true, ServerName: "wrap.local", ALPN: []string{"h3"},
		Certificate: []string{certPEM}, Key: []string{keyPEM},
	})
	if err != nil {
		log.Fatalf("wrap tls: %v", err)
	}
	if err := cfg.Start(); err != nil {
		log.Fatalf("wrap tls start: %v", err)
	}
	return cfg
}

// buildRealityServer builds the inner Reality TLS server (borrowed-SNI handshake).
func buildRealityServer(ctx context.Context, lg logger.ContextLogger, cfg config, handshakePort uint16) sbtls.ServerConfig {
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
		log.Fatalf("reality server tls: %v", err)
	}
	if err := rc.Start(); err != nil {
		log.Fatalf("reality server start: %v", err)
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

type stderrLogger struct{}

func (stderrLogger) Trace(a ...any)                             { log.Print(append([]any{"[trace] "}, a...)...) }
func (stderrLogger) Debug(a ...any)                             { log.Print(append([]any{"[debug] "}, a...)...) }
func (stderrLogger) Info(a ...any)                              { log.Print(append([]any{"[info] "}, a...)...) }
func (stderrLogger) Warn(a ...any)                              { log.Print(append([]any{"[warn] "}, a...)...) }
func (stderrLogger) Error(a ...any)                             { log.Print(append([]any{"[error] "}, a...)...) }
func (stderrLogger) Fatal(a ...any)                             { log.Fatal(a...) }
func (stderrLogger) Panic(a ...any)                             { log.Panic(a...) }
func (l stderrLogger) TraceContext(_ context.Context, a ...any) { l.Trace(a...) }
func (l stderrLogger) DebugContext(_ context.Context, a ...any) { l.Debug(a...) }
func (l stderrLogger) InfoContext(_ context.Context, a ...any)  { l.Info(a...) }
func (l stderrLogger) WarnContext(_ context.Context, a ...any)  { l.Warn(a...) }
func (l stderrLogger) ErrorContext(_ context.Context, a ...any) { l.Error(a...) }
func (l stderrLogger) FatalContext(_ context.Context, a ...any) { l.Fatal(a...) }
func (l stderrLogger) PanicContext(_ context.Context, a ...any) { l.Panic(a...) }
