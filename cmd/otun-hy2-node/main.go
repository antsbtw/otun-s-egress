// Command otun-hy2-node runs an OTun Hysteria2 egress node: it registers on an
// OTun-S rendezvous, answers hole punches, and serves Hysteria2 over the punched
// hole, exiting proxied traffic out this host's IP.
//
// Unlike the other egress binaries, Hy2 needs no OTun-specific server glue:
// sing-quic's hysteria2.Service has built-in realm support. This binary exists
// so the six-protocol reference system has a uniform, same-shape egress for Hy2
// too (mirrors cmd/otun-tuic-node; Hy2 is password-only, so there is no uuid).
//
// Config is JSON:
//
//	{
//	  "server_url": "http://otun-s-host:9443",
//	  "token": "<realm token>",
//	  "realm_id": "m1-hy2",
//	  "stun_servers": ["74.125.250.129:19302","162.159.207.0:3478"],
//	  "password": "hy2-pw",
//	  "sni": "iptv.local",
//	  "alpn": ["h3"]
//	}
//
// TLS uses an in-memory self-signed cert for CN=<sni> (PoC; the client dials
// with insecure=true). For production, supply real cert/key.
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

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

type config struct {
	ServerURL   string   `json:"server_url"`
	Token       string   `json:"token"`
	RealmID     string   `json:"realm_id"`
	STUNServers []string `json:"stun_servers"`
	Password    string   `json:"password"`
	SNI         string   `json:"sni"`
	ALPN        []string `json:"alpn"`
	Listen      string   `json:"listen"` // local UDP bind, default ":0"
}

func main() {
	cfgPath := flag.String("config", "node.json", "path to node config JSON")
	flag.Parse()

	cfg := loadConfig(*cfgPath)
	if cfg.SNI == "" {
		cfg.SNI = "iptv.local"
	}
	if len(cfg.ALPN) == 0 {
		cfg.ALPN = []string{"h3"}
	}

	var stdLog logger.ContextLogger = stderrLogger{}

	ctx := context.Background()
	tlsServer := buildServerTLS(ctx, cfg, stdLog)

	node, err := hy2node.New(hy2node.Options{
		ServerURL:   cfg.ServerURL,
		Token:       cfg.Token,
		RealmID:     cfg.RealmID,
		STUNServers: cfg.STUNServers,
		Resolver:    systemResolver,
		HTTPClient:  &http.Client{},
		TLSConfig:   tlsServer,
		Password:    cfg.Password,
		Logger:      stdLog,
	})
	if err != nil {
		log.Fatalf("build node: %v", err)
	}

	listen := cfg.Listen
	if listen == "" {
		listen = ":0"
	}
	udpAddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		log.Fatalf("resolve listen: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("listen udp: %v", err)
	}

	if err := node.Start(ctx, conn); err != nil {
		log.Fatalf("start node: %v", err)
	}
	log.Printf("OTun Hysteria2 egress node started: realm=%s server=%s local=%s",
		cfg.RealmID, cfg.ServerURL, conn.LocalAddr())

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Print("shutting down")
	_ = node.Close()
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

func buildServerTLS(ctx context.Context, cfg config, lg logger.ContextLogger) sbtls.ServerConfig {
	certPEM, keyPEM := selfSignedCert(cfg.SNI)
	tlsCfg, err := sbtls.NewSTDServer(ctx, lg, option.InboundTLSOptions{
		Enabled:     true,
		ServerName:  cfg.SNI,
		ALPN:        cfg.ALPN,
		Certificate: []string{certPEM},
		Key:         []string{keyPEM},
	})
	if err != nil {
		log.Fatalf("build server tls: %v", err)
	}
	if err := tlsCfg.Start(); err != nil {
		log.Fatalf("start server tls: %v", err)
	}
	return tlsCfg
}

func selfSignedCert(host string) (certPEM, keyPEM string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return
}

func systemResolver(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// stderrLogger is a minimal logger.ContextLogger that writes to the standard
// logger (stderr). Enough to see registration + egress activity on the node.
type stderrLogger struct{}

func (stderrLogger) Trace(args ...any)          { log.Print(append([]any{"[trace] "}, args...)...) }
func (stderrLogger) Debug(args ...any)          { log.Print(append([]any{"[debug] "}, args...)...) }
func (stderrLogger) Info(args ...any)           { log.Print(append([]any{"[info] "}, args...)...) }
func (stderrLogger) Warn(args ...any)           { log.Print(append([]any{"[warn] "}, args...)...) }
func (stderrLogger) Error(args ...any)          { log.Print(append([]any{"[error] "}, args...)...) }
func (stderrLogger) Fatal(args ...any)          { log.Fatal(args...) }
func (stderrLogger) Panic(args ...any)          { log.Panic(args...) }
func (l stderrLogger) TraceContext(_ context.Context, a ...any) { l.Trace(a...) }
func (l stderrLogger) DebugContext(_ context.Context, a ...any) { l.Debug(a...) }
func (l stderrLogger) InfoContext(_ context.Context, a ...any)  { l.Info(a...) }
func (l stderrLogger) WarnContext(_ context.Context, a ...any)  { l.Warn(a...) }
func (l stderrLogger) ErrorContext(_ context.Context, a ...any) { l.Error(a...) }
func (l stderrLogger) FatalContext(_ context.Context, a ...any) { l.Fatal(a...) }
func (l stderrLogger) PanicContext(_ context.Context, a ...any) { l.Panic(a...) }
