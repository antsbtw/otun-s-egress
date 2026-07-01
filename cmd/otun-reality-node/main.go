// Command otun-reality-node runs an OTun Reality egress node: registers on an
// OTun-S rendezvous, answers hole punches, runs a reliable QUIC stream
// (WrapStream) on the punched hole, Reality-handshakes each stream, and exits
// the decrypted traffic out this host's IP.
//
// Server-side counterpart to overlay/reality (DEV M5). Reality engine is reused
// from sing-box as a library (no fork). Build with -tags with_utls.
//
// Config JSON:
//
//	{
//	  "server_url": "http://otun-s-host:9443",
//	  "token": "<realm token>",
//	  "realm_id": "m5-reality-out",
//	  "stun_servers": ["74.125.250.129:19302","162.159.207.0:3478"],
//	  "private_key": "<reality x25519 private, base64url>",
//	  "short_id": "0123456789abcdef",
//	  "server_name": "www.apple.com",
//	  "handshake_server": "www.apple.com",
//	  "handshake_port": 443,
//	  "listen": ":51822"
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

	"github.com/antsbtw/otun-s-egress/node/realitynode"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type config struct {
	ServerURL       string   `json:"server_url"`
	Token           string   `json:"token"`
	RealmID         string   `json:"realm_id"`
	STUNServers     []string `json:"stun_servers"`
	PrivateKey      string   `json:"private_key"`
	ShortID         string   `json:"short_id"`
	UUID            string   `json:"uuid"` // VLESS user id (inner protocol)
	ServerName      string   `json:"server_name"`
	HandshakeServer string   `json:"handshake_server"`
	HandshakePort   uint16   `json:"handshake_port"`
	Listen          string   `json:"listen"`
}

func main() {
	cfgPath := flag.String("config", "reality-node.json", "path to config JSON")
	flag.Parse()
	cfg := loadConfig(*cfgPath)
	if cfg.HandshakePort == 0 {
		cfg.HandshakePort = 443
	}

	ctx := context.Background()
	var lg logger.ContextLogger = stderrLogger{}

	wrapTLS := buildWrapServerTLS(ctx, lg)
	realityTLS := buildRealityServer(ctx, lg, cfg)

	node, err := realitynode.New(realitynode.Options{
		ServerURL:   cfg.ServerURL,
		Token:       cfg.Token,
		RealmID:     cfg.RealmID,
		STUNServers: cfg.STUNServers,
		Resolver:    systemResolver,
		HTTPClient:  &http.Client{},
		WrapTLS:     wrapTLS,
		Reality:     realityTLS,
		UUID:        cfg.UUID,
		Handler:     egressHandler{lg}.egress,
		Logger:      lg,
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
	log.Printf("OTun Reality egress node started: realm=%s server=%s local=%s handshake=%s:%d",
		cfg.RealmID, cfg.ServerURL, conn.LocalAddr(), cfg.HandshakeServer, cfg.HandshakePort)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Print("shutting down")
	_ = node.Close()
}

// egressHandler dials the VLESS-derived destination on the open internet and
// pipes both ways. The destination comes from realitynode's VLESS header read —
// no out-of-band header hack; this is a real VLESS+Reality egress.
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
	// Flush the response (target->client) before closing, like cmd/otun-node.
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

func buildRealityServer(ctx context.Context, lg logger.ContextLogger, cfg config) sbtls.ServerConfig {
	rc, err := sbtls.NewServer(ctx, lg, option.InboundTLSOptions{
		Enabled:    true,
		ServerName: cfg.ServerName,
		Reality: &option.InboundRealityOptions{
			Enabled: true,
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     cfg.HandshakeServer,
					ServerPort: cfg.HandshakePort,
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
