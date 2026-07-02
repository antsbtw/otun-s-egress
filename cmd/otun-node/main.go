// Command otun-node runs an OTun egress node for a TCP-family overlay protocol
// (Trojan / Shadowsocks / VMess) over a realm-punched hole. It is the unified
// deployable binary behind node/{trojannode,ssnode,vmessnode}: it registers on
// an OTun-S rendezvous, answers punches, runs a reliable QUIC stream
// (WrapStream) on the hole, runs the protocol's server handshake on each stream,
// and EGRESSES the decrypted traffic to its real destination out this host's IP.
//
// Protocol engines are reused from sing as libraries (no fork). Build plainly
// (none of these three need uTLS): go build ./cmd/otun-node
//
// Config JSON (protocol-specific fields ignored when not applicable):
//
//	{
//	  "protocol": "trojan",            // trojan | shadowsocks | vmess
//	  "server_url": "http://otun-s:9443",
//	  "token": "<realm token>",
//	  "realm_id": "m5-trojan-out",
//	  "stun_servers": ["74.125.250.129:19302","162.159.207.0:3478"],
//	  "password": "<trojan/ss password>",
//	  "method": "aes-128-gcm",          // shadowsocks only
//	  "uuid": "<vmess uuid>",           // vmess only
//	  "listen": ":51823"
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

	"github.com/antsbtw/otun-s-egress/node/ssnode"
	"github.com/antsbtw/otun-s-egress/node/trojannode"
	"github.com/antsbtw/otun-s-egress/node/vmessnode"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type config struct {
	Protocol    string   `json:"protocol"`
	ServerURL   string   `json:"server_url"`
	Token       string   `json:"token"`
	RealmID     string   `json:"realm_id"`
	STUNServers []string `json:"stun_servers"`
	Password    string   `json:"password"`
	Method      string   `json:"method"`
	UUID        string   `json:"uuid"`
	Listen      string   `json:"listen"`
}

// starter abstracts the three node packages, which share Start/Close shapes.
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
	wrapTLS := buildWrapServerTLS(ctx, lg)

	// egress: dial the proxied destination on the open internet, pipe both ways.
	egress := func(ctx context.Context, conn net.Conn, destination M.Socksaddr) {
		defer conn.Close()
		out, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", destination.String())
		if err != nil {
			lg.Warn("egress dial ", destination, ": ", err)
			return
		}
		defer out.Close()
		// Upstream (client->target): when it ends, stop reading from target so the
		// download copy can finish. Downstream (target->client): MUST fully flush
		// the response into conn before we close conn, else a fast client
		// half-close races the response (observed: 223 response bytes dropped).
		up := make(chan struct{})
		go func() { io.Copy(out, conn); _ = out.Close(); close(up) }()
		io.Copy(conn, out) // returns when target closes (e.g. HTTP Connection: close)
		<-up               // ensure the upstream goroutine has settled too
	}

	var node starter
	var err error
	switch cfg.Protocol {
	case "trojan":
		node, err = trojannode.New(trojannode.Options{
			ServerURL: cfg.ServerURL, Token: cfg.Token, RealmID: cfg.RealmID,
			STUNServers: cfg.STUNServers, Resolver: systemResolver, HTTPClient: &http.Client{},
			WrapTLS: wrapTLS, Password: cfg.Password,
			Handler: trojannode.ConnHandler(egress), Logger: lg,
		})
	case "shadowsocks":
		node, err = ssnode.New(ssnode.Options{
			ServerURL: cfg.ServerURL, Token: cfg.Token, RealmID: cfg.RealmID,
			STUNServers: cfg.STUNServers, Resolver: systemResolver, HTTPClient: &http.Client{},
			WrapTLS: wrapTLS, Method: cfg.Method, Password: cfg.Password,
			Handler: ssnode.ConnHandler(egress), Logger: lg,
		})
	case "vmess":
		node, err = vmessnode.New(vmessnode.Options{
			ServerURL: cfg.ServerURL, Token: cfg.Token, RealmID: cfg.RealmID,
			STUNServers: cfg.STUNServers, Resolver: systemResolver, HTTPClient: &http.Client{},
			WrapTLS: wrapTLS, UUID: cfg.UUID,
			Handler: vmessnode.Handler(egress), Logger: lg,
		})
	default:
		log.Fatalf("unknown protocol %q (want trojan|shadowsocks|vmess)", cfg.Protocol)
	}
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
	log.Printf("OTun %s egress node started: realm=%s server=%s local=%s",
		cfg.Protocol, cfg.RealmID, cfg.ServerURL, conn.LocalAddr())

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
