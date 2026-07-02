package hy2node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/antsbtw/otun-s-egress/node/meter"
	"github.com/antsbtw/otun-s-egress/node/userattr"
	"github.com/antsbtw/otun-s-egress/node/usermap"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	singhy2 "github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/logger"
)

// TestUpdateUsersEvictsRemoved is the review A.1/A.4 integration check at the
// node layer: when UpdateUsers drops a user, that user's live connections are
// force-closed and it disappears from CollectStats — an over-quota/expired user
// cannot keep egressing. Uses the node's meter/usermap directly (no network),
// exercising the same UpdateUsers glue all six nodes share.
//
// We build a Node with just users+meter (the fields UpdateUsers touches) and a
// stub service, so no TLS/rendezvous is needed.
func TestUpdateUsersEvictsRemoved(t *testing.T) {
	n := newTestNode()

	// Seed [A, B].
	must(t, n.UpdateUsers([]userattr.User{
		{UUID: "A", Password: "pw-a"},
		{UUID: "B", Password: "pw-b"},
	}))

	// A has a live connection (as if a client of A is egressing).
	ac, _ := net.Pipe()
	tracked := n.meter.Track("A", ac, meter.ConnMeta{})

	// Remove A (whole-set update to just [B]).
	must(t, n.UpdateUsers([]userattr.User{{UUID: "B", Password: "pw-b"}}))

	// A's live connection must be force-closed.
	if _, err := tracked.Write([]byte("x")); err == nil {
		t.Fatal("A's live connection was not closed after A was removed")
	}
	// A must be gone from billing; B must remain.
	for _, s := range n.CollectStats(false) {
		if s.UUID == "A" {
			t.Fatal("removed user A still present in CollectStats")
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
}

// newTestNode builds a Node with a real hysteria2 Service (whose UpdateUsers is
// an in-memory map swap — no network) plus users+meter. Not Started.
func newTestNode() *Node {
	ctx := context.Background()
	lg := logger.NOP()
	certPEM, keyPEM := selfSignedCertForTest("iptv.local")
	tlsCfg, err := sbtls.NewSTDServer(ctx, lg, option.InboundTLSOptions{
		Enabled: true, ServerName: "iptv.local", ALPN: []string{"h3"},
		Certificate: []string{certPEM}, Key: []string{keyPEM},
	})
	if err != nil {
		panic(err)
	}
	svc, err := singhy2.NewService[int](singhy2.ServiceOptions{
		Context: ctx, Logger: lg, TLSConfig: tlsCfg,
		Handler: egressHandler{dialer: systemDialer{}, logger: lg},
	})
	if err != nil {
		panic(err)
	}
	n := &Node{logger: lg, users: usermap.New(), meter: meter.New()}
	n.service = svc
	return n
}

func selfSignedCertForTest(host string) (string, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
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
