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

	singhy2 "github.com/antsbtw/sing-quic/hysteria2"
	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
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
	n := newTestNode(nil)

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

// TestSharedMeterUsermapIndependent is the C.1 §5.4 check at the node layer: two
// nodes SHARE one meter.Registry but keep SEPARATE usermaps. Each node's
// UpdateUsers assigns indices in its OWN space (node1's index for a UUID is
// unrelated to node2's), yet a Track from either node lands under the same UUID
// in the shared Registry — so billing/kick/snapshot span both without the
// usermaps ever colliding.
func TestSharedMeterUsermapIndependent(t *testing.T) {
	reg := meter.New()
	n1 := newTestNode(reg)
	n2 := newTestNode(reg)

	// n1 seeds [X, Y]; n2 seeds [Y] only. Because usermaps are independent, Y's
	// index in n1 and n2 need not match — and adding to one must not perturb the
	// other's indices.
	must(t, n1.UpdateUsers([]userattr.User{{UUID: "X", Password: "px"}, {UUID: "Y", Password: "py"}}))
	must(t, n2.UpdateUsers([]userattr.User{{UUID: "Y", Password: "py"}}))

	xIdx1, ok := indexOf(n1, "X")
	if !ok {
		t.Fatal("X missing from n1 usermap")
	}
	yIdx1, _ := indexOf(n1, "Y")
	yIdx2, ok := indexOf(n2, "Y")
	if !ok {
		t.Fatal("Y missing from n2 usermap")
	}

	// Stable-index invariant PER NODE: re-updating n1 with a new user must not
	// move X's or Y's existing indices in n1, and must not touch n2 at all.
	must(t, n1.UpdateUsers([]userattr.User{
		{UUID: "X", Password: "px"}, {UUID: "Y", Password: "py"}, {UUID: "Z", Password: "pz"},
	}))
	if i, _ := indexOf(n1, "X"); i != xIdx1 {
		t.Fatalf("n1 X index moved %d -> %d after adding Z", xIdx1, i)
	}
	if i, _ := indexOf(n1, "Y"); i != yIdx1 {
		t.Fatalf("n1 Y index moved %d -> %d after adding Z", yIdx1, i)
	}
	if i, _ := indexOf(n2, "Y"); i != yIdx2 {
		t.Fatalf("n2 Y index perturbed by n1 update: %d -> %d", yIdx2, i)
	}

	// Shared meter: a conn tracked via each node lands under the same UUID "Y" in
	// the one Registry, so its bytes merge and one kick drops both.
	c1, p1 := net.Pipe()
	c2, p2 := net.Pipe()
	defer func() { p1.Close(); p2.Close() }()
	reg.Track("Y", c1, meter.ConnMeta{Protocol: "hysteria2", Source: "via-n1"})
	reg.Track("Y", c2, meter.ConnMeta{Protocol: "hysteria2", Source: "via-n2"})

	if got := len(reg.Snapshot()); got != 2 {
		t.Fatalf("shared registry snapshot=%d, want 2 (one conn from each node)", got)
	}
	// n1.KickUser and n2.KickUser both target the SAME shared registry, so the
	// first kick drops both of Y's conns (proving one shared surface).
	if n := n1.KickUser("Y"); n != 2 {
		t.Fatalf("KickUser(Y) via n1 dropped %d, want 2 (shared meter spans both nodes)", n)
	}
	if got := len(reg.Snapshot()); got != 0 {
		t.Fatalf("after kick, shared snapshot=%d, want 0", got)
	}
}

// indexOf reports the shared-registry-independent usermap index a node assigned
// to a UUID by round-tripping through UUIDForIndex over a small index range.
func indexOf(n *Node, uuid string) (int, bool) {
	for i := 0; i < 64; i++ {
		if got, ok := n.UUIDForIndex(i); ok && got == uuid {
			return i, true
		}
	}
	return 0, false
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
}

// newTestNode builds a Node with a real hysteria2 Service (whose UpdateUsers is
// an in-memory map swap — no network) plus users+meter. Not Started. When reg is
// non-nil the node SHARES it (C.1); nil gives it a private registry.
func newTestNode(reg *meter.Registry) *Node {
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
	if reg == nil {
		reg = meter.New()
	}
	n := &Node{logger: lg, users: usermap.New(), meter: reg}
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
