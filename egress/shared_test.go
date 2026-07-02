package egress

import (
	"net"
	"testing"

	"github.com/antsbtw/otun-s-egress/node/meter"
)

// sharedCfgs is the "one physical node, N protocols" config set: same rendezvous
// slot conceptually, each protocol its own Config. Credentials are minimal valid
// values so New() (which does NOT Start / touch the network) can build each node.
//
// Reality is intentionally omitted: its factory builds+Start()s a reality-server
// TLS config that constructs a real handshake dialer at build time (not Start
// time), which needs live network setup — unlike the other five it can't be
// built offline in a unit test. The shared-registry wiring is identical for
// reality (factory passes cfg.Meter through the same way; assert.go proves the
// interface), so the five buildable protocols fully exercise C.1 here.
func sharedCfgs() []Config {
	const u = "11111111-1111-1111-1111-111111111111"
	// A placeholder rendezvous URL: New() only constructs the realm server (which
	// requires a non-empty URL), it does not Start it, so nothing is dialed.
	const url = "http://127.0.0.1:0"
	const rid = "slot-test"
	stun := []string{"stun.l.google.com:19302"}
	base := func(p string) Config {
		return Config{Protocol: p, ServerURL: url, RealmID: rid, STUNServers: stun}
	}
	mk := func(p string, edit func(*Config)) Config { c := base(p); edit(&c); return c }
	return []Config{
		mk("hysteria2", func(c *Config) { c.Password = "pw" }),
		mk("tuic", func(c *Config) { c.UUID = u; c.Password = "pw" }),
		mk("trojan", func(c *Config) { c.Password = "pw" }),
		mk("shadowsocks", func(c *Config) { c.Method, c.Password = "aes-128-gcm", "pw" }),
		mk("vmess", func(c *Config) { c.UUID = u }),
	}
}

// TestNewSharedOneRegistry is the C.1 top-level acceptance: NewShared builds one
// node per Config, all sharing ONE returned Registry. A conn tracked into that
// Registry — as any of the six nodes' egress path would — is visible through
// EVERY node's ActiveConnections() (they all read the same registry), and one
// KickUser on it drops the conn everywhere. That is the whole point: one call
// covers six protocols.
func TestNewSharedOneRegistry(t *testing.T) {
	cfgs := sharedCfgs()
	nodes, reg, err := NewShared(cfgs)
	if err != nil {
		t.Fatalf("NewShared: %v", err)
	}
	if len(nodes) != len(cfgs) {
		t.Fatalf("NewShared built %d nodes, want %d", len(nodes), len(cfgs))
	}
	defer func() {
		for _, n := range nodes {
			_ = n.Close()
		}
	}()

	// Track a conn straight into the shared registry (stands in for one node's
	// live egress conn). Every node's ActiveConnections must see it, since they
	// share reg.
	c1, peer := net.Pipe()
	defer peer.Close()
	_ = reg.Track("U", c1, meter.ConnMeta{Protocol: "tuic", Destination: "x:1"})

	for i, n := range nodes {
		if got := len(n.ActiveConnections()); got != 1 {
			t.Fatalf("node[%d].ActiveConnections()=%d, want 1 (shared registry)", i, got)
		}
	}
	// One kick via the shared registry drops it for all.
	if k := reg.KickUser("U"); k != 1 {
		t.Fatalf("shared KickUser=%d, want 1", k)
	}
	for i, n := range nodes {
		if got := len(n.ActiveConnections()); got != 0 {
			t.Fatalf("node[%d] still shows %d conns after shared kick", i, got)
		}
	}
}

// TestNewPrivateMeterBackCompat is the §5.5 back-compat check: without injecting
// a Meter, each New() node keeps a PRIVATE registry. We prove isolation by
// injecting a registry into ONE node (a), tracking a conn into it, and showing a
// second node (b) built WITHOUT injection does not observe it — i.e. the default
// is a per-node private meter, unchanged from before C.1.
func TestNewPrivateMeterBackCompat(t *testing.T) {
	const url = "http://127.0.0.1:0"
	const rid = "slot-test"
	stun := []string{"stun.l.google.com:19302"}
	shared := NewRegistry()
	a, err := New(Config{Protocol: "trojan", ServerURL: url, RealmID: rid, STUNServers: stun, Password: "pw", Meter: shared})
	if err != nil {
		t.Fatalf("New(a): %v", err)
	}
	defer a.Close()
	b, err := New(Config{Protocol: "vmess", ServerURL: url, RealmID: rid, STUNServers: stun, UUID: "11111111-1111-1111-1111-111111111111"}) // no Meter
	if err != nil {
		t.Fatalf("New(b): %v", err)
	}
	defer b.Close()

	c1, peer := net.Pipe()
	defer peer.Close()
	_ = shared.Track("U", c1, meter.ConnMeta{Protocol: "trojan"})

	// a shares `shared` → sees the conn; b has a private meter → does not.
	if got := len(a.ActiveConnections()); got != 1 {
		t.Fatalf("injected node a sees %d conns, want 1", got)
	}
	if got := len(b.ActiveConnections()); got != 0 {
		t.Fatalf("non-injected node b sees %d conns, want 0 (private meter, back-compat)", got)
	}
}
