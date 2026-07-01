package realm

import (
	"context"
	"net/netip"
	"testing"
)

// TestPunchValidation covers the argument-validation guards in Punch (no realm
// id / no STUN / no resolver). The full end-to-end punch test (client ↔ real
// OTun-S rendezvous ↔ node) lives in the会合面 (otun-s) repo, since it needs
// core+wire; this egress repo stays free of会合面 code by design.
func TestPunchValidation(t *testing.T) {
	r := func(context.Context, string, bool, bool) ([]netip.Addr, error) { return nil, nil }
	cases := []struct {
		name string
		cfg  Config
		rid  string
	}{
		{"no realm id", Config{STUNServers: []string{"1.2.3.4:3478"}, Resolver: r}, ""},
		{"no stun", Config{Resolver: r}, "slot"},
		{"no resolver", Config{STUNServers: []string{"1.2.3.4:3478"}}, "slot"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Punch(context.Background(), tc.cfg, tc.rid); err == nil {
				t.Fatal("expected validation error, got nil")
			}
		})
	}
}
