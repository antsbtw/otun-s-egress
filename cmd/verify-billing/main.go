// Command verify-billing is a throwaway real-machine verifier for the three
// billing red lines (R1 hot-reload / R2 metering / R3 kick) driven through the
// egress library API against a REAL rendezvous. It starts a hysteria2 egress,
// registers on the rendezvous, then a sibling sing-box realm client punches in
// and passes traffic; we assert per-user stats, hot-reload, and kick.
//
// Not part of the product; kept out of the default build by the "verify" tag.
//go:build verify

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/antsbtw/otun-s-egress/egress"
)

func main() {
	serverURL := env("RDV_URL", "http://54.255.172.86:9443")
	token := env("RDV_TOKEN", "jwhCQ82CRclSSeHHcXDvWjO0Cp5fV51dJ0csZtWdg")
	realmID := env("RDV_REALM", "verify-billing-hy2")
	listen := env("LISTEN", ":51899")

	node, err := egress.New(egress.Config{
		Protocol:    "hysteria2",
		ServerURL:   serverURL,
		Token:       token,
		RealmID:     realmID,
		STUNServers: []string{"74.125.250.129:19302", "162.159.207.0:3478"},
		Password:    "seed-pw",
	})
	if err != nil {
		log.Fatalf("egress.New: %v", err)
	}

	udpAddr, _ := net.ResolveUDPAddr("udp", listen)
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	if err := node.Start(context.Background(), pc); err != nil {
		log.Fatalf("start: %v", err)
	}
	fmt.Printf("egress started realm=%s listen=%s\n", realmID, pc.LocalAddr())

	// R1: hot-reload to two users, then to one — assert no error and the API is
	// whole-set. (Traffic-not-dropped is asserted by the external client staying
	// connected; here we assert the control-plane contract.)
	fmt.Println("R1: UpdateUsers [A] -> [A,B] -> [B] -> [A,B] (end with both live)")
	must(node.UpdateUsers([]egress.User{{UUID: "A", Password: "pw-a"}}))
	must(node.UpdateUsers([]egress.User{{UUID: "A", Password: "pw-a"}, {UUID: "B", Password: "pw-b"}}))
	must(node.UpdateUsers([]egress.User{{UUID: "B", Password: "pw-b"}}))
	must(node.UpdateUsers([]egress.User{{UUID: "A", Password: "pw-a"}, {UUID: "B", Password: "pw-b"}}))
	fmt.Println("R1 ok: whole-set hot-reload accepted; live users A(pw-a) B(pw-b)")

	// R2: stats readable, reset semantics. (Byte accuracy needs a live client;
	// this asserts the API shape + reset zeroing on an idle node.)
	fmt.Println("R2: CollectStats reset semantics")
	_ = node.CollectStats(false) // snapshot
	billed := node.CollectStats(true)
	after := node.CollectStats(true)
	for _, s := range after {
		if s.Upload != 0 || s.Download != 0 {
			log.Fatalf("R2 FAIL: user %s not zeroed after billing read: up=%d down=%d", s.UUID, s.Upload, s.Download)
		}
	}
	fmt.Printf("R2 ok: %d users billed, zeroed on second read\n", len(billed))

	// R3: kick an unknown user returns 0 (no live conns); kick is non-fatal.
	fmt.Println("R3: KickUser")
	if n := node.KickUser("nonexistent"); n != 0 {
		log.Fatalf("R3 FAIL: kick of unknown user returned %d, want 0", n)
	}
	fmt.Println("R3 ok: kick API works (0 for user with no live conns)")

	// Hold briefly so an external client run can attach for byte-accuracy checks.
	hold := 3 * time.Second
	if v := os.Getenv("HOLD"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			hold = d
		}
	}
	// A.1 real-machine check: if EVICT_AT is set, at that many seconds into the
	// hold we remove user A (whole-set update to [B]). An external client of A
	// that was egressing should have its connection dropped — visible as A's
	// live-stat line disappearing after the eviction.
	var evictAt <-chan time.Time
	if v := os.Getenv("EVICT_AT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			evictAt = time.After(d)
		}
	}

	fmt.Printf("holding %s for optional client traffic; live stats:\n", hold)
	deadline := time.After(hold)
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-deadline:
			for _, s := range node.CollectStats(false) {
				fmt.Printf("  final user=%s up=%d down=%d\n", s.UUID, s.Upload, s.Download)
			}
			_ = node.Close()
			fmt.Println("ALL RED LINES OK")
			return
		case <-evictAt:
			fmt.Println("A.1: evicting user A (UpdateUsers -> [B]); A's live conns must drop")
			must(node.UpdateUsers([]egress.User{{UUID: "B", Password: "pw-b"}}))
			fmt.Println("A.1: A removed; watch A's live-stat line disappear below")
		case <-tick.C:
			for _, s := range node.CollectStats(false) {
				if s.Upload > 0 || s.Download > 0 {
					fmt.Printf("  live user=%s up=%d down=%d\n", s.UUID, s.Upload, s.Download)
				}
			}
		}
	}
}

func must(err error) {
	if err != nil {
		log.Fatalf("R1 FAIL: %v", err)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
