package egress_test

import (
	"context"
	"net"

	"github.com/antsbtw/otun-s-egress/egress"
)

// Example shows how realm-agent drives an egress node in-process (deploy scheme
// 甲): one New, then hot-reload users / collect billing / kick on quota — no
// v2ray_api, no clash_api, no hotreload HTTP, no sing-box fork.
func Example() {
	node, err := egress.New(egress.Config{
		Protocol:     "hysteria2",
		ServerURL:    "http://rendezvous:9443",
		Token:        "<realm token>",
		RealmID:      "cn-hy2",
		STUNServers:  []string{"74.125.250.129:19302"},
		ObfsPassword: "<salamander pw from connect_url ?obfs=>", // B.1: must match client
	})
	if err != nil {
		panic(err)
	}

	// Bring the egress online on a UDP socket.
	pc, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 51820})
	_ = node.Start(context.Background(), pc)

	// R1: hot-reload the whole billable user set (add/remove without dropping
	// existing connections; UUID is the billing key).
	_ = node.UpdateUsers([]egress.User{
		{UUID: "user-a-uuid", Password: "pw-a"},
		{UUID: "user-b-uuid", Password: "pw-b"},
	})

	// R2: per-user billing (reset=true reads+zeroes; bill once).
	for _, s := range node.CollectStats(true) {
		_ = s // report {s.UUID, s.Upload, s.Download} to manager
	}

	// R3: kick a user whose quota/time expired.
	_ = node.KickUser("user-a-uuid")

	// B.2: read the live-connection snapshot for obs risk-control.
	for _, c := range node.ActiveConnections() {
		_ = c // {c.UUID, c.Destination, c.Upload, c.Download, c.Start}
	}

	_ = node.Close()
}
