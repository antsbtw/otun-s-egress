package underlay

import (
	"context"
	"net"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// TestWrapStreamValidation covers WrapStream's nil-arg guards. The full M4
// acceptance (a QUIC reliable stream over an actual realm-punched hole) lives in
// the会合面 (otun-s) repo, since it needs core+wire to stand up a rendezvous;
// this egress repo stays free of会合面 code by design.
func TestWrapStreamValidation(t *testing.T) {
	if _, err := WrapStream(context.Background(), nil, M.Socksaddr{}, nil); err == nil {
		t.Fatal("expected error for nil packet conn")
	}
	pc, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer pc.Close()
	if _, err := WrapStream(context.Background(), pc, M.Socksaddr{}, nil); err == nil {
		t.Fatal("expected error for nil TLS config")
	}
}
