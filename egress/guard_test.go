package egress

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestParseGuardMode(t *testing.T) {
	for in, want := range map[string]GuardMode{"": GuardEnforce, "enforce": GuardEnforce, " LOG ": GuardLogOnly, "off": GuardOff} {
		got, err := ParseGuardMode(in)
		if err != nil || got != want {
			t.Errorf("ParseGuardMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseGuardMode("block"); err == nil {
		t.Error("ParseGuardMode(block) should fail")
	}
}

func TestBlockedAddrKind(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1":        "loopback",
		"::1":              "loopback",
		"::ffff:127.0.0.1": "loopback",
		"0.0.0.0":          "unspecified",
		"169.254.169.254":  "link_local",
		"fe80::1":          "link_local",
		"10.1.2.3":         "private",
		"172.20.0.1":       "private",
		"192.168.1.1":      "private",
		"fd00:ec2::254":    "private",
		"100.100.1.1":      "cgnat",
		"239.255.255.250":  "multicast",
		"ff02::1":          "multicast",
		"255.255.255.255":  "reserved",
		"0.1.2.3":          "reserved",
		"8.8.8.8":          "",
		"1.1.1.1":          "",
		"2001:4860::8888":  "",
		"100.128.0.1":      "", // just outside CGNAT
	}
	for s, want := range cases {
		if got := blockedAddrKind(netip.MustParseAddr(s)); got != want {
			t.Errorf("blockedAddrKind(%s) = %q, want %q", s, got, want)
		}
	}
	if got := blockedAddrKind(netip.Addr{}); got != "invalid_addr" {
		t.Errorf("zero addr = %q", got)
	}
}

func TestBlockedDestKind(t *testing.T) {
	cases := []struct {
		network, dest, want string
	}{
		{N.NetworkTCP, "1.2.3.4:25", "smtp"},
		{N.NetworkTCP, "smtp.example.com:25", "smtp"},
		{N.NetworkTCP, "smtp.gmail.com:587", ""},
		{N.NetworkTCP, "smtp.gmail.com:465", ""},
		{N.NetworkUDP, "1.2.3.4:25", ""},
		{N.NetworkTCP, "localhost:80", "local_name"},
		{N.NetworkTCP, "metadata.google.internal:80", "local_name"},
		{N.NetworkTCP, "printer.local.:631", "local_name"},
		{N.NetworkTCP, "www.google.com:443", ""},
		{N.NetworkTCP, "10.0.0.1:443", "private"},
	}
	for _, c := range cases {
		if got := blockedDestKind(c.network, M.ParseSocksaddr(c.dest)); got != c.want {
			t.Errorf("blockedDestKind(%s %s) = %q, want %q", c.network, c.dest, got, c.want)
		}
	}
}

func TestSniffStreamBT(t *testing.T) {
	hs := append([]byte(btHandshake), make([]byte, 48)...)
	cases := map[string]string{
		string(hs): "bittorrent",
		"GET /announce?info_hash=%12%34&peer_id=x&port=6881 HTTP/1.1\r\nHost: t\r\n\r\n": "bittorrent_tracker",
		"GET /scrape?info_hash=%12 HTTP/1.1\r\n":                                         "bittorrent_tracker",
		"GET /announce HTTP/1.1\r\n":                                                     "",
		"GET /search?q=info_hash= HTTP/1.1\r\n":                                          "",
		"\x16\x03\x01\x02\x00\x01":                                                       "",
		"SSH-2.0-OpenSSH_9.6\r\n":                                                        "",
	}
	for in, want := range cases {
		if got := sniffStreamBT([]byte(in)); got != want {
			t.Errorf("sniffStreamBT(%q) = %q, want %q", in, got, want)
		}
	}
}

func utpSyn(ext byte, extData []byte) []byte {
	p := make([]byte, 20)
	p[0], p[1] = 0x41, ext
	binary.BigEndian.PutUint16(p[2:], 0x1234)    // conn id
	binary.BigEndian.PutUint32(p[4:], 123456789) // timestamp
	binary.BigEndian.PutUint32(p[12:], 1<<20)    // wnd
	binary.BigEndian.PutUint16(p[16:], 1)        // seq
	return append(p, extData...)
}

func TestUDPSniffers(t *testing.T) {
	if !isDHT([]byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe")) {
		t.Error("DHT query not detected")
	}
	if !isDHT([]byte("d1:rd2:id20:abcdefghij0123456789e1:t2:aa1:y1:re")) {
		t.Error("DHT response not detected")
	}
	tr := make([]byte, 16)
	binary.BigEndian.PutUint64(tr, 0x41727101980)
	if !isUDPTrackerConnect(tr) {
		t.Error("UDP tracker connect not detected")
	}
	if !isUTPSyn(utpSyn(0, nil)) {
		t.Error("uTP SYN not detected")
	}
	if !isUTPSyn(utpSyn(2, []byte{0, 8, 1, 2, 3, 4, 5, 6, 7, 8})) {
		t.Error("uTP SYN with extension not detected")
	}
	// uTP-looking but carries payload → not a SYN.
	if isUTPSyn(utpSyn(0, []byte("data"))) {
		t.Error("uTP with payload misdetected as SYN")
	}
	// DNS query whose id happens to be 0x4100: header + question is > 20 bytes.
	dns := []byte{0x41, 0x00, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if isUTPSyn(dns) {
		t.Error("DNS query misdetected as uTP SYN")
	}
	quicInitial := append([]byte{0xC3, 0, 0, 0, 1}, make([]byte, 1200)...)
	if isUTPSyn(quicInitial) || isDHT(quicInitial) || isUDPTrackerConnect(quicInitial) {
		t.Error("QUIC initial misdetected")
	}
}

func TestGuardOffReturnsInnerUntouched(t *testing.T) {
	g := newGuard(GuardOff, logger.NOP())
	if d := g.wrap(nil, 0); d != nil {
		t.Fatalf("off + nil inner should stay nil, got %T", d)
	}
	var nilGuard *guard
	if d := nilGuard.wrap(nil, 0); d != nil {
		t.Fatalf("nil guard should return inner")
	}
}

func listenLocal(t *testing.T) (net.Listener, M.Socksaddr) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { b := make([]byte, 1024); c.Read(b); c.Close() }()
		}
	}()
	return ln, M.SocksaddrFromNet(ln.Addr())
}

func TestGuardDialerLoopback(t *testing.T) {
	_, dest := listenLocal(t)
	ctx := context.Background()

	enforce := newGuard(GuardEnforce, logger.NOP()).wrap(nil, 2*time.Second)
	if c, err := enforce.DialContext(ctx, N.NetworkTCP, dest); err == nil {
		c.Close()
		t.Fatal("enforce: dial to loopback should be refused")
	}

	logOnly := newGuard(GuardLogOnly, logger.NOP()).wrap(nil, 2*time.Second)
	c, err := logOnly.DialContext(ctx, N.NetworkTCP, dest)
	if err != nil {
		t.Fatalf("log mode: dial should pass, got %v", err)
	}
	c.Close()
}

func TestGuardDialerResolvedName(t *testing.T) {
	// A name not on the name list that resolves to loopback is caught at connect
	// time by the Control hook. "localhost" itself is name-blocked first, so
	// exercise the hook directly.
	d := newGuard(GuardEnforce, logger.NOP()).wrap(nil, 0).(*guardDialer)
	if err := d.control(context.Background())(context.Background(), "tcp4", "127.0.0.1:8080", nil); err == nil {
		t.Error("control should refuse a loopback connect")
	}
	if err := d.control(context.Background())(context.Background(), "tcp4", "8.8.8.8:443", nil); err != nil {
		t.Errorf("control should allow public addr, got %v", err)
	}
}

func TestGuardConnBlocksBTHandshake(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	go func() { buf := make([]byte, 128); b.Read(buf) }()
	gc := &guardConn{Conn: a, g: newGuard(GuardEnforce, logger.NOP()), ctx: context.Background(), dest: "1.2.3.4:6881"}
	if _, err := gc.Write(append([]byte(btHandshake), make([]byte, 48)...)); err == nil {
		t.Fatal("BT handshake write should be refused")
	}

	a2, b2 := net.Pipe()
	defer b2.Close()
	got := make(chan []byte, 1)
	go func() { buf := make([]byte, 128); n, _ := b2.Read(buf); got <- buf[:n] }()
	gc2 := &guardConn{Conn: a2, g: newGuard(GuardEnforce, logger.NOP()), ctx: context.Background(), dest: "1.2.3.4:443"}
	if _, err := gc2.Write([]byte("\x16\x03\x01hello")); err != nil {
		t.Fatalf("TLS write should pass: %v", err)
	}
	if string(<-got) != "\x16\x03\x01hello" {
		t.Error("payload not forwarded")
	}
	a2.Close()
}

// recordPC is a fake outbound UDP socket that records what was written.
type recordPC struct {
	N.NetPacketConn
	sent []string
}

func (r *recordPC) WritePacket(b *buf.Buffer, dest M.Socksaddr) error {
	r.sent = append(r.sent, dest.String())
	b.Release()
	return nil
}

func TestGuardPacketConnDrops(t *testing.T) {
	rec := &recordPC{}
	pc := &guardPacketConn{inner: rec, g: newGuard(GuardEnforce, logger.NOP()), ctx: context.Background(), firstSeen: map[netip.AddrPort]struct{}{}}
	send := func(dest string, payload []byte) {
		if err := pc.WritePacket(buf.As(payload), M.ParseSocksaddr(dest)); err != nil {
			t.Fatalf("WritePacket(%s) returned error %v (drops must be silent)", dest, err)
		}
	}
	send("8.8.8.8:53", []byte("dns"))                                 // ok
	send("239.255.255.250:1900", []byte("M-SEARCH"))                  // multicast → drop
	send("169.254.169.254:80", []byte("x"))                           // metadata → drop
	send("1.2.3.4:6881", []byte("d1:ad2:id20:abcdefghij0123456789e")) // DHT → drop
	send("5.6.7.8:51413", utpSyn(0, nil))                             // first packet uTP SYN → drop
	send("9.9.9.9:443", utpSyn(0, nil))                               // first packet here too → drop
	send("1.1.1.1:443", []byte{0xC3, 0, 0, 0, 1})                     // QUIC → ok
	send("1.1.1.1:443", utpSyn(0, nil))                               // not first packet → ok

	want := []string{"8.8.8.8:53", "1.1.1.1:443", "1.1.1.1:443"}
	if len(rec.sent) != len(want) {
		t.Fatalf("sent %v, want %v", rec.sent, want)
	}
	for i := range want {
		if rec.sent[i] != want[i] {
			t.Fatalf("sent %v, want %v", rec.sent, want)
		}
	}

	rec2 := &recordPC{}
	logPC := &guardPacketConn{inner: rec2, g: newGuard(GuardLogOnly, logger.NOP()), ctx: context.Background(), firstSeen: map[netip.AddrPort]struct{}{}}
	logPC.WritePacket(buf.As([]byte("x")), M.ParseSocksaddr("10.0.0.1:53"))
	if len(rec2.sent) != 1 {
		t.Error("log mode must not drop")
	}
}

func TestGuardLogRateLimit(t *testing.T) {
	g := newGuard(GuardEnforce, logger.NOP())
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		if !g.violation(ctx, "bittorrent", "tcp", "1.2.3.4:6881") {
			t.Fatal("enforce must block every hit, not just logged ones")
		}
	}
	if n := g.suppressed["unattributed|bittorrent"]; n != 99 {
		t.Errorf("suppressed = %d, want 99", n)
	}
}
