package egress

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// fakeSocks5 is a minimal SOCKS5 server (user/pass auth, CONNECT, UDP ASSOCIATE)
// that records what it was asked to reach. CONNECT is answered by replying the
// requested address back over the stream instead of dialing anywhere.
type fakeSocks5 struct {
	ln       net.Listener
	udp      *net.UDPConn
	user     string
	pass     string
	bindZero bool // answer UDP ASSOCIATE with 0.0.0.0 (proxy-says-"same host")

	mu      sync.Mutex
	targets []string
}

func newFakeSocks5(t *testing.T, user, pass string, bindZero bool) *fakeSocks5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSocks5{ln: ln, udp: udp, user: user, pass: pass, bindZero: bindZero}
	go s.serve()
	go s.serveUDP()
	t.Cleanup(func() { ln.Close(); udp.Close() })
	return s
}

func (s *fakeSocks5) url(user, pass string) string {
	return "socks5://" + user + ":" + pass + "@" + s.ln.Addr().String()
}

func (s *fakeSocks5) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.targets...)
}

func (s *fakeSocks5) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func readAddr(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}
	var host string
	switch atyp[0] {
	case 1:
		b := make([]byte, 4)
		io.ReadFull(r, b)
		host = net.IP(b).String()
	case 3:
		var l [1]byte
		io.ReadFull(r, l[:])
		b := make([]byte, l[0])
		io.ReadFull(r, b)
		host = string(b)
	case 4:
		b := make([]byte, 16)
		io.ReadFull(r, b)
		host = net.IP(b).String()
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}

func (s *fakeSocks5) handle(c net.Conn) {
	defer c.Close()
	h := make([]byte, 2)
	io.ReadFull(c, h)
	io.ReadFull(c, make([]byte, h[1]))
	c.Write([]byte{5, 2})
	var v [2]byte
	io.ReadFull(c, v[:])
	u := make([]byte, v[1])
	io.ReadFull(c, u)
	var pl [1]byte
	io.ReadFull(c, pl[:])
	p := make([]byte, pl[0])
	io.ReadFull(c, p)
	if string(u) != s.user || string(p) != s.pass {
		c.Write([]byte{1, 1})
		return
	}
	c.Write([]byte{1, 0})
	req := make([]byte, 3)
	io.ReadFull(c, req)
	target, err := readAddr(c)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.targets = append(s.targets, target)
	s.mu.Unlock()
	switch req[1] {
	case 1: // CONNECT
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		c.Write([]byte("via-proxy " + target))
	case 3: // UDP ASSOCIATE
		ua := s.udp.LocalAddr().(*net.UDPAddr)
		ip := ua.IP.To4()
		if s.bindZero {
			ip = net.IPv4zero.To4()
		}
		reply := []byte{5, 0, 0, 1}
		reply = append(reply, ip...)
		reply = binary.BigEndian.AppendUint16(reply, uint16(ua.Port))
		c.Write(reply)
		io.Copy(io.Discard, c) // hold the association open
	}
}

// serveUDP echoes each datagram back, prefixed with "udp-echo ".
func (s *fakeSocks5) serveUDP() {
	buf := make([]byte, 2048)
	for {
		n, from, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// header: RSV RSV FRAG ATYP ADDR PORT
		hdrEnd := 4
		switch buf[3] {
		case 1:
			hdrEnd += 4
		case 3:
			hdrEnd += 1 + int(buf[4])
		case 4:
			hdrEnd += 16
		}
		hdrEnd += 2
		out := append(append([]byte{}, buf[:hdrEnd]...), []byte("udp-echo ")...)
		out = append(out, buf[hdrEnd:n]...)
		s.udp.WriteToUDP(out, from)
	}
}

func readAllTimeout(t *testing.T, c net.Conn) string {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, _ := io.ReadAll(c)
	return string(b)
}

func TestUpstreamTCPGoesViaProxyWithRemoteDNS(t *testing.T) {
	s := newFakeSocks5(t, "u", "p", false)
	d, err := NewUpstreamDialer(UpstreamConfig{URL: s.url("u", "p")})
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("www.example.com", 443))
	if err != nil {
		t.Fatal(err)
	}
	if got := readAllTimeout(t, c); got != "via-proxy www.example.com:443" {
		t.Fatalf("got %q", got)
	}
	// The proxy must receive the domain itself (remote DNS), not a locally resolved IP.
	if seen := s.seen(); len(seen) != 1 || seen[0] != "www.example.com:443" {
		t.Fatalf("proxy saw %v", seen)
	}
}

func TestUpstreamWrongPasswordFailsClosed(t *testing.T) {
	s := newFakeSocks5(t, "u", "p", false)
	d, _ := NewUpstreamDialer(UpstreamConfig{URL: s.url("u", "WRONG")})
	if _, err := d.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("www.example.com", 443)); err == nil {
		t.Fatal("expected failure with wrong password, got a connection")
	}
}

func TestUpstreamProxyDownFailsClosed(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listening any more
	d, _ := NewUpstreamDialer(UpstreamConfig{URL: "socks5://u:p@" + addr})
	// Destination is a live local listener: a direct fallback would succeed.
	target, _ := net.Listen("tcp", "127.0.0.1:0")
	defer target.Close()
	if _, err := d.DialContext(context.Background(), "tcp", M.ParseSocksaddr(target.Addr().String())); err == nil {
		t.Fatal("expected failure when upstream is down (no direct fallback)")
	}
}

func TestUpstreamDirectDomainsBypass(t *testing.T) {
	s := newFakeSocks5(t, "u", "p", false)
	target, _ := net.Listen("tcp", "127.0.0.1:0")
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err == nil {
			c.Write([]byte("direct"))
			c.Close()
		}
	}()
	d, _ := NewUpstreamDialer(UpstreamConfig{URL: s.url("u", "p"), DirectDomains: []string{" .LocalHost. "}})
	port := target.Addr().(*net.TCPAddr).Port
	c, err := d.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("localhost", uint16(port)))
	if err != nil {
		t.Fatal(err)
	}
	if got := readAllTimeout(t, c); got != "direct" {
		t.Fatalf("got %q", got)
	}
	if len(s.seen()) != 0 {
		t.Fatalf("direct domain went through proxy: %v", s.seen())
	}
	// Suffix match is on label boundaries: notlocalhost must NOT bypass.
	if d.isDirect(M.ParseSocksaddrHostPort("notlocalhost", 80)) {
		t.Fatal("suffix matched across label boundary")
	}
	if !d.isDirect(M.ParseSocksaddrHostPort("a.b.localhost", 80)) {
		t.Fatal("subdomain should match")
	}
	if d.isDirect(M.ParseSocksaddr("127.0.0.1:80")) {
		t.Fatal("bare IP destinations must go upstream")
	}
}

func TestUpstreamUDPAssociate(t *testing.T) {
	for _, zero := range []bool{false, true} {
		s := newFakeSocks5(t, "u", "p", zero)
		d, _ := NewUpstreamDialer(UpstreamConfig{URL: s.url("u", "p")})
		dst := M.ParseSocksaddr("1.1.1.1:53")
		pc, err := d.ListenPacket(context.Background(), dst)
		if err != nil {
			t.Fatalf("bindZero=%v: %v", zero, err)
		}
		if _, err := pc.WriteTo([]byte("ping"), dst.UDPAddr()); err != nil {
			t.Fatal(err)
		}
		pc.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 256)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("bindZero=%v read: %v", zero, err)
		}
		if got := string(buf[:n]); got != "udp-echo ping" {
			t.Fatalf("bindZero=%v got %q", zero, got)
		}
		pc.Close()
	}
}

func TestNewUpstreamDialerRejectsBadConfig(t *testing.T) {
	for _, u := range []string{"", "http://u:p@1.2.3.4:80", "socks5://u:p@1.2.3.4", "::bad"} {
		if _, err := NewUpstreamDialer(UpstreamConfig{URL: u}); err == nil {
			t.Fatalf("expected error for %q", u)
		}
	}
}
