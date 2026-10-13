package egress

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/antsbtw/otun-s-egress/node/userattr"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// GuardMode selects how the egress abuse guard treats a violation. The guard
// sits on the user egress leg only (the same leg Config.Egress replaces);
// rendezvous / STUN / punch / relay traffic never passes through it.
//
// What it catches:
//   - destinations that are not the open internet: loopback, RFC1918 / ULA,
//     CGNAT 100.64/10, link-local (incl. cloud metadata 169.254.169.254),
//     multicast/broadcast/reserved, and this node's own interface addresses;
//     plus names like localhost / *.internal / *.local
//   - outbound TCP/25 (SMTP spam is the fastest way to get an IP blacklisted;
//     465/587 submission is authenticated mail and stays open)
//   - BitTorrent: TCP peer handshake, plain-HTTP tracker announce/scrape, UDP
//     tracker connect, DHT KRPC, uTP SYN. Encrypted peer wire (MSE/PE) is not
//     detectable here; with DHT/trackers blocked, peer discovery mostly fails.
type GuardMode string

const (
	// GuardEnforce blocks and logs. The zero value ("") means enforce.
	GuardEnforce GuardMode = "enforce"
	// GuardLogOnly logs what enforce would block, lets everything through.
	GuardLogOnly GuardMode = "log"
	// GuardOff disables the guard: Config.Egress is used exactly as given.
	GuardOff GuardMode = "off"
)

// ParseGuardMode maps an operator string ("", enforce, log, off) to a mode.
func ParseGuardMode(s string) (GuardMode, error) {
	switch GuardMode(strings.ToLower(strings.TrimSpace(s))) {
	case "", GuardEnforce:
		return GuardEnforce, nil
	case GuardLogOnly:
		return GuardLogOnly, nil
	case GuardOff:
		return GuardOff, nil
	}
	return "", E.New("egress guard: unknown mode ", s, " (want enforce|log|off)")
}

// errGuardBlocked is returned to the protocol handler for a refused TCP dial.
var errGuardBlocked = E.New("egress guard: destination blocked")

const guardLogInterval = time.Minute

type guard struct {
	mode GuardMode
	lg   logger.ContextLogger

	logMu      sync.Mutex
	lastLog    map[string]time.Time
	suppressed map[string]int
}

func newGuard(mode GuardMode, lg logger.ContextLogger) *guard {
	if mode == "" {
		mode = GuardEnforce
	}
	return &guard{mode: mode, lg: lg, lastLog: map[string]time.Time{}, suppressed: map[string]int{}}
}

// wrap returns the dialer the protocol nodes should use. With the guard off it
// returns inner untouched (nil stays nil → each node's own direct dialer).
// timeout bounds direct TCP connects (0 = OS default), matching what the node
// would have used without the guard.
func (g *guard) wrap(inner N.Dialer, timeout time.Duration) N.Dialer {
	if g == nil || g.mode == GuardOff {
		return inner
	}
	return &guardDialer{g: g, inner: inner, timeout: timeout}
}

// violation reports a hit. It returns true when the caller must block.
// Logging is limited to one line per (user, kind) per minute.
func (g *guard) violation(ctx context.Context, kind string, network string, dest string) bool {
	user := userattr.Label(ctx)
	key := user + "|" + kind
	now := time.Now()
	g.logMu.Lock()
	last, seen := g.lastLog[key]
	if seen && now.Sub(last) < guardLogInterval {
		g.suppressed[key]++
		g.logMu.Unlock()
		return g.mode == GuardEnforce
	}
	n := g.suppressed[key]
	g.lastLog[key] = now
	delete(g.suppressed, key)
	if len(g.lastLog) > 4096 { // bound memory: forget old keys
		for k, t := range g.lastLog {
			if now.Sub(t) >= guardLogInterval {
				delete(g.lastLog, k)
				delete(g.suppressed, k)
			}
		}
	}
	g.logMu.Unlock()
	action := "blocked"
	if g.mode != GuardEnforce {
		action = "would-block"
	}
	g.lg.Warn("egress guard ", action, " user=", user, " kind=", kind, " ", network, " -> ", dest, " (+", n, " suppressed in last ", guardLogInterval, ")")
	return g.mode == GuardEnforce
}

// —— destination classification ——

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

var reservedV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), // incl. 255.255.255.255
}

// blockedAddrKind returns why addr must not be an egress destination, or "".
func blockedAddrKind(addr netip.Addr) string {
	if !addr.IsValid() {
		return "invalid_addr"
	}
	addr = addr.Unmap()
	switch {
	case addr.IsLoopback():
		return "loopback"
	case addr.IsUnspecified():
		return "unspecified"
	case addr.IsLinkLocalUnicast(): // 169.254/16 (cloud metadata), fe80::/10
		return "link_local"
	case addr.IsPrivate(): // 10/8 172.16/12 192.168/16 fc00::/7
		return "private"
	case addr.Is4() && cgnatPrefix.Contains(addr):
		return "cgnat"
	case addr.IsMulticast(), addr.IsInterfaceLocalMulticast(), addr.IsLinkLocalMulticast():
		return "multicast"
	}
	if addr.Is4() {
		for _, p := range reservedV4 {
			if p.Contains(addr) {
				return "reserved"
			}
		}
	}
	if isSelfAddr(addr) {
		return "self"
	}
	return ""
}

var (
	selfOnce  sync.Once
	selfAddrs map[netip.Addr]struct{}
)

// isSelfAddr: this host's own global addresses (so a user cannot reach services
// bound on the node's public IP from the inside). Snapshot at first use.
func isSelfAddr(addr netip.Addr) bool {
	selfOnce.Do(func() {
		selfAddrs = map[netip.Addr]struct{}{}
		ifAddrs, err := net.InterfaceAddrs()
		if err != nil {
			return
		}
		for _, a := range ifAddrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				selfAddrs[p.Addr().Unmap()] = struct{}{}
			}
		}
	})
	_, ok := selfAddrs[addr]
	return ok
}

var blockedNameSuffixes = []string{".localhost", ".local", ".internal", ".lan", ".home.arpa", ".localdomain"}

func blockedNameKind(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "localhost" || name == "metadata" {
		return "local_name"
	}
	for _, s := range blockedNameSuffixes {
		if strings.HasSuffix(name, s) {
			return "local_name"
		}
	}
	return ""
}

func blockedDestKind(network string, dest M.Socksaddr) string {
	if network == N.NetworkTCP && dest.Port == 25 {
		return "smtp"
	}
	if dest.IsFqdn() {
		return blockedNameKind(dest.Fqdn)
	}
	return blockedAddrKind(dest.Addr)
}

// —— dialer ——

type guardDialer struct {
	g       *guard
	inner   N.Dialer // nil = dial directly from this node
	timeout time.Duration
}

func (d *guardDialer) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	if kind := blockedDestKind(N.NetworkTCP, dest); kind != "" && d.g.violation(ctx, kind, "tcp", dest.String()) {
		return nil, errGuardBlocked
	}
	var conn net.Conn
	var err error
	if d.dialsDirect(dest) {
		// Direct dial: re-check the address actually connected to, so a public
		// name resolving to 127.0.0.1 / 169.254.169.254 cannot slip through.
		nd := &net.Dialer{Timeout: d.timeout, ControlContext: d.control(ctx)}
		if up, ok := d.inner.(*UpstreamDialer); ok && up != nil {
			nd.Timeout = upstreamHandshakeTimeout
		}
		conn, err = nd.DialContext(ctx, network, dest.String())
	} else {
		conn, err = d.inner.DialContext(ctx, network, dest)
	}
	if err != nil {
		return nil, err
	}
	return &guardConn{Conn: conn, g: d.g, ctx: ctx, dest: dest.String()}, nil
}

// dialsDirect: no upstream, or an upstream DirectDomains match (which the
// upstream would itself dial directly — we do it here so control() applies).
func (d *guardDialer) dialsDirect(dest M.Socksaddr) bool {
	if d.inner == nil {
		return true
	}
	if up, ok := d.inner.(*UpstreamDialer); ok && up != nil {
		return up.isDirect(dest)
	}
	return false
}

func (d *guardDialer) control(ctx context.Context) func(context.Context, string, string, syscall.RawConn) error {
	return func(_ context.Context, network, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil
		}
		if kind := blockedAddrKind(ap.Addr()); kind != "" && d.g.violation(ctx, kind+"_resolved", network, address) {
			return errGuardBlocked
		}
		return nil
	}
}

func (d *guardDialer) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	var pc net.PacketConn
	var err error
	if d.inner == nil {
		var lc net.ListenConfig
		pc, err = lc.ListenPacket(ctx, N.NetworkUDP, ":0")
	} else {
		pc, err = d.inner.ListenPacket(ctx, dest)
	}
	if err != nil {
		return nil, err
	}
	return &guardPacketConn{inner: bufio.NewPacketConn(pc), g: d.g, ctx: ctx, firstSeen: map[netip.AddrPort]struct{}{}}, nil
}

// —— TCP: inspect the first client→destination bytes ——

// guardConn is the outbound (node→destination) conn. Its first Write carries
// the client's opening bytes, which is where the BitTorrent handshake and HTTP
// tracker request line live. Only net.Conn methods are exposed on purpose.
type guardConn struct {
	net.Conn
	g       *guard
	ctx     context.Context
	dest    string
	checked bool
}

func (c *guardConn) Write(p []byte) (int, error) {
	if !c.checked && len(p) > 0 {
		c.checked = true
		if kind := sniffStreamBT(p); kind != "" && c.g.violation(c.ctx, kind, "tcp", c.dest) {
			_ = c.Conn.Close()
			return 0, errGuardBlocked
		}
	}
	return c.Conn.Write(p)
}

const btHandshake = "\x13BitTorrent protocol"

func sniffStreamBT(p []byte) string {
	if len(p) >= len(btHandshake) && string(p[:len(btHandshake)]) == btHandshake {
		return "bittorrent"
	}
	if bytes.HasPrefix(p, []byte("GET /")) {
		line := p
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line = line[:i]
		}
		if bytes.Contains(line, []byte("info_hash=")) &&
			(bytes.Contains(line, []byte("/announce")) || bytes.Contains(line, []byte("/scrape"))) {
			return "bittorrent_tracker"
		}
	}
	return ""
}

// —— UDP: check every outgoing packet's destination and payload ——

// guardPacketConn wraps the node's outbound UDP socket. A user's UDP session
// can send to arbitrary destinations, so the check is per packet. Blocked
// packets are dropped silently (an error would tear down the whole session,
// e.g. over one stray SSDP multicast in global mode).
type guardPacketConn struct {
	inner N.NetPacketConn
	g     *guard
	ctx   context.Context

	mu        sync.Mutex
	firstSeen map[netip.AddrPort]struct{} // destinations already sent to (uTP SYN check)
}

func (c *guardPacketConn) allow(dest M.Socksaddr, payload []byte) bool {
	if kind := blockedDestKind(N.NetworkUDP, dest); kind != "" {
		return !c.g.violation(c.ctx, kind, "udp", dest.String())
	}
	if kind := c.sniffPacketBT(dest, payload); kind != "" {
		return !c.g.violation(c.ctx, kind, "udp", dest.String())
	}
	return true
}

func (c *guardPacketConn) sniffPacketBT(dest M.Socksaddr, p []byte) string {
	if isDHT(p) {
		return "bittorrent_dht"
	}
	if isUDPTrackerConnect(p) {
		return "bittorrent_tracker"
	}
	if dest.IsFqdn() || dest.Port == 53 {
		return ""
	}
	ap := dest.AddrPort()
	c.mu.Lock()
	_, seen := c.firstSeen[ap]
	if !seen && len(c.firstSeen) < 4096 {
		c.firstSeen[ap] = struct{}{}
	}
	c.mu.Unlock()
	// Only the FIRST packet to a destination can be a uTP SYN. Restricting the
	// check to it keeps QUIC (long header 0xC0+ on first packets) and later
	// short-header packets out of reach of this fairly loose signature.
	if !seen && isUTPSyn(p) {
		return "bittorrent_utp"
	}
	return ""
}

// isDHT: BitTorrent DHT KRPC (BEP 5) — bencoded dict with sorted keys, so a
// query starts "d1:ad2:id20:" and a response "d1:rd2:id20:".
func isDHT(p []byte) bool {
	return bytes.HasPrefix(p, []byte("d1:ad2:id20:")) || bytes.HasPrefix(p, []byte("d1:rd2:id20:"))
}

// isUDPTrackerConnect: BEP 15 connect request (magic protocol id, action 0).
func isUDPTrackerConnect(p []byte) bool {
	return len(p) >= 16 && binary.BigEndian.Uint64(p[:8]) == 0x41727101980 && binary.BigEndian.Uint32(p[8:12]) == 0
}

// isUTPSyn: BEP 29 ST_SYN, version 1 (first byte 0x41), timestamp_difference 0
// (nothing received yet), and an extension chain that consumes the packet
// exactly (a SYN carries no payload).
func isUTPSyn(p []byte) bool {
	if len(p) < 20 || p[0] != 0x41 || binary.BigEndian.Uint32(p[8:12]) != 0 {
		return false
	}
	ext, off := p[1], 20
	for ext != 0 {
		if ext > 4 || off+2 > len(p) {
			return false
		}
		ext = p[off]
		off += 2 + int(p[off+1])
		if off > len(p) {
			return false
		}
	}
	return off == len(p)
}

func (c *guardPacketConn) WritePacket(buffer *buf.Buffer, dest M.Socksaddr) error {
	if !c.allow(dest, buffer.Bytes()) {
		buffer.Release()
		return nil
	}
	return c.inner.WritePacket(buffer, dest)
}

func (c *guardPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if !c.allow(M.SocksaddrFromNet(addr).Unwrap(), p) {
		return len(p), nil
	}
	return c.inner.WriteTo(p, addr)
}

func (c *guardPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return c.inner.ReadPacket(buffer)
}

func (c *guardPacketConn) ReadFrom(p []byte) (int, net.Addr, error) { return c.inner.ReadFrom(p) }
func (c *guardPacketConn) Close() error                             { return c.inner.Close() }
func (c *guardPacketConn) LocalAddr() net.Addr                      { return c.inner.LocalAddr() }
func (c *guardPacketConn) SetDeadline(t time.Time) error            { return c.inner.SetDeadline(t) }
func (c *guardPacketConn) SetReadDeadline(t time.Time) error        { return c.inner.SetReadDeadline(t) }
func (c *guardPacketConn) SetWriteDeadline(t time.Time) error       { return c.inner.SetWriteDeadline(t) }
