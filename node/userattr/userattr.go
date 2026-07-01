// Package userattr resolves the authenticated user behind an egress connection.
//
// Every over-realm protocol's sing service, after authenticating a connection,
// stashes the matched user's INDEX into the handler context via
// auth.ContextWithUser (hy2/tuic/trojan/vmess/vless/ss-multi all do this — it is
// the sing ecosystem's uniform convention). The egress handlers previously threw
// that context away; this package is the single point that reads it back, so
// per-user metering (R2), per-user kick (R3), and billing (via the node's
// index→UUID map) can attribute each connection to a concrete user.
//
// This is the R2a foundation: attribution without touching any protocol engine —
// the index is already in the context, we just stop discarding it.
package userattr

import (
	"context"
	"strconv"

	"github.com/sagernet/sing/common/auth"
)

// User is a billable user's egress-side credential + stable identity, shared by
// all six node packages' UpdateUsers. UUID is the billing primary key (the
// realm-agent uses it to meter and kick); the other fields are the per-protocol
// credential (only the ones a given protocol needs are read):
//   - hy2 / trojan / ss : Password
//   - tuic              : UUID (as the TUIC uuid) + Password
//   - vmess / reality   : UUID
//   - ss                : Method + Password
//   - vmess             : AlterId (usually 0)
//   - reality (vless)   : Flow (usually "")
type User struct {
	UUID     string
	Password string
	Method   string // shadowsocks
	AlterId  int    // vmess
	Flow     string // reality/vless
}

// IndexFromContext returns the authenticated user INDEX the protocol service
// stored for this connection, and whether one was present. The index is the
// []int position passed to the service's UpdateUsers; the node maps it back to a
// UUID. ok is false for connections with no attributed user (should not happen
// on an authenticated egress path, but callers must handle it — e.g. count under
// a sentinel or drop).
func IndexFromContext(ctx context.Context) (index int, ok bool) {
	return auth.UserFromContext[int](ctx)
}

// Label renders the attributed user index for logging. Returns e.g. "3" when a
// user index is present, or "unattributed" when none is — so egress logs make
// it visible whether R2a attribution actually fired on this connection (a real
// authenticated egress connection should always be attributed).
func Label(ctx context.Context) string {
	if idx, ok := IndexFromContext(ctx); ok {
		return strconv.Itoa(idx)
	}
	return "unattributed"
}
