// Package egress is the STABLE library API for driving a six-protocol over-realm
// egress node from another process — specifically realm-agent (deploy scheme
// "甲": realm-agent imports this package instead of exec-ing a sing-box fork and
// talking to it over v2ray_api / clash_api / hotreload). One import, one Node
// interface, no local IPC, no fork.
//
// A Node is a running egress for ONE protocol on ONE rendezvous slot. The caller:
//   - New(Config) builds it (does not start),
//   - Start(ctx, packetConn) brings it online on a UDP socket,
//   - UpdateUsers(users) hot-reloads the whole billable user set (R1),
//   - CollectStats(reset) reads per-user traffic for billing/observability (R2),
//   - KickUser(uuid) drops a user's live connections on quota/expiry (R3),
//   - Close() stops it.
//
// The protocol engines are reused from sing (zero fork); this package only
// selects and wires the right node/* implementation behind a uniform interface.
package egress

import (
	"context"
	"net"

	"github.com/antsbtw/otun-s-egress/node/meter"
	"github.com/antsbtw/otun-s-egress/node/userattr"
)

// User re-exports the billable-user credential type so callers depend only on
// this package.
type User = userattr.User

// UserStat re-exports the per-user traffic counter.
type UserStat = meter.UserStat

// ConnInfo re-exports the per-connection observability snapshot. ConnInfo.Protocol
// tags which protocol served the conn — meaningful when several protocol nodes
// share one Registry (C.1).
type ConnInfo = meter.ConnInfo

// Registry re-exports the shared per-user meter + connection registry. Build one
// with NewRegistry and inject it into several nodes (via Config.Meter or
// NewShared) so billing/kick/snapshot span all of them in one call (C.1).
type Registry = meter.Registry

// NewRegistry builds an empty shared Registry. Inject the SAME instance into
// several protocol Configs (Config.Meter) — or use NewShared — so one physical
// node's six protocols share one billing/kick/snapshot surface (C.1). Operate on
// it directly: reg.CollectStats(true) / reg.KickUser(uuid) / reg.Snapshot() each
// cover every node sharing it, atomically and without merging six results.
func NewRegistry() *Registry { return meter.New() }

// Node is a running egress for one protocol on one rendezvous slot. All six
// protocol node packages satisfy it.
type Node interface {
	// Start opens the egress on conn (a UDP socket): registers on the rendezvous
	// and serves the protocol on the punched hole.
	Start(ctx context.Context, conn net.PacketConn) error
	// Close stops the node.
	Close() error
	// UpdateUsers replaces the whole online user set (whole-set semantics; add/
	// remove without dropping existing connections; stable per-UUID indices).
	UpdateUsers(users []User) error
	// CollectStats returns per-user traffic. reset=true reads+zeroes (billing,
	// bill-once); reset=false is a non-destructive snapshot (observability). Never
	// use one reset=true call for both.
	CollectStats(reset bool) []UserStat
	// KickUser force-closes all live connections of a user, returning the count.
	KickUser(uuid string) int
	// ActiveConnections returns a read-only snapshot of all live connections for
	// realm-agent's obs risk-control (conn_lifecycle / egress_behavior). Metadata
	// only (destination/source/bytes/start), never payload.
	ActiveConnections() []ConnInfo
	// ActiveUserCount returns the number of distinct users with at least one
	// live connection (dedup by UUID) — the capacity-watermark metric (occupied
	// user seats), vs ActiveConnections() which is the utilization metric
	// (connection count; one user may hold many conns). With a shared Registry
	// (C.1) the count spans every node sharing it, deduped globally across
	// protocols: a user on hy2+reality at once counts as 1.
	ActiveUserCount() int
}
