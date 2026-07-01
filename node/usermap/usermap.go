// Package usermap keeps a STABLE mapping from a user's UUID (the billing key) to
// the integer INDEX the sing protocol services authenticate/meter by.
//
// Why stable indices matter (the VLESS hot-reload "WP-A" lesson): every protocol
// service authenticates by an []int index and reports the matched index up the
// handler context (see node/userattr). If the same UUID were assigned a
// different index across two UpdateUsers calls, authentication and per-user
// metering would silently attribute to the WRONG user. So a UUID must map to the
// same index for its whole lifetime, and a removed UUID's index must not be
// reused immediately (a fresh connection racing an in-flight one could otherwise
// inherit stale counters).
//
// This type is the single place that logic lives, shared by all six node
// packages so they diff identically. It is NOT safe for concurrent use; callers
// (the node) serialize UpdateUsers.
package usermap

// Diff is the outcome of reconciling a new full user set against the current
// one: the resulting index-aligned slices to feed the protocol service's
// UpdateUsers, plus which UUIDs were removed (so the node can kick their live
// connections — R3 linkage).
type Diff struct {
	// Indices and UUIDs are index-aligned and cover the FULL post-update user
	// set (UpdateUsers is whole-set replace, not incremental). Indices[i] is the
	// stable int index for UUIDs[i].
	Indices []int
	UUIDs   []string
	// Removed are UUIDs present before this update but not after — their live
	// connections should be kicked.
	Removed []string
}

// Map assigns and remembers stable indices for UUIDs.
type Map struct {
	byUUID  map[string]int // uuid -> stable index
	byIndex map[int]string // index -> uuid (reverse, for attribution)
	// freeList holds indices retired by removals, NOT reused until a full cycle
	// (see Reconcile) — retired indices are parked here and only handed out after
	// the next reconcile, so an index never jumps user within one update.
	retired []int
	next    int // next never-used index
}

// New builds an empty map.
func New() *Map {
	return &Map{byUUID: map[string]int{}, byIndex: map[int]string{}, next: 0}
}

// UUIDForIndex reverse-resolves an authenticated index to its UUID (used by the
// egress handler to attribute a connection for metering/billing). ok is false if
// the index is unknown.
func (m *Map) UUIDForIndex(index int) (uuid string, ok bool) {
	uuid, ok = m.byIndex[index]
	return
}

// Reconcile updates the map to exactly the given UUID set and returns the Diff
// to push to the protocol service. Existing UUIDs keep their index; new UUIDs
// get a fresh index (preferring never-used over retired, so retired indices
// stay parked one cycle); removed UUIDs are reported in Diff.Removed and their
// indices retired (parked, not immediately reused).
func (m *Map) Reconcile(uuids []string) Diff {
	// Dedup input, preserving first occurrence.
	seen := map[string]bool{}
	want := make([]string, 0, len(uuids))
	for _, u := range uuids {
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		want = append(want, u)
	}

	// Removed = current UUIDs not in want.
	var removed []string
	for u := range m.byUUID {
		if !seen[u] {
			removed = append(removed, u)
		}
	}
	// Retire removed indices (park them; do not reuse this cycle).
	for _, u := range removed {
		idx := m.byUUID[u]
		delete(m.byUUID, u)
		delete(m.byIndex, idx)
		m.retired = append(m.retired, idx)
	}

	// Assign indices for the wanted set: keep existing, allocate for new.
	indices := make([]int, len(want))
	for i, u := range want {
		if idx, ok := m.byUUID[u]; ok {
			indices[i] = idx
			continue
		}
		idx := m.allocIndex()
		m.byUUID[u] = idx
		m.byIndex[idx] = u
		indices[i] = idx
	}

	return Diff{Indices: indices, UUIDs: want, Removed: removed}
}

// allocIndex hands out a fresh never-used index. Retired indices are intentionally
// NOT reused here (they were parked this cycle by Reconcile); they become
// available as never-used only if a later New/Reset rebuilds. Simplicity over
// index compaction: index space is int, exhaustion is not a real concern for a
// per-node user count.
func (m *Map) allocIndex() int {
	idx := m.next
	m.next++
	return idx
}
