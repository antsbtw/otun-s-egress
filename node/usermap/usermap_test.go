package usermap

import "testing"

// TestStableIndexAcrossReconcile is the R1 core property: a UUID keeps the SAME
// index across UpdateUsers calls (the VLESS "WP-A stable index" lesson), and a
// removed UUID's index is not immediately reused. Drives the [A] -> [A,B] -> [B]
// sequence and asserts A's index never changes and B never inherits A's index.
func TestStableIndexAcrossReconcile(t *testing.T) {
	m := New()

	// [A]
	d1 := m.Reconcile([]string{"A"})
	if len(d1.Indices) != 1 || len(d1.Removed) != 0 {
		t.Fatalf("[A]: got indices=%v removed=%v", d1.Indices, d1.Removed)
	}
	idxA := indexOf(d1, "A")

	// [A, B] — A must keep its index, B gets a different one.
	d2 := m.Reconcile([]string{"A", "B"})
	if indexOf(d2, "A") != idxA {
		t.Fatalf("[A,B]: A index changed from %d to %d", idxA, indexOf(d2, "A"))
	}
	idxB := indexOf(d2, "B")
	if idxB == idxA {
		t.Fatalf("[A,B]: B got A's index %d", idxB)
	}
	if len(d2.Removed) != 0 {
		t.Fatalf("[A,B]: unexpected removed %v", d2.Removed)
	}

	// [B] — A removed, B keeps its index.
	d3 := m.Reconcile([]string{"B"})
	if indexOf(d3, "B") != idxB {
		t.Fatalf("[B]: B index changed from %d to %d", idxB, indexOf(d3, "B"))
	}
	if len(d3.Removed) != 1 || d3.Removed[0] != "A" {
		t.Fatalf("[B]: expected removed=[A], got %v", d3.Removed)
	}

	// Reverse lookup: B's index resolves to B; A's old index no longer resolves.
	if u, ok := m.UUIDForIndex(idxB); !ok || u != "B" {
		t.Fatalf("UUIDForIndex(%d)=%q,%v want B", idxB, u, ok)
	}
	if _, ok := m.UUIDForIndex(idxA); ok {
		t.Fatalf("removed A's index %d still resolves", idxA)
	}

	// Re-adding A must NOT reuse B's index, and (retired-parked) must not collide.
	d4 := m.Reconcile([]string{"A", "B"})
	if indexOf(d4, "A") == idxB {
		t.Fatalf("re-added A collided with B's index %d", idxB)
	}
	if indexOf(d4, "B") != idxB {
		t.Fatalf("B index drifted on re-add of A")
	}
}

// TestDedup ensures duplicate/empty UUIDs are collapsed.
func TestDedup(t *testing.T) {
	m := New()
	d := m.Reconcile([]string{"A", "A", "", "B", "B"})
	if len(d.UUIDs) != 2 {
		t.Fatalf("expected 2 unique users, got %v", d.UUIDs)
	}
}

func indexOf(d Diff, uuid string) int {
	for i, u := range d.UUIDs {
		if u == uuid {
			return d.Indices[i]
		}
	}
	return -1
}
