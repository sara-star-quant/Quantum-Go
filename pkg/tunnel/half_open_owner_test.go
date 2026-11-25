package tunnel

import "testing"

// A responder frees its half-open slot and source mapping when it finishes or fails. The same
// remote address can start a new responder while an older handshake loop is still lingering, and
// the old loop then runs its cleanup again. The cleanup must free only what its own session
// holds: releasing by address alone would drop the newer responder's slot and mapping.
func TestStaleCleanupDoesNotReleaseANewerRespondersSlot(t *testing.T) {
	r := newConnRegistry(8)
	const src = "198.51.100.7:4000"
	build := func() *datagramSession { return &datagramSession{} }

	oldDS, ok := r.reserveSource(src, build)
	if !ok {
		t.Fatal("first responder was not admitted")
	}
	r.releaseSource(src, oldDS)
	if r.halfOpenLoad() != 0 {
		t.Fatalf("cleanup left %d half-open slots", r.halfOpenLoad())
	}

	// The same address redials and gets a new responder.
	newDS, ok := r.reserveSource(src, build)
	if !ok || newDS == oldDS {
		t.Fatal("the redial was not admitted as a new responder")
	}

	// The old loop's cleanup runs again (a lingering loop, or a failed branch after surfacing).
	r.releaseSource(src, oldDS)

	if got := r.halfOpenLoad(); got != 1 {
		t.Fatalf("stale cleanup changed the half-open count to %d, want 1", got)
	}
	if !r.sourceOwner(src, newDS) {
		t.Fatal("stale cleanup removed the newer responder's source mapping")
	}

	// The real owner still frees its own slot, and a second cleanup is a no-op.
	r.releaseSource(src, newDS)
	r.releaseSource(src, newDS)
	if r.halfOpenLoad() != 0 || r.sourceOwner(src, newDS) {
		t.Fatalf("owner cleanup left count %d", r.halfOpenLoad())
	}
}
