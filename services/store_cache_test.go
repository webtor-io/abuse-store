package services

import (
	"testing"

	"github.com/dgraph-io/badger/v3"
	m "github.com/webtor-io/abuse-store/models"
)

// A row with no infohash must still contribute its fingerprint. Badger refuses
// an empty key, and the infohash entry used to be written first, so the whole
// call failed before the fingerprint was ever stored — losing the only usable
// half of the row.
func TestPushToCacheWithoutInfohashStillCachesFingerprint(t *testing.T) {
	s := newTestStore(t)
	fp := digest(0x7F)

	if err := s.pushToCache(&m.Abuse{Infohash: "", Fingerprint: fp}); err != nil {
		t.Fatalf("a row without an infohash must not fail the cache write: %v", err)
	}
	if !blocked(t, s, "some-other-hash", fp) {
		t.Fatal("fingerprint of an infohash-less row never reached the cache")
	}
}

// Both halves of a normal row land in the cache.
func TestPushToCacheStoresBothArms(t *testing.T) {
	s := newTestStore(t)
	fp := digest(0x2A)
	const h = "aa11bb22cc33dd44ee55ff6677889900aabbccdd"

	if err := s.pushToCache(&m.Abuse{Infohash: h, Fingerprint: fp}); err != nil {
		t.Fatal(err)
	}
	if !blocked(t, s, h, nil) {
		t.Fatal("infohash arm not cached")
	}
	if !blocked(t, s, "unrelated", fp) {
		t.Fatal("fingerprint arm not cached")
	}
}

// syncRow's contract is what keeps one bad row from ending the load: it must
// report failure without returning an error, whatever the row looks like. The
// startup Sync is fatal, so a propagated error means a crash loop rather than
// one missing stoplist entry.
func TestSyncRowReportsFailureWithoutAbortingTheWalk(t *testing.T) {
	s := newTestStore(t)
	// A key larger than Badger's limit — a row that genuinely cannot be cached.
	unusable := &m.Abuse{Infohash: string(make([]byte, 1<<21))}
	if s.syncRow(unusable) {
		t.Fatal("an uncacheable row was reported as synced")
	}
	// The walk continues: a healthy row after it still lands.
	const good = "beef000000000000000000000000000000000000"
	if !s.syncRow(&m.Abuse{Infohash: good}) {
		t.Fatal("a healthy row after the unusable one was not synced")
	}
	if !blocked(t, s, good, nil) {
		t.Fatal("the healthy row never reached the cache")
	}
}

// Guards the fingerprint-first ordering directly: with the infohash key
// unusable, the fingerprint must already be committed.
func TestFingerprintIsWrittenBeforeInfohash(t *testing.T) {
	s := newTestStore(t)
	fp := digest(0x5C)
	_ = s.pushToCache(&m.Abuse{Infohash: "", Fingerprint: fp})

	err := s.b.View(func(txn *badger.Txn) error {
		_, err := txn.Get(fingerprintKey(fp))
		return err
	})
	if err != nil {
		t.Fatalf("fingerprint was not committed: %v", err)
	}
}

// A row deleted from the table must stop blocking at the next sync. Sync used
// to only upsert, so a lifted ban stayed in the cache until the pod restarted.
// Both arms of the deleted row go; both arms of the surviving row stay.
func TestPruneDropsRowsGoneFromTheTable(t *testing.T) {
	s := newTestStore(t)
	const kept, gone = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"
	keptFP, goneFP := digest(0x11), digest(0x22)
	for _, a := range []*m.Abuse{{Infohash: kept, Fingerprint: keptFP}, {Infohash: gone, Fingerprint: goneFP}} {
		if err := s.pushToCache(a); err != nil {
			t.Fatal(err)
		}
	}

	n, err := s.prune(map[string]struct{}{kept: {}, string(fingerprintKey(keptFP)): {}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("pruned %d keys, want 2 (infohash + fingerprint of the deleted row)", n)
	}
	if blocked(t, s, gone, nil) || blocked(t, s, "unrelated", goneFP) {
		t.Fatal("deleted row still blocks")
	}
	if !blocked(t, s, kept, nil) || !blocked(t, s, "unrelated", keptFP) {
		t.Fatal("surviving row was pruned")
	}
}

// An exempt row shadows every row for its infohash, both arms, even when the
// blocking row comes first — the order rows come back from Postgres is not
// guaranteed. Other infohashes are untouched.
func TestLoadExemptShadowsSameInfohashInAnyOrder(t *testing.T) {
	s := newTestStore(t)
	const cleared, other = "3333333333333333333333333333333333333333", "4444444444444444444444444444444444444444"
	clearedFP := digest(0x33)
	keep, synced, _, exempt := s.load([]*m.Abuse{
		{Infohash: cleared, Fingerprint: clearedFP},
		{Infohash: other},
		{Infohash: cleared, Exempt: true},
	})
	if synced != 1 || exempt != 1 {
		t.Fatalf("synced=%d exempt=%d, want 1 and 1", synced, exempt)
	}
	if blocked(t, s, cleared, nil) || blocked(t, s, "unrelated", clearedFP) {
		t.Fatal("exempt infohash blocks")
	}
	if !blocked(t, s, other, nil) {
		t.Fatal("unrelated row lost")
	}
	if _, ok := keep[cleared]; ok {
		t.Fatal("exempt infohash would survive the prune")
	}
}

// A ban flipped to exempt is lifted by the next sync, not the next restart.
func TestExemptingACachedBanLiftsItOnSync(t *testing.T) {
	s := newTestStore(t)
	const h = "5555555555555555555555555555555555555555"
	keep, _, _, _ := s.load([]*m.Abuse{{Infohash: h}})
	if _, err := s.prune(keep); err != nil || !blocked(t, s, h, nil) {
		t.Fatalf("setup: ban not cached (err=%v)", err)
	}
	keep, _, _, _ = s.load([]*m.Abuse{{Infohash: h, Exempt: true}})
	if _, err := s.prune(keep); err != nil {
		t.Fatal(err)
	}
	if blocked(t, s, h, nil) {
		t.Fatal("exempted ban still blocks after sync")
	}
}

// A fingerprint-only row marked exempt stops blocking itself, but must not
// exempt the other fingerprint-only bans, whose infohash is also empty.
func TestExemptRowWithoutInfohashExemptsOnlyItself(t *testing.T) {
	s := newTestStore(t)
	fp, exemptFP := digest(0x66), digest(0x77)
	s.load([]*m.Abuse{{Exempt: true, Fingerprint: exemptFP}, {Fingerprint: fp}})
	if blocked(t, s, "unrelated", exemptFP) {
		t.Fatal("exempt fingerprint-only row still blocks")
	}
	if !blocked(t, s, "unrelated", fp) {
		t.Fatal("fingerprint-only ban lost to an exempt row with no infohash")
	}
}
