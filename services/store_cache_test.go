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

// syncRow is the entire body of Sync's ForEach callback, so its contract is
// what keeps one bad row from ending the walk: it must report failure without
// returning an error, whatever the row looks like. ForEach stops on the first
// error returned, and the startup Sync is fatal, so a propagated error means
// a crash loop rather than one missing stoplist entry.
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
