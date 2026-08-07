package services

import (
	"bytes"
	"errors"
	"testing"

	"github.com/dgraph-io/badger/v3"
)

// newTestStore builds a Store backed by an in-memory Badger. Check never
// touches Postgres, so the blocking decision can be tested on its own.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true).WithLogger(nil))
	if err != nil {
		t.Fatalf("badger: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Store{b: db}
}

func digest(b byte) []byte {
	d := make([]byte, fingerprintSize)
	for i := range d {
		d[i] = b
	}
	return d
}

func blocked(t *testing.T, s *Store, hash string, fps ...[]byte) bool {
	t.Helper()
	err := s.Check(hash, fps)
	if err == nil {
		return true
	}
	if errors.Is(err, ErrNotFound) {
		return false
	}
	t.Fatalf("Check: %v", err)
	return false
}

func TestCheckMatchesInfohash(t *testing.T) {
	s := newTestStore(t)
	if err := s.pushToCacheRaw("abc123", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if !blocked(t, s, "abc123") {
		t.Fatal("known infohash not blocked")
	}
	if blocked(t, s, "other") {
		t.Fatal("unknown infohash blocked")
	}
}

// The point of the whole mechanism: a torrent whose infohash was never
// reported is still blocked when its payload is.
func TestCheckMatchesFingerprintForUnknownInfohash(t *testing.T) {
	s := newTestStore(t)
	fp := digest(0xAB)
	if err := s.pushFingerprintToCache(fp); err != nil {
		t.Fatal(err)
	}
	if !blocked(t, s, "never-reported-hash", fp) {
		t.Fatal("payload is blocked but its re-upload was not")
	}
	if blocked(t, s, "never-reported-hash", digest(0xCD)) {
		t.Fatal("unrelated payload blocked")
	}
	if blocked(t, s, "never-reported-hash") {
		t.Fatal("blocked with no fingerprints supplied")
	}
}

// Any one match blocks; the caller passes every fingerprint it derived.
func TestCheckMatchesAnyOfSeveral(t *testing.T) {
	s := newTestStore(t)
	fp := digest(0x11)
	if err := s.pushFingerprintToCache(fp); err != nil {
		t.Fatal(err)
	}
	if !blocked(t, s, "h", digest(0x22), fp, digest(0x33)) {
		t.Fatal("match in a later position missed")
	}
}

// A digest of the wrong length must be ignored rather than probed: it can only
// come from a caller bug, and treating it as a key would let a short value sit
// in the index shadowing nothing.
func TestCheckIgnoresWrongLengthFingerprints(t *testing.T) {
	s := newTestStore(t)
	short := []byte("short")
	if err := s.b.Update(func(txn *badger.Txn) error {
		return txn.SetEntry(badger.NewEntry(fingerprintKey(short), []byte{1}))
	}); err != nil {
		t.Fatal(err)
	}
	if blocked(t, s, "h", short) {
		t.Fatal("a wrong-length fingerprint was honoured")
	}
}

// Digests are raw bytes and infohashes are hex strings; the namespace prefix
// keeps them from ever addressing the same key.
func TestFingerprintKeyIsNamespaced(t *testing.T) {
	fp := digest(0x41) // all 'A' — valid ASCII, so a plausible collision shape
	if bytes.Equal(fingerprintKey(fp), fp) {
		t.Fatal("fingerprint key is not namespaced")
	}
	s := newTestStore(t)
	if err := s.pushFingerprintToCache(fp); err != nil {
		t.Fatal(err)
	}
	// Same bytes read as an infohash must not hit the fingerprint entry.
	if blocked(t, s, string(fp)) {
		t.Fatal("fingerprint entry was reachable through the infohash key space")
	}
}
