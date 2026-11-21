package services

import (
	"slices"
	"testing"
	"time"

	m "github.com/webtor-io/abuse-store/models"
)

// Every hash of a notice passes the same anchored check, repeats collapse,
// and the primary stays first (its row carries the fingerprint).
func TestNoticeInfohashes(t *testing.T) {
	const a, b = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	got, err := noticeInfohashes(" "+a, []string{"B" + b[1:], a, b})
	if err != nil || !slices.Equal(got, []string{a, b}) {
		t.Fatalf("got %v, %v; want [%s %s]", got, err, a, b)
	}
	// A fingerprint-only ban keeps its empty primary.
	if got, err := noticeInfohashes("", []string{b}); err != nil || !slices.Equal(got, []string{"", b}) {
		t.Fatalf("fingerprint-only: got %v, %v", got, err)
	}
	for _, bad := range []string{"", "magnet:?xt=urn:btih:" + a, a[:39]} {
		if _, err := noticeInfohashes(a, []string{bad}); err == nil {
			t.Errorf("extra %q accepted", bad)
		}
	}
	if _, err := noticeInfohashes(a[:39], nil); err == nil {
		t.Error("short primary accepted")
	}
}

// A ban inside its purge delay blocks but is not due; it becomes due once
// purge_after passes. Rows from before the column (zero) are due, and one due
// row is enough.
func TestDueInfohashes(t *testing.T) {
	now := time.Now()
	const old, pending, passed, mixed = "o", "p", "q", "x"
	due := dueInfohashes([]*m.Abuse{
		{Infohash: old},
		{Infohash: pending, PurgeAfter: now.Add(time.Hour)},
		{Infohash: passed, PurgeAfter: now.Add(-time.Second)},
		{Infohash: mixed, PurgeAfter: now.Add(time.Hour)},
		{Infohash: mixed, PurgeAfter: now.Add(-time.Hour)},
	}, now)
	for h, want := range map[string]bool{old: true, pending: false, passed: true, mixed: true} {
		if _, got := due[h]; got != want {
			t.Errorf("%s due = %v, want %v", h, got, want)
		}
	}
	if _, ok := dueInfohashes([]*m.Abuse{{Infohash: pending, PurgeAfter: now.Add(time.Hour)}}, now.Add(2*time.Hour))[pending]; !ok {
		t.Error("pending ban not due after its purge_after")
	}
}
