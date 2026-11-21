package services

import (
	"strings"
	"testing"
	"time"

	m "github.com/webtor-io/abuse-store/models"
)

// A report against an exempt infohash is mailed like any other, but the
// reporter must not be told it was added to the stoplist, and support must
// see that it was not.
func TestExemptReportLetters(t *testing.T) {
	ms := &Mailer{support: "support@example.com"}
	for _, exempt := range []bool{false, true} {
		const h = "465d6a0eac381e68ca77115f44f19f0c968b9590"
		n := &Notice{Abuse: &m.Abuse{Infohash: h}, Hashes: []NoticeHash{{Infohash: h, Exempt: exempt}}}
		user, err := ms.render(n, userTemplate)
		if err != nil {
			t.Fatal(err)
		}
		support, err := ms.render(n, supportTemplate)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(user, "added to stoplist"); got == exempt {
			t.Errorf("exempt=%v: reporter told added to stoplist = %v", exempt, got)
		}
		if got := strings.Contains(user, "under moderation"); got != exempt {
			t.Errorf("exempt=%v: reporter told under moderation = %v", exempt, got)
		}
		if got := strings.Contains(support, "EXEMPT"); got != exempt {
			t.Errorf("exempt=%v: support letter marks EXEMPT = %v", exempt, got)
		}
		if got := strings.Contains(support, "Data purge"); got == exempt {
			t.Errorf("exempt=%v: support letter announces a purge = %v", exempt, got)
		}
	}
}

// One letter per notice lists every infohash it named, and support learns
// when the data goes and how to keep it — or that it already went.
func TestNoticeLettersListEveryHashAndThePurge(t *testing.T) {
	ms := &Mailer{support: "support@example.com"}
	const a, b, c = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222", "3333333333333333333333333333333333333333"
	at := time.Date(2026, 11, 24, 9, 30, 0, 0, time.UTC)
	n := &Notice{
		Abuse:  &m.Abuse{Infohash: a, PurgeAfter: at},
		Hashes: []NoticeHash{{Infohash: a}, {Infohash: b, Existed: true}, {Infohash: c, Exempt: true}},
	}
	user, err := ms.render(n, userTemplate)
	if err != nil {
		t.Fatal(err)
	}
	support, err := ms.render(n, supportTemplate)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{a, b, c} {
		if !strings.Contains(user, h) || !strings.Contains(support, h) {
			t.Errorf("%s missing from a letter", h)
		}
	}
	for _, want := range []string{b + " (already in the stoplist)", c + " (exempt)", "scheduled for 2026-11-24 09:30 UTC", "Setting exempt", "EXEMPT"} {
		if !strings.Contains(support, want) {
			t.Errorf("support letter lacks %q:\n%s", want, support)
		}
	}
	if !strings.Contains(user, c+" (under moderation)") || !strings.Contains(user, "added to stoplist") {
		t.Errorf("reporter letter:\n%s", user)
	}

	// Nothing new: no purge was scheduled by this notice.
	n.Hashes = n.Hashes[1:]
	if support, err = ms.render(n, supportTemplate); err != nil || strings.Contains(support, "Data purge") {
		t.Errorf("notice adding no row announces a purge (%v):\n%s", err, support)
	}

	// An immediate purge covers the known hash too.
	n.PurgeNow = true
	support, err = ms.render(n, supportTemplate)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(support, "Data purge: immediate") || strings.Contains(support, "scheduled") {
		t.Errorf("purge_now support letter:\n%s", support)
	}
}
