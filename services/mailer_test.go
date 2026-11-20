package services

import (
	"strings"
	"testing"

	m "github.com/webtor-io/abuse-store/models"
)

// A report against an exempt infohash is mailed like any other, but the
// reporter must not be told it was added to the stoplist, and support must
// see that it was not.
func TestExemptReportLetters(t *testing.T) {
	ms := &Mailer{support: "support@example.com"}
	for _, exempt := range []bool{false, true} {
		a := &m.Abuse{Infohash: "465d6a0eac381e68ca77115f44f19f0c968b9590", Exempt: exempt}
		user, err := ms.render(a, userTemplate)
		if err != nil {
			t.Fatal(err)
		}
		support, err := ms.render(a, supportTemplate)
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
	}
}
