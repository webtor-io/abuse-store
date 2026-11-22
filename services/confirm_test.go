package services

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/urfave/cli"
	pb "github.com/webtor-io/abuse-store/proto"
	cs "github.com/webtor-io/common-services"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The TestPG ones run against Postgres and NATS like push_pg_test.go; same
// env, same skip. e.form is the public port with --form-confirm.

const reporter = "reporter@example.com"

// takedown is a complete copyright notice from the form.
func takedown(hashes ...string) *pb.PushRequest {
	return &pb.PushRequest{Infohash: hashes[0], ExtraInfohashes: hashes[1:], Source: pb.PushRequest_FORM,
		Cause: pb.PushRequest_ILLEGAL_CONTENT, Email: reporter, ReporterName: "Rights Holder", GoodFaith: true, Authorized: true}
}

var tokenRe = regexp.MustCompile(regexp.QuoteMeta(testConfirmURL) + `\?t=([A-Za-z0-9_-]{43})\n`)

// held pushes in through the form listener, checks it was held, and returns
// the token of the one letter it sent, to in.Email.
func (e *pgEnv) held(t *testing.T, in *pb.PushRequest) string {
	t.Helper()
	r, err := e.form.Push(context.Background(), in)
	if err != nil || !r.GetConfirmationSent() {
		t.Fatalf("form push: %v, confirmation_sent %v", err, r.GetConfirmationSent())
	}
	mail := e.sink.waitFor(t, 1)
	if len(mail) != 1 || mail[0].rcpt != in.Email {
		t.Fatalf("want one letter to %s, got %+v", in.Email, mail)
	}
	e.sink.reset()
	m := tokenRe.FindStringSubmatch(mail[0].body)
	if m == nil {
		t.Fatalf("no confirmation link in %q", mail[0].body)
	}
	return m[1]
}

func confirm(t *testing.T, g *GRPC, tok string) *pb.ConfirmReply {
	t.Helper()
	r, err := g.Confirm(context.Background(), &pb.ConfirmRequest{Token: tok})
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	return r
}

// Held: nothing blocks, nothing is stored in abuse, support hears nothing, and
// the reporter gets one letter with the link. Confirmed: blocked, purge
// scheduled, both letters, the name and statements on the rows and in the
// support letter. Confirmed again: nothing more.
func TestPGFormNoticeWaitsForConfirmation(t *testing.T) {
	e := newPGEnv(t, "72h")
	r, err := e.form.Push(context.Background(), takedown(hashA, hashB))
	if err != nil || !r.GetConfirmationSent() {
		t.Fatalf("push: %v, confirmation_sent %v", err, r.GetConfirmationSent())
	}
	if blocked(t, e.s, hashA, nil) || blocked(t, e.s, hashB, nil) {
		t.Fatal("blocked before confirmation")
	}
	if n := e.count(t, `SELECT count(*) FROM abuse`); n != 0 {
		t.Fatalf("%d abuse rows before confirmation", n)
	}
	mail := e.sink.waitFor(t, 1)
	if len(mail) != 1 || mail[0].rcpt != reporter {
		t.Fatalf("want one letter, to the reporter: %+v", mail)
	}
	subj := mail.subject(t, reporter)
	if !regexp.MustCompile(`^Confirm your report [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(subj) {
		t.Fatalf("subject %q", subj)
	}
	for _, want := range []string{"2 torrent(s):\n" + hashA + "\n" + hashB + "\n", "within 72 hours"} {
		if !strings.Contains(mail[0].body, want) {
			t.Errorf("confirmation letter lacks %q:\n%s", want, mail[0].body)
		}
	}
	e.sink.reset()
	tok := tokenRe.FindStringSubmatch(mail[0].body)[1]

	if c := confirm(t, e.form, tok); c.GetStatus() != pb.ConfirmReply_CONFIRMED || c.GetHashes() != 2 {
		t.Fatalf("confirm: %v", c)
	}
	if !blocked(t, e.s, hashA, nil) || !blocked(t, e.s, hashB, nil) {
		t.Fatal("not blocked after confirmation")
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE purge_after > now() + interval '71 hours'
		AND reporter_name = 'Rights Holder' AND good_faith AND authorized AND notice_id = ?`, strings.TrimPrefix(subj, "Confirm your report ")); n != 2 {
		t.Fatalf("%d rows with the purge ahead, the reporter on them and the mailed notice id, want 2", n)
	}
	if got := e.banned(); len(got) != 0 {
		t.Fatalf("published at Confirm: %v", got)
	}
	mail = e.sink.waitFor(t, 2)
	if len(mail) != 2 || !strings.Contains(mail.to(reporter), "added to stoplist") {
		t.Fatalf("letters after confirmation: %+v", mail)
	}
	support := mail.to("support@example.com")
	for _, want := range []string{"Name:      Rights Holder", "Statement: yes, the use is not authorized", "Statement: yes, the reporter owns the work",
		reporter + " (confirmed", "waits until"} {
		if !strings.Contains(support, want) {
			t.Errorf("support letter lacks %q:\n%s", want, support)
		}
	}
	e.sink.reset()

	for _, g := range []*GRPC{e.form, e.g} {
		if c := confirm(t, g, tok); c.GetStatus() != pb.ConfirmReply_ALREADY_CONFIRMED {
			t.Fatalf("repeat: %v, want ALREADY_CONFIRMED", c)
		}
	}
	if n := e.count(t, `SELECT count(*) FROM abuse`); n != 2 {
		t.Fatalf("%d rows after repeats, want 2", n)
	}
	if mail := e.sink.waitFor(t, 0); len(mail) != 0 {
		t.Fatalf("%d letters for repeats", len(mail))
	}
}

// Refused before anything is stored or mailed (no database here: a store
// call would be Internal).
func TestFormNoticeNeedsTheReporter(t *testing.T) {
	st := newTestStore(t)
	st.p = &cs.PG{}
	g := &GRPC{formConfirm: true, store: st}
	for name, edit := range map[string]func(*pb.PushRequest){
		"no email":           func(r *pb.PushRequest) { r.Email = "" },
		"no name":            func(r *pb.PushRequest) { r.ReporterName = "" },
		"blank name":         func(r *pb.PushRequest) { r.ReporterName = " \t" },
		"no good faith":      func(r *pb.PushRequest) { r.GoodFaith = false },
		"not authorized":     func(r *pb.PushRequest) { r.Authorized = false },
		"intimate, no email": func(r *pb.PushRequest) { r.Cause, r.Email = pb.PushRequest_INTIMATE_IMAGE, "" },
	} {
		in := takedown(hashA)
		edit(in)
		if _, err := g.Push(context.Background(), in); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
}

// --form-confirm is off unless set, and both flags reach the public port
// only: the admin port never holds a notice.
func TestFormConfirmFlags(t *testing.T) {
	parse := func(args ...string) (pub, admin *GRPC) {
		t.Helper()
		app := cli.NewApp()
		app.Flags = RegisterGRPCFlags(nil)
		app.Action = func(c *cli.Context) error { pub, admin = NewGRPC(c, nil, nil), NewAdminGRPC(c, nil, nil); return nil }
		if err := app.Run(append([]string{"test"}, args...)); err != nil {
			t.Fatal(err)
		}
		return pub, admin
	}
	if g, _ := parse(); g.formConfirm || g.confirmURL != "https://webtor.io/support/confirm" {
		t.Fatalf("defaults: %+v", g)
	}
	g, admin := parse("--form-confirm", "--confirm-url", testConfirmURL)
	if !g.formConfirm || g.confirmURL != testConfirmURL {
		t.Fatalf("set: %+v", g)
	}
	if admin.formConfirm {
		t.Fatal("the admin port holds form notices")
	}
}

// Confirms racing on one token, on both ports: one applies, the rest find it
// done, and the notice is stored and mailed once.
func TestPGConcurrentConfirmsApplyOnce(t *testing.T) {
	e := newPGEnv(t, "72h")
	tok := e.held(t, takedown(hashA))
	var wg sync.WaitGroup
	got := make(chan pb.ConfirmReply_Status, 8)
	for i := range 8 {
		g := e.form
		if i%2 == 1 {
			g = e.g
		}
		wg.Go(func() { got <- confirm(t, g, tok).GetStatus() })
	}
	wg.Wait()
	close(got)
	count := map[pb.ConfirmReply_Status]int{}
	for s := range got {
		count[s]++
	}
	if count[pb.ConfirmReply_CONFIRMED] != 1 || count[pb.ConfirmReply_ALREADY_CONFIRMED] != 7 {
		t.Fatalf("statuses %v, want one CONFIRMED and 7 ALREADY_CONFIRMED", count)
	}
	if n := e.count(t, `SELECT count(*) FROM abuse`); n != 1 {
		t.Fatalf("%d rows, want 1", n)
	}
	if mail := e.sink.waitFor(t, 2); len(mail) != 2 {
		t.Fatalf("%d letters, want 2", len(mail))
	}
}

// Past its expiry a notice is not applied; once Sync drops it, its token is
// unknown like any other. Garbage is unknown too.
func TestPGConfirmExpiredOrUnknown(t *testing.T) {
	e := newPGEnv(t, "72h")
	tok := e.held(t, takedown(hashA))
	e.exec(t, `UPDATE unconfirmed_notice SET expires_at = now() - interval '1 second'`)
	if c := confirm(t, e.form, tok); c.GetStatus() != pb.ConfirmReply_EXPIRED {
		t.Fatalf("expired: %v", c)
	}
	if blocked(t, e.s, hashA, nil) || e.count(t, `SELECT count(*) FROM abuse`) != 0 {
		t.Fatal("expired notice applied")
	}
	if mail := e.sink.waitFor(t, 0); len(mail) != 0 {
		t.Fatalf("%d letters for an expired notice", len(mail))
	}
	e.sync(t)
	for _, tk := range []string{tok, strings.Repeat("A", 43), "not a token!", "", tok + "A"} {
		if c := confirm(t, e.form, tk); c.GetStatus() != pb.ConfirmReply_UNKNOWN {
			t.Errorf("%q: %v, want UNKNOWN", tk, c)
		}
	}
}

// Sync drops every notice past its expiry, confirmed or not, and keeps the
// others: a confirmed one still answers ALREADY_CONFIRMED until then.
func TestPGSyncDropsExpiredNotices(t *testing.T) {
	e := newPGEnv(t, "72h")
	toks := map[string]string{}
	for _, k := range []string{"pending", "confirmed", "expired", "confirmed expired"} {
		in := takedown(hashA)
		in.Email = strings.ReplaceAll(k, " ", "-") + "@example.com"
		toks[k] = e.held(t, in)
	}
	for _, k := range []string{"confirmed", "confirmed expired"} {
		if c := confirm(t, e.form, toks[k]); c.GetStatus() != pb.ConfirmReply_CONFIRMED {
			t.Fatalf("%s: %v", k, c)
		}
	}
	e.exec(t, `UPDATE unconfirmed_notice SET expires_at = now() - interval '1 second' WHERE email LIKE '%expired@%'`)
	e.sync(t)
	if n := e.count(t, `SELECT count(*) FROM unconfirmed_notice`); n != 2 {
		t.Fatalf("%d notices left, want the 2 unexpired", n)
	}
	if c := confirm(t, e.form, toks["confirmed"]); c.GetStatus() != pb.ConfirmReply_ALREADY_CONFIRMED {
		t.Fatalf("confirmed, unexpired: %v", c)
	}
	if c := confirm(t, e.form, toks["pending"]); c.GetStatus() != pb.ConfirmReply_CONFIRMED {
		t.Fatalf("pending: %v", c)
	}
}

// At most confirmPerAddress held notices per address (any case) and
// confirmPerDay in all, counted over the last 24 hours.
func TestPGFormNoticeRateLimits(t *testing.T) {
	e := newPGEnv(t, "72h")
	push := func(email string) codes.Code {
		in := takedown(hashA)
		in.Email = email
		_, err := e.form.Push(context.Background(), in)
		return status.Code(err)
	}
	for i, email := range []string{reporter, "Reporter@Example.com", reporter} {
		if c := push(email); c != codes.OK {
			t.Fatalf("notice %d: %v", i+1, c)
		}
	}
	e.sink.waitFor(t, 3)
	e.sink.reset()
	if c := push("REPORTER@example.com"); c != codes.ResourceExhausted {
		t.Fatalf("fourth for the address: %v, want ResourceExhausted", c)
	}
	if mail := e.sink.waitFor(t, 0); len(mail) != 0 {
		t.Fatalf("%d letters past the limit", len(mail))
	}
	if c := push("other@example.com"); c != codes.OK {
		t.Fatalf("another address: %v", c)
	}
	e.exec(t, `UPDATE unconfirmed_notice SET created_at = now() - interval '25 hours' WHERE lower(email) = ?`, reporter)
	if c := push(reporter); c != codes.OK {
		t.Fatalf("after 24 hours: %v", c)
	}
	// 2 within the day so far; fill the day up.
	e.exec(t, `INSERT INTO unconfirmed_notice (token_hash, email, notice, expires_at)
		SELECT decode(md5(g::text), 'hex'), 'filler' || g || '@example.com', '{}', now() + interval '1 day'
		FROM generate_series(1, ?) g`, confirmPerDay-2)
	if c := push("third@example.com"); c != codes.ResourceExhausted {
		t.Fatalf("past %d in a day: %v, want ResourceExhausted", confirmPerDay, c)
	}
}

// Pushes racing for one address get its slots and no more. A slow insert
// widens the window between each one's count and its insert.
func TestPGFormNoticeRateLimitUnderRace(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.exec(t, `CREATE FUNCTION slow() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.2); RETURN NEW; END $$`)
	t.Cleanup(func() { e.exec(t, `DROP FUNCTION slow() CASCADE`) })
	e.exec(t, `CREATE TRIGGER slow BEFORE INSERT ON unconfirmed_notice FOR EACH ROW EXECUTE FUNCTION slow()`)
	var wg sync.WaitGroup
	got := make(chan codes.Code, 12)
	for range 12 {
		wg.Go(func() {
			_, err := e.form.Push(context.Background(), takedown(hashA))
			got <- status.Code(err)
		})
	}
	wg.Wait()
	close(got)
	ok := 0
	for c := range got {
		if c == codes.OK {
			ok++
		} else if c != codes.ResourceExhausted {
			t.Errorf("push: %v", c)
		}
	}
	if ok != confirmPerAddress || e.count(t, `SELECT count(*) FROM unconfirmed_notice`) != confirmPerAddress {
		t.Fatalf("%d racing pushes held, want %d", ok, confirmPerAddress)
	}
}

// An intimate image needs only the address, and once confirmed it bans like
// a takedown: blocked, the letters, the purge fanned out once due.
func TestPGIntimateImageBansOnceConfirmed(t *testing.T) {
	e := newPGEnv(t, "72h")
	tok := e.held(t, &pb.PushRequest{Infohash: hashA, Source: pb.PushRequest_FORM, Cause: pb.PushRequest_INTIMATE_IMAGE, Email: reporter})
	if blocked(t, e.s, hashA, nil) {
		t.Fatal("blocked before confirmation")
	}
	if c := confirm(t, e.g, tok); c.GetStatus() != pb.ConfirmReply_CONFIRMED || c.GetHashes() != 1 {
		t.Fatalf("confirm on the admin port: %v", c)
	}
	if !blocked(t, e.s, hashA, nil) || e.count(t, `SELECT count(*) FROM abuse WHERE cause = ?`, int(pb.PushRequest_INTIMATE_IMAGE)) != 1 {
		t.Fatal("not banned after confirmation")
	}
	mail := e.sink.waitFor(t, 2)
	if !strings.Contains(mail.to(reporter), "added to stoplist") || !strings.Contains(mail.to("support@example.com"), "Data purge: the automatic purge waits") {
		t.Fatalf("letters: %+v", mail)
	}
	e.exec(t, `UPDATE abuse SET purge_after = now() - interval '1 second'`)
	e.sync(t)
	if got := e.banned(); len(got) != 1 || got[0] != hashA {
		t.Fatalf("published %v, want [%s]", got, hashA)
	}
}

// A CSAM report is a letter to support and nothing else, on any port, from
// any source, flag or no flag, purge_now or not.
func TestPGCSAMReportNeverBans(t *testing.T) {
	e := newPGEnv(t, "0")
	for _, g := range []*GRPC{e.pub, e.form, e.g} {
		for _, src := range []pb.PushRequest_Source{pb.PushRequest_MAIL, pb.PushRequest_FORM} {
			r, err := g.Push(context.Background(), &pb.PushRequest{Infohash: hashA, Cause: pb.PushRequest_CSAM_REPORT, Source: src,
				Email: reporter, Subject: "seen", PurgeNow: true})
			if err != nil || r.GetConfirmationSent() {
				t.Fatalf("admin=%v source=%v: %v, confirmation_sent %v", g.admin, src, err, r.GetConfirmationSent())
			}
			mail := e.sink.waitFor(t, 1)
			if len(mail) != 1 || mail[0].rcpt != "support@example.com" || !strings.HasPrefix(mail.subject(t, "support@example.com"), "[CSAM report] [") {
				t.Fatalf("admin=%v source=%v: want one letter to support prefixed [CSAM report], got %+v", g.admin, src, mail)
			}
			e.sink.reset()
		}
	}
	if blocked(t, e.s, hashA, nil) || e.count(t, `SELECT count(*) FROM abuse`) != 0 ||
		e.count(t, `SELECT count(*) FROM unconfirmed_notice`) != 0 || len(e.banned()) != 0 {
		t.Fatal("a CSAM report was stored, held or published")
	}
}

// Nothing the caller typed reaches the confirmation letter: not the subject,
// the description, the work, the file, the name, nor the notice id.
func TestPGConfirmationLetterCarriesNoReporterText(t *testing.T) {
	e := newPGEnv(t, "72h")
	const evil = "<a href=\"https://evil.example/\">click</a>\r\nBcc: victim@example.com\r\n\r\nbody"
	in := takedown(hashA)
	in.Subject, in.Description, in.Work, in.Filename, in.ReporterName, in.NoticeId = evil, evil, evil, evil, evil, evil
	if r, err := e.form.Push(context.Background(), in); err != nil || !r.GetConfirmationSent() {
		t.Fatalf("push: %v", err)
	}
	mail := e.sink.waitFor(t, 1)
	raw := mail.to(reporter)
	for _, bad := range []string{"evil", "<a", "click", "Bcc", "victim"} {
		if strings.Contains(raw, bad) {
			t.Errorf("confirmation letter carries %q:\n%s", bad, raw)
		}
	}
	if l := parseLetter(t, raw); len(l.header["Bcc"]) != 0 || !strings.HasPrefix(l.subject, "Confirm your report ") {
		t.Fatalf("headers %v", l.header)
	}
}

// Without the flag, from the automated intake, and on the admin port, a
// notice bans at once as before; a question is mailed as before.
func TestPGNoConfirmationWithoutFlagForMailOrOnAdmin(t *testing.T) {
	e := newPGEnv(t, "72h")
	mailSrc := takedown(hashB)
	mailSrc.Source = pb.PushRequest_MAIL
	for name, tc := range map[string]struct {
		g  *GRPC
		in *pb.PushRequest
		h  string
	}{
		"flag off": {e.pub, takedown(hashA), hashA},
		"mail":     {e.form, mailSrc, hashB},
		"admin":    {e.g, takedown(hashC), hashC},
	} {
		r, err := tc.g.Push(context.Background(), tc.in)
		if err != nil || r.GetConfirmationSent() || !blocked(t, e.s, tc.h, nil) {
			t.Errorf("%s: %v, confirmation_sent %v, blocked %v; want banned at once", name, err, r.GetConfirmationSent(), blocked(t, e.s, tc.h, nil))
		}
	}
	if n := e.count(t, `SELECT count(*) FROM unconfirmed_notice`); n != 0 {
		t.Fatalf("%d held", n)
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE reporter_name = 'Rights Holder' AND good_faith AND authorized`); n != 3 {
		t.Fatalf("%d rows carry the reporter, want 3", n)
	}
	e.sink.waitFor(t, 6)
	e.sink.reset()
	if r, err := e.form.Push(context.Background(), &pb.PushRequest{Source: pb.PushRequest_FORM, Cause: pb.PushRequest_QUESTION, Email: reporter}); err != nil || r.GetConfirmationSent() {
		t.Fatalf("question: %v", err)
	}
	if mail := e.sink.waitFor(t, 2); len(mail) != 2 {
		t.Fatalf("question: %d letters, want 2", len(mail))
	}
}

// A form notice whose every hash already blocks is AlreadyExists and silent,
// as without the flag; one new hash among them is held.
func TestPGFormNoticeOfBlockedHashes(t *testing.T) {
	e := newPGEnv(t, "72h")
	if _, err := e.pub.Push(context.Background(), takedown(hashA)); err != nil {
		t.Fatal(err)
	}
	e.sink.waitFor(t, 2)
	e.sink.reset()
	if _, err := e.form.Push(context.Background(), takedown(hashA)); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("blocked hash: %v, want AlreadyExists", err)
	}
	if mail := e.sink.waitFor(t, 0); len(mail) != 0 || e.count(t, `SELECT count(*) FROM unconfirmed_notice`) != 0 {
		t.Fatalf("held or mailed: %d letters", len(mail))
	}
	e.held(t, takedown(hashA, hashB))
}

// A confirmation letter that cannot be sent fails the push and frees the
// address's slot: the notice could never be confirmed.
func TestPGConfirmationLetterFailureFreesTheSlot(t *testing.T) {
	e := newPGEnv(t, "72h")
	// Nothing listens on port 1.
	g := &GRPC{store: e.s, mailer: &Mailer{sender: "noreply@example.com", smtp: &SMTP{host: "127.0.0.1", port: 1}}, formConfirm: true, confirmURL: testConfirmURL}
	if _, err := g.Push(context.Background(), takedown(hashA)); status.Code(err) != codes.Unavailable {
		t.Fatalf("push: %v, want Unavailable", err)
	}
	if n := e.count(t, `SELECT count(*) FROM unconfirmed_notice`); n != 0 {
		t.Fatalf("%d notices held with no letter sent", n)
	}
}

// A confirmation whose ban fails is not used up: the reporter's retry
// applies it.
func TestPGFailedConfirmationCanBeRetried(t *testing.T) {
	e := newPGEnv(t, "72h")
	tok := e.held(t, takedown(hashA))
	e.refuse(t, "BEFORE INSERT ON abuse FOR EACH ROW")
	if _, err := e.form.Confirm(context.Background(), &pb.ConfirmRequest{Token: tok}); status.Code(err) != codes.Internal {
		t.Fatalf("confirm with the insert refused: %v, want Internal", err)
	}
	e.exec(t, `DROP TRIGGER refuse ON abuse`)
	if c := confirm(t, e.form, tok); c.GetStatus() != pb.ConfirmReply_CONFIRMED || !blocked(t, e.s, hashA, nil) {
		t.Fatalf("retry: %v, blocked %v", c, blocked(t, e.s, hashA, nil))
	}
}
