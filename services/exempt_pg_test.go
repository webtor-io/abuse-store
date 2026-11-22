package services

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	m "github.com/webtor-io/abuse-store/models"
	pb "github.com/webtor-io/abuse-store/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Against Postgres and NATS like push_pg_test.go; same env, same skip.

func (e *pgEnv) exempt(t *testing.T, h string) (int32, codes.Code) {
	t.Helper()
	r, err := e.g.Exempt(context.Background(), &pb.ExemptRequest{Infohash: h, Reason: "reviewed"})
	return r.GetRows(), status.Code(err)
}

// Inside the window: OK, the block lifts at once on both arms with no Sync,
// one letter tells support, and once the purge time passes Sync publishes
// nothing. The unreviewed ban next to it shows the purge would have gone out.
func TestPGExemptInsideTheWindow(t *testing.T) {
	e := newPGEnv(t, "72h")
	fp := digest(0x51)
	e.push(t, &pb.PushRequest{Infohash: hashA, Fingerprint: fp})
	e.push(t, &pb.PushRequest{Infohash: hashB})
	e.sink.waitFor(t, 4)
	e.sink.reset()

	if rows, c := e.exempt(t, strings.ToUpper(hashA)); c != codes.OK || rows != 1 {
		t.Fatalf("exempt: rows %d, %v; want 1, OK", rows, c)
	}
	if blocked(t, e.s, hashA, nil) {
		t.Fatal("still blocked by infohash right after Exempt")
	}
	if blocked(t, e.s, "", fp) {
		t.Fatal("still blocked by the row's fingerprint right after Exempt")
	}
	mail := e.sink.waitFor(t, 1)
	if len(mail) != 1 || mail[0].rcpt != "support@example.com" ||
		mail.subject(t, "support@example.com") != "[exempt] "+hashA+" — reviewed" ||
		!strings.Contains(mail[0].body, "Rows set exempt: 1") {
		t.Fatalf("want one letter to support for Exempt, got %d: %+v", len(mail), mail)
	}
	e.sink.reset()
	if rows, c := e.exempt(t, hashA); c != codes.OK || rows != 0 {
		t.Fatalf("repeat: rows %d, %v; want 0, OK", rows, c)
	}
	if mail := e.sink.waitFor(t, 0); len(mail) != 0 {
		t.Fatalf("%d letters for a repeat that exempted nothing", len(mail))
	}

	e.exec(t, `UPDATE abuse SET purge_after = now() - interval '1 second'`)
	e.sync(t)
	e.sync(t)
	if got := e.banned(); !slices.Equal(got, []string{hashB}) {
		t.Fatalf("published %v, want only the unreviewed %s", got, hashB)
	}
	if blocked(t, e.s, hashA, nil) {
		t.Fatal("blocked again after Sync")
	}
}

// Outside the window the RPC refuses and the ban stays exactly as it was.
func TestPGExemptRefusedOutsideTheWindow(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, e *pgEnv)
	}{
		{"purge_now", func(t *testing.T, e *pgEnv) {
			e.push(t, &pb.PushRequest{Infohash: hashA, PurgeNow: true})
		}},
		{"one pending, one immediate row", func(t *testing.T, e *pgEnv) {
			e.push(t, &pb.PushRequest{Infohash: hashA})
			e.exec(t, `INSERT INTO abuse (infohash, purge_after) VALUES (?, now())`, hashA)
		}},
		{"purge_after NULL", func(t *testing.T, e *pgEnv) {
			e.exec(t, `INSERT INTO abuse (infohash) VALUES (?)`, hashA)
			e.sync(t)
		}},
		{"purge_after passed", func(t *testing.T, e *pgEnv) {
			e.push(t, &pb.PushRequest{Infohash: hashA})
			e.exec(t, `UPDATE abuse SET purge_after = now() - interval '1 second'`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPGEnv(t, "72h")
			tc.setup(t, e)
			if _, c := e.exempt(t, hashA); c != codes.FailedPrecondition {
				t.Fatalf("exempt: %v, want FailedPrecondition", c)
			}
			if n := e.count(t, `SELECT count(*) FROM abuse WHERE exempt`); n != 0 {
				t.Fatalf("%d rows set exempt", n)
			}
			if !blocked(t, e.s, hashA, nil) {
				t.Fatal("unblocked by a refused Exempt")
			}
			e.sync(t)
			if !blocked(t, e.s, hashA, nil) {
				t.Fatal("unblocked after Sync")
			}
		})
	}
}

// Unknown is NotFound; a malformed or empty infohash is refused before it
// reaches the table.
func TestPGExemptUnknownAndMalformed(t *testing.T) {
	e := newPGEnv(t, "72h")
	if _, c := e.exempt(t, hashC); c != codes.NotFound {
		t.Fatalf("unknown: %v, want NotFound", c)
	}
	for _, h := range []string{"", "  ", "abc", hashA + "0"} {
		if _, c := e.exempt(t, h); c != codes.InvalidArgument {
			t.Errorf("%q: %v, want InvalidArgument", h, c)
		}
	}
}

// An exempt row inserted by hand has no purge_after; it is not a ban, so the
// hash is already fully exempt rather than outside the window.
func TestPGExemptAlreadyExemptByHand(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.exec(t, `INSERT INTO abuse (infohash, exempt) VALUES (?, true)`, hashA)
	if rows, c := e.exempt(t, hashA); c != codes.OK || rows != 0 {
		t.Fatalf("exempt: rows %d, %v; want 0, OK", rows, c)
	}
}

// A purge brought forward while Exempt runs (PurgeNow, here held open in a
// transaction): Exempt waits for it, sees the new purge_after and refuses,
// instead of exempting a hash whose purge has just gone out.
func TestPGExemptWaitsForAPurgeBroughtForward(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashA})
	tx, err := e.s.p.Get().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Close() }()
	if _, err := tx.Exec(`UPDATE abuse SET purge_after = now() WHERE infohash = ?`, hashA); err != nil {
		t.Fatal(err)
	}
	done := make(chan codes.Code, 1)
	go func() {
		_, err := e.g.Exempt(context.Background(), &pb.ExemptRequest{Infohash: hashA})
		done <- status.Code(err)
	}()
	time.Sleep(300 * time.Millisecond)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if c := <-done; c != codes.FailedPrecondition {
		t.Fatalf("exempt racing a purge brought forward: %v, want FailedPrecondition", c)
	}
}

// Exempt waits for the lock Push and Sync hold: a Sync that read the table
// before the UPDATE must finish before the cache is touched, or its stale
// rows put the hash back.
func TestPGExemptTakesTheStoreLock(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashA})
	e.s.mu.Lock()
	done := make(chan codes.Code, 1)
	go func() {
		_, err := e.g.Exempt(context.Background(), &pb.ExemptRequest{Infohash: hashA})
		done <- status.Code(err)
	}()
	select {
	case c := <-done:
		e.s.mu.Unlock()
		t.Fatalf("Exempt returned %v while the store lock was held", c)
	case <-time.After(300 * time.Millisecond):
	}
	e.s.mu.Unlock()
	select {
	case c := <-done:
		if c != codes.OK {
			t.Fatalf("exempt: %v", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Exempt did not return after the lock was released")
	}
}

// holdRowLock opens a transaction holding a row lock on h's rows, as a hand
// UPDATE left open in psql does, and returns its commit.
func (e *pgEnv) holdRowLock(t *testing.T, h string) (commit func()) {
	t.Helper()
	tx, err := e.s.p.Get().Begin()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Close() })
	if _, err := tx.Exec(`UPDATE abuse SET description = 'held' WHERE infohash = ?`, h); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}

// Exempt waiting on a row lock does not hold up Push or Sync on the replica,
// a purge_now ban of another hash included; once the lock goes, it exempts.
func TestPGExemptWaitingOnARowLockStallsNothingElse(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashA})
	commit := e.holdRowLock(t, hashA)
	exempted := make(chan codes.Code, 1)
	go func() {
		_, err := e.g.Exempt(context.Background(), &pb.ExemptRequest{Infohash: hashA})
		exempted <- status.Code(err)
	}()
	time.Sleep(200 * time.Millisecond)
	done := make(chan error, 1)
	go func() {
		_, err := e.g.Push(context.Background(), &pb.PushRequest{Infohash: hashB, PurgeNow: true})
		if err == nil {
			err = e.s.Sync()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		commit()
		t.Fatal("Push and Sync stalled behind Exempt waiting on a row lock")
	}
	if !blocked(t, e.s, hashB, nil) {
		t.Fatal("purge_now ban of another hash does not block")
	}
	commit()
	if c := <-exempted; c != codes.OK {
		t.Fatalf("exempt after the lock went: %v", c)
	}
}

// The caller's deadline ends Exempt's wait on a row lock, and the hash stays
// banned: it is not exempted later, when the lock goes.
func TestPGExemptGivesUpAtTheDeadline(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashA})
	commit := e.holdRowLock(t, hashA)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	exempted := make(chan codes.Code, 1)
	go func() {
		_, err := e.g.Exempt(ctx, &pb.ExemptRequest{Infohash: hashA})
		exempted <- status.Code(err)
	}()
	select {
	case c := <-exempted:
		if c == codes.OK {
			t.Fatal("exempt past its deadline: OK")
		}
	case <-time.After(3 * time.Second):
		commit()
		<-exempted
		t.Fatal("Exempt still waiting on the row lock 3s after a 300ms deadline")
	}
	commit()
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE exempt`); n != 0 {
		t.Fatalf("%d rows exempt after the caller gave up", n)
	}
	if !blocked(t, e.s, hashA, nil) {
		t.Fatal("unblocked by an Exempt that gave up")
	}
}

// Store.Push reads the exemption itself, under its lock and in its
// transaction: an ordinary report of a hash exempted since the caller looked
// gets no row, and the block Exempt lifted is not put back.
func TestPGStorePushAbsorbsAnExemption(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashA})
	if rows, c := e.exempt(t, hashA); c != codes.OK || rows != 1 {
		t.Fatalf("exempt: rows %d, %v; want 1, OK", rows, c)
	}
	nh, err := e.s.Push(context.Background(), &m.Abuse{Infohash: hashA, PurgeAfter: time.Now().Add(72 * time.Hour)}, false)
	if err != nil || !nh.Exempt {
		t.Fatalf("push after Exempt: %+v, %v; want Exempt", nh, err)
	}
	if blocked(t, e.s, hashA, nil) {
		t.Fatal("blocked again by a push after Exempt")
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE infohash = ?`, hashA); n != 1 {
		t.Fatalf("%d rows, want 1", n)
	}
}

// An exemption, set with Exempt or by hand, absorbs every later report but an
// immediate ban on the admin port: ordinary ones on either port and purge_now
// on the public one change nothing. The immediate ban is stored with its
// fingerprint, blocks at once on the infohash and on both fingerprints (the
// exempted row's included), is published and survives Sync, support is told
// the exemption was overridden, and Exempt refuses the hash from then on.
func TestPGImmediateBanOverridesAnyExemption(t *testing.T) {
	for _, tc := range []struct {
		name    string
		letters int // before the immediate ban
		exempt  func(t *testing.T, e *pgEnv)
	}{
		{"Exempt RPC", 6, func(t *testing.T, e *pgEnv) {
			if rows, c := e.exempt(t, hashA); c != codes.OK || rows != 1 {
				t.Fatalf("exempt: rows %d, %v; want 1, OK", rows, c)
			}
		}},
		{"by hand", 5, func(t *testing.T, e *pgEnv) {
			e.exec(t, `UPDATE abuse SET exempt = true WHERE infohash = ?`, hashA)
			e.sync(t)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPGEnv(t, "72h")
			fpOld, fpNew := digest(0x76), digest(0x77)
			e.push(t, &pb.PushRequest{Infohash: hashA, Fingerprint: fpOld})
			tc.exempt(t, e)
			if blocked(t, e.s, hashA, nil) || blocked(t, e.s, "", fpOld) {
				t.Fatal("exempted hash still blocks")
			}
			for _, g := range []*GRPC{e.g, e.pub} {
				if _, err := g.Push(context.Background(), &pb.PushRequest{Infohash: hashA}); err != nil {
					t.Fatalf("ordinary repeat: %v", err)
				}
			}
			if _, err := e.pub.Push(context.Background(), &pb.PushRequest{Infohash: hashA, PurgeNow: true}); err != nil {
				t.Fatalf("purge_now on the public port: %v", err)
			}
			if blocked(t, e.s, hashA, nil) || e.count(t, `SELECT count(*) FROM abuse`) != 1 || len(e.banned()) != 0 {
				t.Fatal("a report other than an immediate ban on the admin port was not absorbed")
			}
			if mail := e.sink.waitFor(t, tc.letters); len(mail) != tc.letters {
				t.Fatalf("%d letters before the immediate ban, want %d", len(mail), tc.letters)
			}
			e.sink.reset()

			if c := e.push(t, &pb.PushRequest{Infohash: hashA, PurgeNow: true, Fingerprint: fpNew}); c != codes.OK {
				t.Fatalf("immediate ban: %v", c)
			}
			if got := e.banned(); !slices.Equal(got, []string{hashA}) {
				t.Fatalf("published %v, want [%s]", got, hashA)
			}
			for _, sync := range []bool{false, true} {
				if sync {
					e.sync(t)
				}
				if !blocked(t, e.s, hashA, nil) || !blocked(t, e.s, "", fpNew) || !blocked(t, e.s, "", fpOld) {
					t.Fatalf("immediate ban does not block on every arm (after Sync: %v)", sync)
				}
			}
			if n := e.count(t, `SELECT count(*) FROM abuse WHERE exempt OR purge_after > now()`); n != 0 {
				t.Fatalf("%d rows still exempt or pending", n)
			}
			if n := e.count(t, `SELECT count(*) FROM abuse`); n != 2 {
				t.Fatalf("%d rows, want 2: the immediate ban has its own", n)
			}
			mail := e.sink.waitFor(t, 2)
			if l := mail.to("support@example.com"); !strings.Contains(l, "an exemption was overridden by an immediate ban") ||
				!strings.Contains(l, hashA+" (its exemption overridden by this immediate ban)") || !strings.Contains(l, "Data purge: immediate") {
				t.Fatalf("support letter: %s", l)
			}
			if _, c := e.exempt(t, hashA); c != codes.FailedPrecondition {
				t.Fatalf("exempt after the immediate ban: %v, want FailedPrecondition", c)
			}
		})
	}
}

// An immediate ban that arrives while Exempt waits on a row lock of the same
// hash waits behind it, then finds the exemption and clears it in its own
// transaction: the hash ends blocked, published, and with no exempt row, and
// support has both letters.
func TestPGImmediateBanRacingExempt(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashA})
	e.sink.waitFor(t, 2)
	e.sink.reset()
	commit := e.holdRowLock(t, hashA)
	exempted := make(chan *pb.ExemptReply, 1)
	go func() {
		r, _ := e.g.Exempt(context.Background(), &pb.ExemptRequest{Infohash: hashA, Reason: "reviewed"})
		exempted <- r
	}()
	time.Sleep(200 * time.Millisecond)
	pushed := make(chan error, 1)
	go func() {
		_, err := e.g.Push(context.Background(), &pb.PushRequest{Infohash: hashA, PurgeNow: true})
		pushed <- err
	}()
	time.Sleep(200 * time.Millisecond)
	commit()
	if r := <-exempted; r.GetRows() != 1 {
		t.Fatalf("exempt: rows %d, want 1", r.GetRows())
	}
	if err := <-pushed; err != nil {
		t.Fatalf("immediate ban: %v", err)
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE exempt`); n != 0 {
		t.Fatalf("%d rows exempt after the immediate ban", n)
	}
	// Its own row, although the cache still held the hash when it looked.
	if n := e.count(t, `SELECT count(*) FROM abuse`); n != 2 {
		t.Fatalf("%d rows, want 2", n)
	}
	if !blocked(t, e.s, hashA, nil) {
		t.Fatal("immediate ban does not block")
	}
	e.sync(t)
	if !blocked(t, e.s, hashA, nil) {
		t.Fatal("immediate ban lifted by Sync")
	}
	if got := e.banned(); !slices.Equal(got, []string{hashA}) {
		t.Fatalf("published %v, want [%s]", got, hashA)
	}
	mail := e.sink.waitFor(t, 2)
	var overridden, exemptLetter bool
	for _, l := range mail {
		overridden = overridden || strings.Contains(l.body, "an exemption was overridden by an immediate ban")
		exemptLetter = exemptLetter || strings.Contains(l.body, "Exempted through the admin port")
	}
	if !overridden || !exemptLetter {
		t.Fatalf("letters: override noted %v, exempt letter %v", overridden, exemptLetter)
	}
}

// The clearing or the insert fails (a trigger refuses it here): the immediate
// ban returns an error and the other half is rolled back with it, so nothing
// is stored, blocked or published and the exemption stands.
func TestPGImmediateBanIsOneTransaction(t *testing.T) {
	for _, tc := range []struct{ name, when string }{
		{"clearing fails", `BEFORE UPDATE ON abuse FOR EACH ROW WHEN (OLD.exempt AND NOT NEW.exempt)`},
		{"insert fails", `BEFORE INSERT ON abuse FOR EACH ROW`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPGEnv(t, "72h")
			e.exec(t, `INSERT INTO abuse (infohash, exempt) VALUES (?, true)`, hashA)
			e.refuse(t, tc.when)
			if _, err := e.g.Push(context.Background(), &pb.PushRequest{Infohash: hashA, PurgeNow: true}); err == nil {
				t.Fatal("immediate ban succeeded although half of it failed")
			}
			if n := e.count(t, `SELECT count(*) FROM abuse WHERE exempt`); n != 1 {
				t.Fatalf("%d exempt rows, want the exemption to stand", n)
			}
			if n := e.count(t, `SELECT count(*) FROM abuse`); n != 1 {
				t.Fatalf("%d rows, want the exempt one only", n)
			}
			if blocked(t, e.s, hashA, nil) || len(e.banned()) != 0 {
				t.Fatal("a failed immediate ban blocked or published")
			}
		})
	}
}

// An immediate ban of a hash already blocked only brings its pending purge
// forward; when that fails it is an error, not a purge published with the
// schedule left behind.
func TestPGImmediateBanFailsWhenThePurgeCannotBeBroughtForward(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashA})
	e.refuse(t, `BEFORE UPDATE ON abuse FOR EACH ROW`)
	if _, err := e.g.Push(context.Background(), &pb.PushRequest{Infohash: hashA, PurgeNow: true}); err == nil {
		t.Fatal("immediate ban succeeded although bringing the purge forward failed")
	}
	if got := e.banned(); len(got) != 0 {
		t.Fatalf("published %v", got)
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE purge_after > now()`); n != 1 {
		t.Fatalf("%d rows pending, want 1", n)
	}
}

// refuse makes Postgres raise on the statements the trigger condition when
// names, until the test ends.
func (e *pgEnv) refuse(t *testing.T, when string) {
	t.Helper()
	e.exec(t, `CREATE FUNCTION refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$`)
	e.exec(t, `CREATE TRIGGER refuse `+when+` EXECUTE FUNCTION refuse()`)
	t.Cleanup(func() { e.exec(t, `DROP FUNCTION refuse() CASCADE`) })
}

// A due row that landed while Exempt's read waited on a lock, here an
// immediate one put in by hand, was never checked, and the exemption would
// shadow it: Exempt refuses and rolls back, the row it did check included.
func TestPGExemptRefusesARowThatLandedWhileItWaited(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashA})
	commit := e.holdRowLock(t, hashA)
	exempted := make(chan codes.Code, 1)
	go func() {
		_, err := e.g.Exempt(context.Background(), &pb.ExemptRequest{Infohash: hashA})
		exempted <- status.Code(err)
	}()
	time.Sleep(200 * time.Millisecond)
	e.exec(t, `INSERT INTO abuse (infohash, purge_after) VALUES (?, now())`, hashA)
	commit()
	if c := <-exempted; c != codes.FailedPrecondition {
		t.Fatalf("exempt: %v, want FailedPrecondition", c)
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE exempt`); n != 0 {
		t.Fatalf("%d rows exempt, want the UPDATE rolled back", n)
	}
	if !blocked(t, e.s, hashA, nil) {
		t.Fatal("unblocked by a refused Exempt")
	}
}

// The UPDATE commits but the cache reload after it fails (Badger is closed
// here): the call fails, and support gets the letter all the same, since the
// hash is exempt in Postgres from now on.
func TestPGExemptMailsWhenTheReloadFails(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashA})
	e.sink.waitFor(t, 2)
	e.sink.reset()
	if err := e.s.b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, c := e.exempt(t, hashA); c != codes.Internal {
		t.Fatalf("exempt with the reload failing: %v, want Internal", c)
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE exempt`); n != 1 {
		t.Fatalf("%d rows exempt, want 1", n)
	}
	if s := e.sink.waitFor(t, 1).subject(t, "support@example.com"); s != "[exempt] "+hashA+" — reviewed" {
		t.Fatalf("support letter subject %q, want the exempt one", s)
	}
}
