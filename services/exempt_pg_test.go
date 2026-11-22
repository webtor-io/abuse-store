package services

import (
	"context"
	"errors"
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
// no letter, and once the purge time passes Sync publishes nothing. The
// unreviewed ban next to it shows the purge would have gone out.
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
	if rows, c := e.exempt(t, hashA); c != codes.OK || rows != 0 {
		t.Fatalf("repeat: rows %d, %v; want 0, OK", rows, c)
	}
	if mail := e.sink.waitFor(t, 0); len(mail) != 0 {
		t.Fatalf("%d letters for Exempt", len(mail))
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

// Store.Push asks again under its lock. Here it gets the row a Push makes
// once its earlier IsExempt read came before Exempt's commit: no row, and
// the block Exempt lifted is not put back.
func TestPGStorePushRechecksTheExemption(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashA})
	if rows, c := e.exempt(t, hashA); c != codes.OK || rows != 1 {
		t.Fatalf("exempt: rows %d, %v; want 1, OK", rows, c)
	}
	err := e.s.Push(&m.Abuse{Infohash: hashA, PurgeAfter: time.Now().Add(72 * time.Hour)})
	if !errors.Is(err, ErrExempt) {
		t.Fatalf("push after Exempt: %v, want ErrExempt", err)
	}
	if blocked(t, e.s, hashA, nil) {
		t.Fatal("blocked again by a push that raced Exempt")
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE infohash = ?`, hashA); n != 1 {
		t.Fatalf("%d rows, want 1", n)
	}
}

// An exemption set through the RPC absorbs a later ordinary report, but gives
// way to an immediate one (the agents' purge_now): that ban is stored with its
// fingerprint, blocks on both arms, is published and survives Sync, and Exempt
// refuses the hash from then on. Otherwise any caller in the cluster could
// make a hash immune to a CSAM ban by reporting and exempting it first.
func TestPGImmediateBanOverridesAnRPCExemption(t *testing.T) {
	e := newPGEnv(t, "72h")
	fp := digest(0x77)
	e.push(t, &pb.PushRequest{Infohash: hashA})
	if rows, c := e.exempt(t, hashA); c != codes.OK || rows != 1 {
		t.Fatalf("exempt: rows %d, %v; want 1, OK", rows, c)
	}
	if c := e.push(t, &pb.PushRequest{Infohash: hashA}); c != codes.OK {
		t.Fatalf("ordinary repeat: %v", c)
	}
	if blocked(t, e.s, hashA, nil) || e.count(t, `SELECT count(*) FROM abuse`) != 1 {
		t.Fatal("ordinary repeat not absorbed by the exemption")
	}

	if c := e.push(t, &pb.PushRequest{Infohash: hashA, PurgeNow: true, Fingerprint: fp}); c != codes.OK {
		t.Fatalf("immediate ban: %v", c)
	}
	if got := e.banned(); !slices.Equal(got, []string{hashA}) {
		t.Fatalf("published %v, want [%s]", got, hashA)
	}
	if !blocked(t, e.s, hashA, nil) || !blocked(t, e.s, "", fp) {
		t.Fatal("immediate ban does not block on both arms")
	}
	e.sync(t)
	if !blocked(t, e.s, hashA, nil) || !blocked(t, e.s, "", fp) {
		t.Fatal("immediate ban lifted by Sync")
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE exempt OR exempt_by_rpc`); n != 0 {
		t.Fatalf("%d rows still exempt", n)
	}
	if _, c := e.exempt(t, hashA); c != codes.FailedPrecondition {
		t.Fatalf("exempt after the immediate ban: %v, want FailedPrecondition", c)
	}
}

// Exempt changes only the rows it checked. One that landed while its read
// waited on a lock, here an immediate ban, is not in its window and is left
// non-exempt for its Push's PurgeNow to clear the exemption by.
func TestPGExemptLeavesARowThatLandedWhileItWaited(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashA})
	commit := e.holdRowLock(t, hashA)
	exempted := make(chan *pb.ExemptReply, 1)
	go func() {
		r, _ := e.g.Exempt(context.Background(), &pb.ExemptRequest{Infohash: hashA})
		exempted <- r
	}()
	time.Sleep(200 * time.Millisecond)
	e.exec(t, `INSERT INTO abuse (infohash, purge_after) VALUES (?, now())`, hashA)
	commit()
	if r := <-exempted; r.GetRows() != 1 {
		t.Fatalf("exempt: rows %d, want 1", r.GetRows())
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE exempt AND purge_after <= now()`); n != 0 {
		t.Fatalf("%d immediate rows exempted unchecked", n)
	}
}
