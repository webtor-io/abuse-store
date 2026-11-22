package services

import (
	"context"
	"encoding/json"
	"mime"
	"net"
	"net/mail"
	"net/textproto"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/urfave/cli"
	pb "github.com/webtor-io/abuse-store/proto"
	cs "github.com/webtor-io/common-services"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// These tests drive Push and Sync against a real Postgres and NATS, and are
// skipped unless both are given:
//
//	docker run -d --rm -e POSTGRES_PASSWORD=test -e POSTGRES_DB=abuse_test -p 127.0.0.1:55432:5432 postgres:17-alpine
//	docker run -d --rm -p 127.0.0.1:54222:4222 nats:2-alpine
//	ABUSE_STORE_TEST_PG=postgres://postgres:test@127.0.0.1:55432/abuse_test \
//	ABUSE_STORE_TEST_NATS=127.0.0.1:54222 go test ./services/
//
// The database is wiped before every test, so its name must end in _test.

type pgEnv struct {
	// g is the admin port, pub the public one, form the public one with
	// --form-confirm.
	g, pub, form *GRPC
	s            *Store
	sink         *mailSink
	// banned drains what was published to resource.banned so far.
	banned func() []string
}

func newPGEnv(t *testing.T, purgeDelay string) *pgEnv {
	t.Helper()
	pgURL, natsAddr := os.Getenv("ABUSE_STORE_TEST_PG"), os.Getenv("ABUSE_STORE_TEST_NATS")
	if pgURL == "" || natsAddr == "" {
		t.Skip("ABUSE_STORE_TEST_PG and ABUSE_STORE_TEST_NATS not set")
	}
	u, err := url.Parse(pgURL)
	if err != nil {
		t.Fatal(err)
	}
	db := strings.TrimPrefix(u.Path, "/")
	if !strings.HasSuffix(db, "_test") {
		t.Fatalf("database %q does not end in _test; refusing to wipe it", db)
	}
	pass, _ := u.User.Password()
	natsHost, natsPort, _ := net.SplitHostPort(natsAddr)
	var c *cli.Context
	app := cli.NewApp()
	app.Flags = RegisterStoreFlags(cs.RegisterNATSFlags(cs.RegisterPGFlags(nil)))
	app.Action = func(cc *cli.Context) error { c = cc; return nil }
	if err := app.Run([]string{"test",
		"--postgres-host", u.Hostname(), "--postgres-port", u.Port(), "--postgres-user", u.User.Username(),
		"--postgres-password", pass, "--postgres-database", db,
		"--nats-service-host", natsHost, "--nats-service-port", natsPort,
		"--purge-delay", purgeDelay,
	}); err != nil {
		t.Fatal(err)
	}

	pg := cs.NewPG(c)
	t.Cleanup(pg.Close)
	// Migration 1 hands the table to a role that only existed on the old
	// cluster; give the test database one so it applies.
	if _, err := pg.Get().Exec(`DO $$ BEGIN CREATE ROLE abusestore; EXCEPTION WHEN duplicate_object THEN NULL; END $$`); err != nil {
		t.Fatal(err)
	}
	t.Chdir("..") // the migrator reads ./migrations
	if err := cs.NewPGMigration(pg).Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Get().Exec(`TRUNCATE abuse, banned_published, unconfirmed_notice`); err != nil {
		t.Fatal(err)
	}

	b, err := badger.Open(badger.DefaultOptions("").WithInMemory(true).WithLogger(nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	n := cs.NewNATS(c)
	t.Cleanup(n.Close)
	nc := n.Get()
	if nc == nil {
		t.Fatal("no nats connection")
	}
	sub, err := nc.SubscribeSync(resourceBannedSubject)
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	st := NewStore(c, b, pg, n)
	smtp, sink := newMailSink(t)
	mr := &Mailer{sender: "noreply@example.com", support: "support@example.com", smtp: smtp}
	return &pgEnv{
		g:    &GRPC{store: st, mailer: mr, admin: true},
		pub:  &GRPC{store: st, mailer: mr},
		form: &GRPC{store: st, mailer: mr, formConfirm: true, confirmURL: testConfirmURL},
		s:    st,
		sink: sink,
		banned: func() []string {
			// Publishes are buffered; the flush round trip delivers every one
			// sent so far to this connection's own subscription.
			if err := nc.Flush(); err != nil {
				t.Fatal(err)
			}
			var got []string
			for {
				msg, err := sub.NextMsg(200 * time.Millisecond)
				if err != nil {
					return got
				}
				var p struct{ Infohash string }
				if err := json.Unmarshal(msg.Data, &p); err != nil {
					t.Fatal(err)
				}
				got = append(got, p.Infohash)
			}
		},
	}
}

func (e *pgEnv) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := e.s.p.Get().Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

// count runs a SELECT count(*) query.
func (e *pgEnv) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var r struct{ Count int }
	if _, err := e.s.p.Get().QueryOne(&r, q, args...); err != nil {
		t.Fatal(err)
	}
	return r.Count
}

func (e *pgEnv) sync(t *testing.T) {
	t.Helper()
	if err := e.s.Sync(); err != nil {
		t.Fatal(err)
	}
}

func (e *pgEnv) push(t *testing.T, in *pb.PushRequest) codes.Code {
	t.Helper()
	in.Email = "reporter@example.com"
	_, err := e.g.Push(context.Background(), in)
	if c := status.Code(err); c != codes.OK && c != codes.AlreadyExists {
		t.Fatalf("push: %v", err)
	}
	return status.Code(err)
}

const (
	hashA = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	hashB = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	hashC = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
)

// A delayed ban blocks at once, but nobody purges until purge_after passes;
// then one Sync publishes it, exactly once.
func TestPGDelayedBanIsPublishedOnlyOnceDue(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashA})
	if !blocked(t, e.s, hashA, nil) {
		t.Fatal("delayed ban does not block")
	}
	if got := e.banned(); len(got) != 0 {
		t.Fatalf("published at Push: %v", got)
	}
	if after := e.count(t, `SELECT count(*) FROM abuse WHERE infohash = ? AND purge_after > now() + interval '71 hours'`, hashA); after != 1 {
		t.Fatalf("%d rows with purge_after ~72h ahead, want 1", after)
	}
	e.sync(t)
	if got := e.banned(); len(got) != 0 {
		t.Fatalf("published by Sync before purge_after: %v", got)
	}
	e.exec(t, `UPDATE abuse SET purge_after = now() - interval '1 second'`)
	e.sync(t)
	if got := e.banned(); !slices.Equal(got, []string{hashA}) {
		t.Fatalf("published after purge_after = %v, want [%s]", got, hashA)
	}
	e.sync(t)
	if got := e.banned(); len(got) != 0 {
		t.Fatalf("republished: %v", got)
	}
}

// purge_now publishes with the Push; so does a server with no delay, as
// before the delay existed. Sync does not publish it a second time.
func TestPGPurgeNowPublishesAtPush(t *testing.T) {
	for _, tc := range []struct {
		name, delay string
		purgeNow    bool
	}{{"purge_now", "72h", true}, {"delay 0", "0", false}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPGEnv(t, tc.delay)
			e.push(t, &pb.PushRequest{Infohash: hashA, PurgeNow: tc.purgeNow})
			if got := e.banned(); !slices.Equal(got, []string{hashA}) {
				t.Fatalf("published at Push = %v, want [%s]", got, hashA)
			}
			e.sync(t)
			if got := e.banned(); len(got) != 0 {
				t.Fatalf("republished by Sync: %v", got)
			}
			if mail := e.sink.waitFor(t, 2); !strings.Contains(mail.to("support@example.com"), "Data purge: immediate") {
				t.Fatalf("support letter: %s", mail.to("support@example.com"))
			}
		})
	}
}

// Set exempt, or deleted, inside the window: the data is kept for good. The
// unreviewed ban next to them is what shows the purge would have gone out.
func TestPGReviewInsideTheWindowKeepsTheData(t *testing.T) {
	e := newPGEnv(t, "72h")
	for _, h := range []string{hashA, hashB, hashC} {
		e.push(t, &pb.PushRequest{Infohash: h})
	}
	e.exec(t, `UPDATE abuse SET exempt = true WHERE infohash = ?`, hashA)
	e.exec(t, `DELETE FROM abuse WHERE infohash = ?`, hashB)
	e.exec(t, `UPDATE abuse SET purge_after = now() - interval '1 second'`)
	e.sync(t)
	e.sync(t)
	if got := e.banned(); !slices.Equal(got, []string{hashC}) {
		t.Fatalf("published %v, want only the unreviewed %s", got, hashC)
	}
	if blocked(t, e.s, hashA, nil) || blocked(t, e.s, hashB, nil) {
		t.Fatal("reviewed bans still block")
	}
}

// A repeat report does not purge a delayed ban early; a repeat with
// purge_now does, and moves the schedule so a lost publish is retried by Sync.
// Bringing the purge forward is news: OK and a letter to support. Once nothing
// is pending, a purge_now repeat is AlreadyExists and silent again.
func TestPGDuplicatePush(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashA})
	if c := e.push(t, &pb.PushRequest{Infohash: hashA}); c != codes.AlreadyExists {
		t.Fatalf("repeat: %v, want AlreadyExists", c)
	}
	if got := e.banned(); len(got) != 0 {
		t.Fatalf("repeat report purged a delayed ban: %v", got)
	}
	e.sink.waitFor(t, 2)
	e.sink.reset()

	if c := e.push(t, &pb.PushRequest{Infohash: hashA, PurgeNow: true}); c != codes.OK {
		t.Fatalf("repeat with purge_now bringing the purge forward: %v, want OK", c)
	}
	if got := e.banned(); !slices.Equal(got, []string{hashA}) {
		t.Fatalf("purge_now repeat published %v, want [%s]", got, hashA)
	}
	if pending := e.count(t, `SELECT count(*) FROM abuse WHERE purge_after > now()`); pending != 0 {
		t.Fatalf("%d rows still pending after purge_now", pending)
	}
	mail := e.sink.waitFor(t, 2)
	var support []string
	for _, l := range mail {
		if l.rcpt == "support@example.com" {
			support = append(support, l.body)
		}
	}
	if len(support) != 1 || !strings.Contains(support[0], "Data purge: immediate") ||
		!strings.Contains(support[0], hashA+" (already in the stoplist) (its scheduled purge replaced by this immediate one)") {
		t.Fatalf("%d support letters, want 1 saying the purge replaced the schedule: %q", len(support), support)
	}
	e.sink.reset()

	if c := e.push(t, &pb.PushRequest{Infohash: hashA, PurgeNow: true}); c != codes.AlreadyExists {
		t.Fatalf("purge_now repeat of a purged ban: %v, want AlreadyExists", c)
	}
	if mail := e.sink.waitFor(t, 0); len(mail) != 0 {
		t.Fatalf("%d letters for a purge_now repeat of a purged ban", len(mail))
	}
}

// A server with no delay purges every report at once, but only an immediate
// ban on the admin port overrides an exemption: an exempt hash in an ordinary
// notice is neither stored nor purged, whichever port it came in on.
func TestPGDelayZeroSkipsExempt(t *testing.T) {
	e := newPGEnv(t, "0")
	e.exec(t, `INSERT INTO abuse (infohash, exempt) VALUES (?, true)`, hashC)
	for _, g := range []*GRPC{e.pub, e.g} {
		if _, err := g.Push(context.Background(), &pb.PushRequest{Infohash: hashA, ExtraInfohashes: []string{hashC}}); err != nil && status.Code(err) != codes.AlreadyExists {
			t.Fatalf("push: %v", err)
		}
		if got := e.banned(); !slices.Equal(got, []string{hashA}) {
			t.Fatalf("published %v, want only [%s]", got, hashA)
		}
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE infohash = ?`, hashC); n != 1 {
		t.Fatalf("%d rows for the exempt hash, want its exempt one only", n)
	}
}

// purge_now on the public port is ignored: the ban blocks and waits out the
// delay like any report, and a repeat brings no pending purge forward.
func TestPGPublicPortIgnoresPurgeNow(t *testing.T) {
	e := newPGEnv(t, "72h")
	if _, err := e.pub.Push(context.Background(), &pb.PushRequest{Infohash: hashA, PurgeNow: true}); err != nil {
		t.Fatal(err)
	}
	if !blocked(t, e.s, hashA, nil) {
		t.Fatal("does not block")
	}
	if got := e.banned(); len(got) != 0 {
		t.Fatalf("published at Push: %v", got)
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE purge_after > now() + interval '71 hours'`); n != 1 {
		t.Fatalf("%d rows waiting out the delay, want 1", n)
	}
	if l := e.sink.waitFor(t, 1).to("support@example.com"); !strings.Contains(l, "waits until") {
		t.Fatalf("support letter: %s", l)
	}
	if _, err := e.pub.Push(context.Background(), &pb.PushRequest{Infohash: hashA, PurgeNow: true}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("repeat: %v, want AlreadyExists", err)
	}
	if got := e.banned(); len(got) != 0 {
		t.Fatalf("repeat published %v", got)
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE purge_after > now()`); n != 1 {
		t.Fatal("repeat brought the purge forward")
	}
}

// One notice, several hashes: a row for each new one under the same notice,
// the fingerprint on the primary only, exempt and known ones skipped, and one
// letter each to support and the reporter naming them all.
func TestPGNoticeWithSeveralHashes(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashB})
	e.exec(t, `INSERT INTO abuse (infohash, exempt) VALUES (?, true)`, hashC)
	e.sink.waitFor(t, 2)
	e.sink.reset()

	fp := digest(0x42)
	const extra = "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"
	if c := e.push(t, &pb.PushRequest{NoticeId: "n-1", Infohash: hashA, Fingerprint: fp,
		ExtraInfohashes: []string{strings.ToUpper(hashA), hashB, hashC, extra}}); c != codes.OK {
		t.Fatalf("push: %v", c)
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE notice_id = 'n-1'`); n != 2 {
		t.Fatalf("%d rows for the notice, want 2 (primary + new extra)", n)
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE notice_id = 'n-1' AND fingerprint IS NOT NULL AND infohash = ?`, hashA); n != 1 {
		t.Fatal("fingerprint not on the primary row")
	}
	if n := e.count(t, `SELECT count(*) FROM abuse WHERE notice_id = 'n-1' AND fingerprint IS NOT NULL`); n != 1 {
		t.Fatal("fingerprint copied onto an extra")
	}
	if !blocked(t, e.s, extra, nil) || blocked(t, e.s, hashC, nil) {
		t.Fatal("extra not blocked, or exempt one blocked")
	}
	mail := e.sink.waitFor(t, 2)
	if len(mail) != 2 {
		t.Fatalf("%d letters, want 2", len(mail))
	}
	for _, to := range []string{"support@example.com", "reporter@example.com"} {
		body := mail.to(to)
		for _, h := range []string{hashA, hashB, hashC, extra} {
			if strings.Count(body, h) != 1 {
				t.Errorf("letter to %s names %s %d times", to, h, strings.Count(body, h))
			}
		}
	}
}

// AlreadyExists, and silence, only when every hash was already blocked.
func TestPGAlreadyExistsOnlyWhenAllExist(t *testing.T) {
	e := newPGEnv(t, "72h")
	e.push(t, &pb.PushRequest{Infohash: hashA})
	if c := e.push(t, &pb.PushRequest{Infohash: hashA, ExtraInfohashes: []string{hashB}}); c != codes.OK {
		t.Fatalf("one new hash of two: %v, want OK", c)
	}
	e.sink.waitFor(t, 4)
	e.sink.reset()
	if c := e.push(t, &pb.PushRequest{Infohash: hashA, ExtraInfohashes: []string{hashB}}); c != codes.AlreadyExists {
		t.Fatalf("both known: %v, want AlreadyExists", c)
	}
	if mail := e.sink.waitFor(t, 0); len(mail) != 0 {
		t.Fatalf("%d letters for a pure repeat", len(mail))
	}
	if n := e.count(t, `SELECT count(*) FROM abuse`); n != 2 {
		t.Fatalf("%d rows, want 2", n)
	}
}

// mailSink is just enough of an SMTP server for net/smtp to deliver to.
type mailSink struct {
	mu   sync.Mutex
	mail letters
}

type letters []struct{ rcpt, body string }

func (l letters) to(rcpt string) string {
	for _, m := range l {
		if m.rcpt == rcpt {
			return m.body
		}
	}
	return ""
}

// subject is the decoded Subject of the letter to rcpt.
func (l letters) subject(t *testing.T, rcpt string) string {
	t.Helper()
	return parseLetter(t, l.to(rcpt)).subject
}

type letter struct {
	header  mail.Header
	subject string
}

func parseLetter(t *testing.T, raw string) letter {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("unparsable letter %q: %v", raw, err)
	}
	subj, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil {
		t.Fatal(err)
	}
	return letter{header: msg.Header, subject: subj}
}

func newMailSink(t *testing.T) (*SMTP, *mailSink) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	k := &mailSink{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go k.serve(c)
		}
	}()
	return &SMTP{host: "127.0.0.1", port: ln.Addr().(*net.TCPAddr).Port}, k
}

func (k *mailSink) serve(c net.Conn) {
	defer c.Close()
	tp := textproto.NewConn(c)
	_ = tp.PrintfLine("220 sink")
	var rcpt string
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		switch cmd := strings.ToUpper(line); {
		case strings.HasPrefix(cmd, "AUTH"):
			_ = tp.PrintfLine("235 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			rcpt = strings.Trim(line[len("RCPT TO:"):], "<>")
			_ = tp.PrintfLine("250 ok")
		case cmd == "DATA":
			_ = tp.PrintfLine("354 go")
			b, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			k.mu.Lock()
			k.mail = append(k.mail, struct{ rcpt, body string }{rcpt, string(b)})
			k.mu.Unlock()
			_ = tp.PrintfLine("250 ok")
		case cmd == "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default: // EHLO, MAIL FROM
			_ = tp.PrintfLine("250 ok")
		}
	}
}

// waitFor waits for n letters (sent from goroutines), then a little longer
// so an extra one would show up too.
func (k *mailSink) waitFor(t *testing.T, n int) letters {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		k.mu.Lock()
		got := len(k.mail)
		k.mu.Unlock()
		if got >= n {
			break
		}
	}
	time.Sleep(300 * time.Millisecond)
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.mail)
}

func (k *mailSink) reset() {
	k.mu.Lock()
	k.mail = nil
	k.mu.Unlock()
}

const testConfirmURL = "https://example.com/support/confirm"
