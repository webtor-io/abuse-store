package services

import (
	"context"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/urfave/cli"
	pb "github.com/webtor-io/abuse-store/proto"
	cs "github.com/webtor-io/common-services"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The public port has no Exempt: it answers Unimplemented before touching the
// store (there is none here).
func TestPublicPortHasNoExempt(t *testing.T) {
	_, err := (&GRPC{}).Exempt(context.Background(), &pb.ExemptRequest{Infohash: hashA})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("public Exempt: %v, want Unimplemented", err)
	}
}

// The admin listener binds 127.0.0.1 on 50052 by default, whatever
// --grpc-host says, and --admin-port 0 turns it off.
func TestAdminListener(t *testing.T) {
	parse := func(args ...string) (pub, admin *GRPC) {
		t.Helper()
		app := cli.NewApp()
		app.Flags = RegisterGRPCFlags(nil)
		app.Action = func(c *cli.Context) error {
			pub, admin = NewGRPC(c, nil, nil), NewAdminGRPC(c, nil, nil)
			return nil
		}
		if err := app.Run(append([]string{"test"}, args...)); err != nil {
			t.Fatal(err)
		}
		return pub, admin
	}
	pub, admin := parse("--grpc-host", "0.0.0.0")
	if pub.admin || pub.port != 50051 {
		t.Fatalf("public: %+v", pub)
	}
	if admin == nil || !admin.admin || admin.host != "127.0.0.1" || admin.port != 50052 {
		t.Fatalf("admin: %+v", admin)
	}
	if _, admin := parse("--admin-port", "0"); admin != nil {
		t.Fatalf("--admin-port 0: %+v", admin)
	}
}

// A subject with CR LF in it cannot add a header: it is encoded, and decodes
// back to what was sent.
func TestSubjectCannotAddAHeader(t *testing.T) {
	smtp, sink := newMailSink(t)
	const subj = "hi\r\nBcc: evil@example.com"
	if err := smtp.Send("noreply@example.com", "support@example.com", "", subj, "body"); err != nil {
		t.Fatal(err)
	}
	l := parseLetter(t, sink.waitFor(t, 1).to("support@example.com"))
	if len(l.header["Bcc"]) != 0 {
		t.Fatalf("subject added a header: %v", l.header)
	}
	if l.subject != subj {
		t.Fatalf("subject %q, want %q", l.subject, subj)
	}
}

// Push drops CR and LF from the subject and the notice id before they reach
// the letters (and the table).
func TestPushKeepsSubjectAndNoticeIDOnOneLine(t *testing.T) {
	smtp, sink := newMailSink(t)
	g := &GRPC{mailer: &Mailer{sender: "noreply@example.com", support: "support@example.com", smtp: smtp}}
	_, err := g.Push(context.Background(), &pb.PushRequest{Cause: pb.PushRequest_QUESTION,
		NoticeId: "n\r\nX-Evil: 1", Subject: "hi\nBcc: evil@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	l := parseLetter(t, sink.waitFor(t, 1).to("support@example.com"))
	if l.subject != "[nX-Evil: 1] hiBcc: evil@example.com" || strings.ContainsAny(l.subject, "\r\n") {
		t.Fatalf("subject %q", l.subject)
	}
}

// purge_now on the public port is logged with every infohash of the notice:
// the only trace of a ban whose purge was meant to be immediate. (No database
// here, so Push fails after the warning.)
func TestPublicPortLogsIgnoredPurgeNow(t *testing.T) {
	hook := logtest.NewGlobal()
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(make(log.LevelHooks)) })
	g := &GRPC{store: &Store{p: &cs.PG{}, pd: time.Hour}}
	_, _ = g.Push(context.Background(), &pb.PushRequest{Infohash: hashA, ExtraInfohashes: []string{hashB}, PurgeNow: true})
	for _, e := range hook.AllEntries() {
		if e.Message == "purge_now ignored on the public port" {
			if e.Level != log.WarnLevel || e.Data["infohash"] != hashA+","+hashB {
				t.Fatalf("warning %v with fields %v, want warn with infohash=%s,%s", e.Level, e.Data, hashA, hashB)
			}
			return
		}
	}
	t.Fatal("purge_now on the public port not logged")
}
