package main

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	pb "github.com/webtor-io/abuse-store/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type recorder struct {
	pb.UnimplementedAbuseStoreServer
	got        *pb.PushRequest
	gotExempt  *pb.ExemptRequest
	exemptErr  error
	gotConfirm *pb.ConfirmRequest
}

func (r *recorder) Confirm(_ context.Context, in *pb.ConfirmRequest) (*pb.ConfirmReply, error) {
	r.gotConfirm = in
	return &pb.ConfirmReply{Status: pb.ConfirmReply_CONFIRMED, Hashes: 2}, nil
}

func (r *recorder) Exempt(_ context.Context, in *pb.ExemptRequest) (*pb.ExemptReply, error) {
	r.gotExempt = in
	if r.exemptErr != nil {
		return nil, r.exemptErr
	}
	return &pb.ExemptReply{Rows: 1}, nil
}

func (r *recorder) Push(_ context.Context, in *pb.PushRequest) (*pb.PushReply, error) {
	r.got = in
	return &pb.PushReply{}, nil
}

// Every push flag reaches the request; --subject and --started-at used to be
// parsed and then dropped.
func TestPushFlagsReachTheRequest(t *testing.T) {
	r, port := serveRecorder(t)

	run := func(args ...string) *pb.PushRequest {
		t.Helper()
		r.got = nil
		if err := newApp().Run(append([]string{"cli", "--host", "127.0.0.1", "--port", port, "push"}, args...)); err != nil {
			t.Fatal(err)
		}
		return r.got
	}

	const a, b, c = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccccccccccc"
	got := run("--hash", a, "--extra-hash", b, "--extra-hash", c, "--purge-now", "--source", "mail",
		"--subject", "s", "--started-at", "2026-11-21T10:00:00Z", "--notice-id", "n",
		"--reporter-name", "R", "--good-faith", "--authorized")
	want := &pb.PushRequest{Infohash: a, ExtraInfohashes: []string{b, c}, PurgeNow: true, Source: pb.PushRequest_MAIL,
		Subject: "s", StartedAt: 1795255200, NoticeId: "n", Cause: pb.PushRequest_ILLEGAL_CONTENT,
		ReporterName: "R", GoodFaith: true, Authorized: true}
	if !proto.Equal(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}

	// Defaults: a form report, purged after the delay.
	if got := run("--hash", a, "--started-at", "1795255200"); got.Source != pb.PushRequest_FORM || got.PurgeNow || got.StartedAt != 1795255200 {
		t.Fatalf("defaults: %v", got)
	}

	for flag, want := range map[string]pb.PushRequest_Cause{"illegal": pb.PushRequest_ILLEGAL_CONTENT, "malware": pb.PushRequest_MALWARE,
		"app_error": pb.PushRequest_APP_ERROR, "question": pb.PushRequest_QUESTION, "csam_report": pb.PushRequest_CSAM_REPORT,
		"intimate_image": pb.PushRequest_INTIMATE_IMAGE} {
		if got := run("--hash", a, "--cause", flag); got.Cause != want {
			t.Errorf("--cause %s sent %v, want %v", flag, got.Cause, want)
		}
	}

	for _, bad := range [][]string{{"--hash", a, "--source", "fax"}, {"--hash", a, "--started-at", "yesterday"}, {"--hash", a, "--cause", "spam"}} {
		if err := newApp().Run(append([]string{"cli", "--host", "127.0.0.1", "--port", port, "push"}, bad...)); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func serveRecorder(t *testing.T) (*recorder, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{}
	gs := grpc.NewServer()
	pb.RegisterAbuseStoreServer(gs, r)
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)
	return r, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}

// exempt sends --hash and --reason; a refusal comes back as an error naming
// the gRPC code, which main prints before exiting 1.
func TestExemptFlagsAndErrors(t *testing.T) {
	r, port := serveRecorder(t)
	const a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	run := func() error {
		return newApp().Run([]string{"cli", "-H", "127.0.0.1", "-P", port, "exempt", "--hash", a, "--reason", "reviewed"})
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if want := (&pb.ExemptRequest{Infohash: a, Reason: "reviewed"}); !proto.Equal(r.gotExempt, want) {
		t.Fatalf("got  %v\nwant %v", r.gotExempt, want)
	}
	for _, c := range []codes.Code{codes.FailedPrecondition, codes.NotFound} {
		r.exemptErr = status.Error(c, "no")
		if err := run(); err == nil || !strings.Contains(err.Error(), "code = "+c.String()) {
			t.Errorf("%v: got error %v", c, err)
		}
	}
}

// confirm sends --token.
func TestConfirmSendsTheToken(t *testing.T) {
	r, port := serveRecorder(t)
	if err := newApp().Run([]string{"cli", "-H", "127.0.0.1", "-P", port, "confirm", "--token", "tok"}); err != nil {
		t.Fatal(err)
	}
	if want := (&pb.ConfirmRequest{Token: "tok"}); !proto.Equal(r.gotConfirm, want) {
		t.Fatalf("got  %v\nwant %v", r.gotConfirm, want)
	}
}
