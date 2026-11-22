package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"github.com/urfave/cli"
	m "github.com/webtor-io/abuse-store/models"
	pb "github.com/webtor-io/abuse-store/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	log "github.com/sirupsen/logrus"
)

// infohashRe matches a full v1 infohash and nothing else. It is anchored:
// the previous pattern was not, so any string containing five hex characters
// anywhere passed — which is how 51 rows carrying magnet URIs and web links
// got stored verbatim as stoplist keys, blocking nothing.
var infohashRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// normalizeInfohash trims and lowercases before validation, so a hash pasted
// in upper case (as many trackers emit) is accepted rather than rejected or,
// worse, silently reduced to nothing upstream.
func normalizeInfohash(h string) string {
	return strings.ToLower(strings.TrimSpace(h))
}

const (
	grpcHostFlag    = "grpc-host"
	grpcPortFlag    = "grpc-port"
	adminPortFlag   = "admin-port"
	formConfirmFlag = "form-confirm"
	confirmURLFlag  = "confirm-url"
)

// adminHost is where the admin listener binds, and the whole of its access
// control: only something inside the pod's network namespace reaches it,
// which from outside means kubectl port-forward to the pod. It has no
// Service port and needs no containerPort.
const adminHost = "127.0.0.1"

func RegisterGRPCFlags(f []cli.Flag) []cli.Flag {
	return append(f,
		cli.StringFlag{
			Name:   grpcHostFlag,
			Usage:  "grpc listening host",
			Value:  "",
			EnvVar: "GRPC_HOST",
		},
		cli.IntFlag{
			Name:   grpcPortFlag,
			Usage:  "grpc listening port",
			Value:  50051,
			EnvVar: "GRPC_PORT",
		},
		cli.IntFlag{
			Name:   adminPortFlag,
			Usage:  "admin grpc port on " + adminHost + " (Push with purge_now honoured, Check, Exempt); 0 disables it",
			Value:  50052,
			EnvVar: "ADMIN_GRPC_PORT",
		},
		cli.BoolFlag{
			Name:   formConfirmFlag,
			Usage:  "hold ILLEGAL_CONTENT and INTIMATE_IMAGE notices from the form on the public port until the reporter confirms them through a link mailed to them",
			EnvVar: "FORM_CONFIRM",
		},
		cli.StringFlag{
			Name:   confirmURLFlag,
			Usage:  "page the confirmation link opens; the token is appended as ?t=",
			Value:  "https://webtor.io/support/confirm",
			EnvVar: "CONFIRM_URL",
		},
	)
}

// gracefulStopTimeout bounds how long shutdown waits for in-flight RPCs.
// Check answers from a local KV and Push is dominated by one insert, so the
// real tail is far below this; the pod's terminationGracePeriodSeconds is 30,
// leaving room for Badger to close afterwards.
const gracefulStopTimeout = 15 * time.Second

// GRPC serves one listener. The public one (the Service, no authentication)
// serves Push and Check and ignores purge_now; the admin one also honours
// purge_now and serves Exempt, the two calls that override a decision: an
// immediate ban beats an exemption, an exemption lifts a ban.
//
// With formConfirm, the public one holds form notices that would ban until
// their reporter confirms them (Confirm, on both listeners).
type GRPC struct {
	pb.UnimplementedAbuseStoreServer
	host        string
	port        int
	admin       bool
	formConfirm bool
	confirmURL  string
	ln          net.Listener
	store       *Store
	mailer      *Mailer
	mu          sync.Mutex
	gs          *grpc.Server
}

func NewGRPC(c *cli.Context, s *Store, mr *Mailer) *GRPC {
	return &GRPC{
		host:        c.String(grpcHostFlag),
		port:        c.Int(grpcPortFlag),
		formConfirm: c.Bool(formConfirmFlag),
		confirmURL:  c.String(confirmURLFlag),
		store:       s,
		mailer:      mr,
	}
}

// NewAdminGRPC is the admin listener on adminHost, or nil with --admin-port 0.
func NewAdminGRPC(c *cli.Context, s *Store, mr *Mailer) *GRPC {
	if c.Int(adminPortFlag) == 0 {
		return nil
	}
	return &GRPC{
		host:   adminHost,
		port:   c.Int(adminPortFlag),
		admin:  true,
		store:  s,
		mailer: mr,
	}
}

func (s *GRPC) Serve() error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return errors.Wrap(err, "failed to listen to tcp connection")
	}
	s.ln = ln
	var opts []grpc.ServerOption
	gs := grpc.NewServer(opts...)
	pb.RegisterAbuseStoreServer(gs, s)

	s.mu.Lock()
	s.gs = gs
	s.mu.Unlock()

	log.WithField("admin", s.admin).Infof("serving GRPC at %v", addr)
	return gs.Serve(ln)
}
func (s *GRPC) Push(ctx context.Context, in *pb.PushRequest) (*pb.PushReply, error) {
	startedAt := time.Now()
	if in.GetStartedAt() != 0 {
		startedAt = time.Unix(in.GetStartedAt(), 0)
	}
	// Both end up in a mail header (the subject); smtp.go encodes it as well.
	noticeID := oneLine(in.GetNoticeId())
	if noticeID == "" {
		noticeID = fmt.Sprintf("%s", uuid.NewV4())
	}
	hashes, err := noticeInfohashes(in.GetInfohash(), in.GetExtraInfohashes())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	infohash := hashes[0]

	// A ban has to name what it bans. Without either arm the row is dead
	// weight: no infohash to key the stoplist on, no fingerprint to catch
	// re-uploads — and it used to be worse than useless, because a row with
	// no infohash could not be cached at all and took the whole sync down
	// with it.
	if bans(in.GetCause()) && infohash == "" && len(in.GetFingerprint()) != fingerprintSize {
		return nil, status.Error(codes.InvalidArgument, "illegal content report needs an infohash or a content fingerprint")
	}

	email := in.GetEmail()
	if email != "" {
		match, _ := regexp.MatchString("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", email)
		if !match {
			return nil, status.Error(codes.InvalidArgument, "wrong email")
		}
	}

	subject := oneLine(in.GetSubject())
	if subject == "" {
		subject = fmt.Sprintf("Abuse notice %v", noticeID)
	}
	a := &m.Abuse{
		NoticeID:     noticeID,
		StartedAt:    startedAt,
		Work:         in.GetWork(),
		Filename:     in.GetFilename(),
		Infohash:     infohash,
		Description:  in.GetDescription(),
		Email:        email,
		Subject:      subject,
		Fingerprint:  in.GetFingerprint(),
		Cause:        int(in.GetCause()),
		Source:       int(in.GetSource()),
		ReporterName: in.GetReporterName(),
		GoodFaith:    in.GetGoodFaith(),
		Authorized:   in.GetAuthorized(),
	}
	if !bans(in.GetCause()) {
		n := &Notice{Abuse: a}
		for _, h := range hashes {
			n.Hashes = append(n.Hashes, NoticeHash{Infohash: h})
		}
		s.notify(n)
		return &pb.PushReply{}, nil
	}
	// Only the public listener has formConfirm (NewGRPC): the automated
	// intake (MAIL) and the admin port ban as before.
	if s.formConfirm && in.GetSource() == pb.PushRequest_FORM {
		return s.askConfirmation(ctx, a, hashes)
	}
	// The block is immediate; the purge waits out the delay unless the caller
	// on the admin port or the server (delay 0) says otherwise. Sync publishes
	// once it is due.
	override := in.GetPurgeNow() && s.admin
	if in.GetPurgeNow() && !s.admin {
		log.WithField("notice_id", noticeID).WithField("infohash", strings.Join(hashes, ",")).
			Warn("purge_now ignored on the public port")
	}
	n, err := s.ban(ctx, a, hashes, override)
	if err != nil {
		return nil, err
	}
	s.notify(n)
	return &pb.PushReply{}, nil
}

// bans reports whether a notice of cause c blocks what it names. The others
// are mailed only, CSAM_REPORT included: a report of it is for a person to
// look at, and the bans go through the admin port.
func bans(c pb.PushRequest_Cause) bool {
	return c == pb.PushRequest_ILLEGAL_CONTENT || c == pb.PushRequest_INTIMATE_IMAGE
}

// ban stores a banning notice, hash by hash, and returns it for the letters;
// AlreadyExists when it changed nothing.
func (s *GRPC) ban(ctx context.Context, a *m.Abuse, hashes []string, override bool) (*Notice, error) {
	n := &Notice{Abuse: a}
	n.PurgeNow = override || s.store.pd <= 0
	a.PurgeAfter = time.Now()
	if !n.PurgeNow {
		a.PurgeAfter = a.PurgeAfter.Add(s.store.pd)
	}
	for i, h := range hashes {
		row := *a
		row.Infohash = h
		if i > 0 {
			// The fingerprint is the primary torrent's payload, not the
			// extras'.
			row.Fingerprint = nil
		}
		nh, err := s.store.Push(ctx, &row, override)
		if err != nil {
			return nil, err
		}
		if nh.Exempt {
			log.WithField("infohash", h).Info("report for exempt infohash not added to stoplist")
		} else if n.PurgeNow {
			// Duplicates included: a dropped publish is retried by Sync, and
			// consumers must be idempotent. A delayed ban publishes nothing
			// here, so a repeat report cannot purge it early.
			s.store.PublishBanned(h)
		}
		n.Hashes = append(n.Hashes, nh)
	}
	// Silent only when nothing changed: every hash already blocked (an exempt
	// or overridden one was not) and no purge brought forward.
	if !slices.ContainsFunc(n.Hashes, func(h NoticeHash) bool { return !h.Existed || h.Advanced }) {
		return nil, status.Errorf(codes.AlreadyExists, "abuse notice with infoHash=%v already exists", strings.Join(hashes, ","))
	}
	return n, nil
}

// pendingNotice is what an unconfirmed notice keeps for Confirm to replay
// through ban: the notice as Push normalized it, and its infohashes.
type pendingNotice struct {
	Abuse  *m.Abuse
	Hashes []string
}

// tokenSize is the random part of a confirmation link, in bytes.
const tokenSize = 32

// askConfirmation holds a form notice that would ban until its reporter
// confirms it, and mails them the link. Nothing is blocked or mailed to
// support until then. The address must be theirs: a takedown notice also
// needs their name and both statements.
func (s *GRPC) askConfirmation(ctx context.Context, a *m.Abuse, hashes []string) (*pb.PushReply, error) {
	if a.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "a notice from the form needs the reporter's email, to confirm it")
	}
	if a.Cause == int(pb.PushRequest_ILLEGAL_CONTENT) && (strings.TrimSpace(a.ReporterName) == "" || !a.GoodFaith || !a.Authorized) {
		return nil, status.Error(codes.InvalidArgument, "a takedown notice needs the reporter's name and both statements")
	}
	// Nothing to confirm when every hash already blocks: AlreadyExists and no
	// letter, as without the flag.
	if !slices.ContainsFunc(hashes, func(h string) bool { return h == "" || s.store.Check(h, nil) != nil }) {
		return nil, status.Errorf(codes.AlreadyExists, "abuse notice with infoHash=%v already exists", strings.Join(hashes, ","))
	}
	// The notice id goes into the confirmation letter's subject, which must
	// carry nothing the caller typed: a uuid, rewritten canonically, or a new one.
	id, err := uuid.FromString(a.NoticeID)
	if err != nil {
		id = uuid.NewV4()
	}
	a.NoticeID = id.String()
	notice, err := json.Marshal(pendingNotice{Abuse: a, Hashes: hashes})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	tok := make([]byte, tokenSize)
	_, _ = rand.Read(tok) // never fails (crypto/rand, Go 1.24+)
	th := sha256.Sum256(tok)
	expires, err := s.store.AddUnconfirmed(ctx, th[:], a.Email, notice)
	if errors.Is(err, ErrTooManyNotices) {
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	} else if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	link := s.confirmURL + "?t=" + base64.RawURLEncoding.EncodeToString(tok)
	// Sent before replying, unlike the other letters: without it the notice
	// can never be confirmed, and the reporter is told to look for it.
	named := slices.DeleteFunc(slices.Clone(hashes), func(h string) bool { return h == "" })
	if err := s.mailer.SendConfirmEmail(a.Email, a.NoticeID, link, named, expires); err != nil {
		log.WithError(err).WithField("notice_id", a.NoticeID).Error("failed to send confirmation email")
		if err := s.store.DropUnconfirmed(th[:]); err != nil {
			log.WithError(err).WithField("notice_id", a.NoticeID).Error("failed to drop unconfirmed notice")
		}
		return nil, status.Error(codes.Unavailable, "failed to send the confirmation email")
	}
	log.WithField("notice_id", a.NoticeID).WithField("infohash", strings.Join(hashes, ",")).Info("notice waits for confirmation")
	return &pb.PushReply{ConfirmationSent: true}, nil
}

// Confirm stores and mails a notice held by askConfirmation, once, as Push
// would have without the flag; on both listeners, since the token is the
// credential. A notice whose every hash got blocked meanwhile is confirmed
// with no letters, as a repeat Push is AlreadyExists and silent.
func (s *GRPC) Confirm(ctx context.Context, in *pb.ConfirmRequest) (*pb.ConfirmReply, error) {
	// One that does not decode matches no stored hash: UNKNOWN.
	tok, _ := base64.RawURLEncoding.DecodeString(in.GetToken())
	th := sha256.Sum256(tok)
	var p pendingNotice
	var n *Notice
	err := s.store.Confirm(ctx, th[:], func(notice []byte) error {
		if err := json.Unmarshal(notice, &p); err != nil {
			return err
		}
		var berr error
		if n, berr = s.ban(ctx, p.Abuse, p.Hashes, false); status.Code(berr) == codes.AlreadyExists {
			return nil
		}
		return berr
	})
	switch {
	case errors.Is(err, ErrNotFound):
		return &pb.ConfirmReply{Status: pb.ConfirmReply_UNKNOWN}, nil
	case errors.Is(err, ErrNoticeConfirmed):
		return &pb.ConfirmReply{Status: pb.ConfirmReply_ALREADY_CONFIRMED}, nil
	case errors.Is(err, ErrNoticeExpired):
		return &pb.ConfirmReply{Status: pb.ConfirmReply_EXPIRED}, nil
	case err != nil:
		log.WithError(err).Error("failed to confirm notice")
		return nil, status.Error(codes.Internal, err.Error())
	}
	if n != nil {
		n.Confirmed = true
		s.notify(n)
	}
	log.WithField("notice_id", p.Abuse.NoticeID).Info("notice confirmed")
	return &pb.ConfirmReply{Status: pb.ConfirmReply_CONFIRMED, Hashes: int32(len(slices.DeleteFunc(p.Hashes, func(h string) bool { return h == "" })))}, nil
}

// noticeInfohashes normalizes and validates the primary infohash and the
// extras, and drops repeats. The primary stays first, and may be empty (a
// fingerprint-only ban); an extra may not.
func noticeInfohashes(primary string, extras []string) ([]string, error) {
	primary = normalizeInfohash(primary)
	if primary != "" && !infohashRe.MatchString(primary) {
		return nil, errors.New("wrong infohash")
	}
	hashes := []string{primary}
	for _, h := range extras {
		h = normalizeInfohash(h)
		if !infohashRe.MatchString(h) {
			return nil, errors.Errorf("wrong extra infohash %q", h)
		}
		if !slices.Contains(hashes, h) {
			hashes = append(hashes, h)
		}
	}
	return hashes, nil
}

// oneLine drops CR and LF, so a value that ends up in a mail header cannot
// start a header of its own.
func oneLine(v string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(v)
}

// notify mails the reporter (when they left an address; never for a CSAM
// report) and support, once per notice whatever the number of infohashes.
// Best effort: failures are logged and never fail the RPC.
func (s *GRPC) notify(n *Notice) {
	if n.Abuse.Email != "" && n.Abuse.Cause != int(pb.PushRequest_CSAM_REPORT) {
		go func() {
			if err := s.mailer.SendUserEmail(n); err != nil {
				log.WithError(err).Error("failed to send user email")
			}
		}()
	}
	go func() {
		if err := s.mailer.SendSupportEmail(n); err != nil {
			log.WithError(err).Error("failed to send support email")
		}
	}()
}

func (s *GRPC) Check(_ context.Context, in *pb.CheckRequest) (*pb.CheckReply, error) {
	// Infohashes are normalized on the way in, so normalize on the way out
	// too: a caller sending an upper-case hash must get the same answer as one
	// sending it lower-case, not a silent miss.
	err := s.store.Check(normalizeInfohash(in.GetInfohash()), in.GetFingerprint())
	if errors.Is(err, ErrNotFound) {
		return &pb.CheckReply{Exists: false}, nil
	} else if err != nil {
		return nil, errors.Wrap(err, "failed to get data")
	} else {
		return &pb.CheckReply{Exists: true}, nil
	}
}

// Exempt lifts a ban still in its review window (Store.Exempt), on the admin
// port only: the public one answers Unimplemented. An immediate purge or a
// purge already due is FailedPrecondition, and is exempted by hand. Every
// exemption is mailed to support with its reason.
func (s *GRPC) Exempt(ctx context.Context, in *pb.ExemptRequest) (*pb.ExemptReply, error) {
	if !s.admin {
		return s.UnimplementedAbuseStoreServer.Exempt(ctx, in)
	}
	h := normalizeInfohash(in.GetInfohash())
	if !infohashRe.MatchString(h) {
		return nil, status.Error(codes.InvalidArgument, "wrong infohash")
	}
	l := log.WithField("infohash", h).WithField("reason", in.GetReason())
	n, err := s.store.Exempt(ctx, h)
	// Rows changed means the UPDATE committed: support hears of it even when
	// the cache reload after it failed and the call returns that error.
	if n > 0 {
		go func() {
			if err := s.mailer.SendExemptEmail(h, oneLine(in.GetReason()), n); err != nil {
				log.WithError(err).Error("failed to send exempt email")
			}
		}()
	}
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, status.Errorf(codes.NotFound, "no abuse rows for infohash=%v", h)
	case errors.Is(err, ErrPurgeDue):
		l.Warn("exempt refused: not in the review window")
		return nil, status.Errorf(codes.FailedPrecondition, "infohash=%v is not in its review window (immediate purge, row from before the delay, or purge due); exempt it in the database by hand", h)
	case err != nil:
		l.WithError(err).Error("failed to exempt")
		return nil, status.Error(codes.Internal, err.Error())
	}
	l.WithField("rows", n).Info("infohash exempted")
	return &pb.ExemptReply{Rows: int32(n)}, nil
}

// Close drains in-flight RPCs before returning.
//
// Closing only the listener — which is what this used to do — stops new
// connections but leaves established ones serving, and shutdown then continued
// down the defer chain and closed Badger underneath handlers still reading it.
// That is the exact shape that crashed torrent-store three times during
// rollouts in August 2026 (nil dereference inside Badger's memtable handling).
// Badger closes after this returns, so it must be able to assume no handler is
// still using it.
func (s *GRPC) Close() {
	log.Info("closing GRPC")
	defer func() {
		log.Info("GRPC closed")
	}()

	s.mu.Lock()
	gs := s.gs
	s.mu.Unlock()

	if gs == nil {
		// Never got as far as serving.
		if s.ln != nil {
			_ = s.ln.Close()
		}
		return
	}

	done := make(chan struct{})
	go func() {
		gs.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(gracefulStopTimeout):
		// A stuck stream must not hold shutdown past the pod's grace period —
		// losing it beats being SIGKILLed mid-close.
		log.Warn("grpc graceful stop timed out, forcing")
		gs.Stop()
		<-done
	}
}
