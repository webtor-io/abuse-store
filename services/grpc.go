package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"github.com/urfave/cli"
	m "github.com/webtor-io/abuse-store/models"
	pb "github.com/webtor-io/abuse-store/proto"
	cs "github.com/webtor-io/common-services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	log "github.com/sirupsen/logrus"
)

const resourceBannedSubject = "resource.banned"

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
	grpcHostFlag = "grpc-host"
	grpcPortFlag = "grpc-port"
)

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
	)
}

// gracefulStopTimeout bounds how long shutdown waits for in-flight RPCs.
// Check answers from a local KV and Push is dominated by one insert, so the
// real tail is far below this; the pod's terminationGracePeriodSeconds is 30,
// leaving room for Badger to close afterwards.
const gracefulStopTimeout = 15 * time.Second

type GRPC struct {
	pb.UnimplementedAbuseStoreServer
	host   string
	port   int
	ln     net.Listener
	store  *Store
	mailer *Mailer
	nats   *cs.NATS
	mu     sync.Mutex
	gs     *grpc.Server
}

func NewGRPC(c *cli.Context, s *Store, mr *Mailer, nats *cs.NATS) *GRPC {
	return &GRPC{
		host:   c.String(grpcHostFlag),
		port:   c.Int(grpcPortFlag),
		store:  s,
		mailer: mr,
		nats:   nats,
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

	log.Infof("serving GRPC at %v", addr)
	return gs.Serve(ln)
}
func (s *GRPC) Push(ctx context.Context, in *pb.PushRequest) (*pb.PushReply, error) {
	startedAt := time.Now()
	if in.GetStartedAt() != 0 {
		startedAt = time.Unix(in.GetStartedAt(), 0)
	}
	noticeID := in.GetNoticeId()
	if noticeID == "" {
		noticeID = fmt.Sprintf("%s", uuid.NewV4())
	}
	infohash := normalizeInfohash(in.GetInfohash())
	if infohash != "" && !infohashRe.MatchString(infohash) {
		return nil, status.Error(codes.InvalidArgument, "wrong infohash")
	}

	// A ban has to name what it bans. Without either arm the row is dead
	// weight: no infohash to key the stoplist on, no fingerprint to catch
	// re-uploads — and it used to be worse than useless, because a row with
	// no infohash could not be cached at all and took the whole sync down
	// with it.
	if in.GetCause() == pb.PushRequest_ILLEGAL_CONTENT && infohash == "" && len(in.GetFingerprint()) != fingerprintSize {
		return nil, status.Error(codes.InvalidArgument, "illegal content report needs an infohash or a content fingerprint")
	}

	email := in.GetEmail()
	if email != "" {
		match, _ := regexp.MatchString("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", email)
		if !match {
			return nil, status.Error(codes.InvalidArgument, "wrong email")
		}
	}

	subject := in.GetSubject()
	if subject == "" {
		subject = fmt.Sprintf("Abuse notice %v", noticeID)
	}
	a := &m.Abuse{
		NoticeID:    noticeID,
		StartedAt:   startedAt,
		Work:        in.GetWork(),
		Filename:    in.GetFilename(),
		Infohash:    infohash,
		Description: in.GetDescription(),
		Email:       email,
		Subject:     subject,
		Fingerprint: in.GetFingerprint(),
		Cause:       int(in.GetCause()),
		Source:      int(in.GetSource()),
	}
	if in.GetCause() == pb.PushRequest_ILLEGAL_CONTENT {
		// Deduplicate on the REPORT, not on the payload: the fingerprints are
		// deliberately not passed here. A newly reported infohash whose payload
		// is already blocked still deserves its own abuse row, otherwise the
		// audit trail loses the fact that it was reported at all.
		r, err := s.Check(ctx, &pb.CheckRequest{Infohash: infohash})
		if err != nil {
			return nil, err
		}
		if !r.Exists {
			err = s.store.Push(a)
			if err != nil {
				return nil, err
			}
		}
		// Always publish on ILLEGAL_CONTENT — a duplicate report re-triggers
		// downstream cleanup, recovering from a previously dropped publish.
		// Consumers must be idempotent.
		s.publishBanned(infohash)
		if r.Exists {
			return nil, status.Errorf(codes.AlreadyExists, "abuse notice with infoHash=%v already exists", infohash)
		}
	}
	if email != "" {
		go func() {
			err := s.mailer.SendUserEmail(a)
			if err != nil {
				log.WithError(err).Error("failed to send user email")
			}
		}()
	}
	go func() {
		err := s.mailer.SendSupportEmail(a)
		if err != nil {
			log.WithError(err).Error("failed to send support email")
		}
	}()
	return &pb.PushReply{}, nil
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

func (s *GRPC) publishBanned(infohash string) {
	if s.nats == nil {
		return
	}
	if infohash == "" {
		return
	}
	nc := s.nats.Get()
	if nc == nil {
		log.WithField("infohash", infohash).Error("failed to get nats connection, skipping resource.banned publish")
		return
	}
	body, err := json.Marshal(struct {
		Infohash string `json:"infohash"`
	}{Infohash: infohash})
	if err != nil {
		log.WithError(err).WithField("infohash", infohash).Error("failed to marshal resource.banned payload")
		return
	}
	if err := nc.Publish(resourceBannedSubject, body); err != nil {
		log.WithError(err).WithField("infohash", infohash).Error("failed to publish resource.banned")
		return
	}
	log.WithField("infohash", infohash).Info("published resource.banned")
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
