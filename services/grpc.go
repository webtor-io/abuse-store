package services

import (
	"context"
	"fmt"
	"net"
	"regexp"
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

type GRPC struct {
	pb.UnimplementedAbuseStoreServer
	host   string
	port   int
	ln     net.Listener
	store  *Store
	mailer *Mailer
}

func NewGRPC(c *cli.Context, s *Store, mr *Mailer) *GRPC {
	return &GRPC{
		host:   c.String(grpcHostFlag),
		port:   c.Int(grpcPortFlag),
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
	infohash := in.GetInfohash()
	if infohash != "" {
		match, _ := regexp.MatchString("[0-9a-f]{5,40}", infohash)

		if !match {
			return nil, status.Error(codes.InvalidArgument, "wrong infohash")
		}
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
		Cause:       int(in.GetCause()),
		Source:      int(in.GetSource()),
	}
	if in.GetCause() == pb.PushRequest_ILLEGAL_CONTENT {
		exists := false
		r, err := s.Check(ctx, &pb.CheckRequest{Infohash: infohash})
		if err != nil {
			return nil, err
		}
		exists = r.Exists
		if exists {
			return nil, status.Errorf(codes.AlreadyExists, "abuse notice with infoHash=%v already exists", infohash)
		}
		err = s.store.Push(a)
		if err != nil {
			return nil, err
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

func (s *GRPC) Check(ctx context.Context, in *pb.CheckRequest) (*pb.CheckReply, error) {
	err := s.store.Check(in.GetInfohash())
	if err == ErrNotFound {
		return &pb.CheckReply{Exists: false}, nil
	} else if err != nil {
		return nil, errors.Wrap(err, "failed to get data")
	} else {
		return &pb.CheckReply{Exists: true}, nil
	}
}

func (s *GRPC) Close() {
	log.Info("closing GRPC")
	defer func() {
		log.Info("GRPC closed")
	}()
	if s.ln != nil {
		s.ln.Close()
	}
}
