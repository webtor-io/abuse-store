package services

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/mailgun/mailgun-go/v3"
	"github.com/urfave/cli"
	m "github.com/webtor-io/abuse-store/models"

	pb "github.com/webtor-io/abuse-store/proto"
)

func emailQuote(in string) string {
	clines := []string{}
	for _, line := range strings.Split(in, "\n") {
		clines = append(clines, fmt.Sprintf("> %s", line))
	}
	return strings.Join(clines, "\n")
}

func isIllegal(a *m.Abuse) bool {
	return a.Cause == int(pb.PushRequest_ILLEGAL_CONTENT)
}

func causeName(c int) string {
	return pb.PushRequest_Cause_name[int32(c)]
}

var (
	//go:embed templates/user.go.tpl
	userTemplateSrc string
	//go:embed templates/support.go.tpl
	supportTemplateSrc string

	userTemplate = template.Must(template.New("user").Funcs(template.FuncMap{
		"IsIllegal":  isIllegal,
		"EmailQuote": emailQuote,
	}).Parse(userTemplateSrc))
	supportTemplate = template.Must(template.New("support").Funcs(template.FuncMap{
		"CauseName": causeName,
	}).Parse(supportTemplateSrc))
)

const (
	mailSender  = "mail-sender"
	mailSupport = "mail-support"
)

func RegisterMailerFlags(f []cli.Flag) []cli.Flag {
	return append(f,
		cli.StringFlag{
			Name:   mailSender,
			Usage:  "mail sender",
			Value:  "noreply@webtor.io",
			EnvVar: "MAIL_SENDER",
		},
		cli.StringFlag{
			Name:   mailSupport,
			Usage:  "mail support",
			Value:  "support@webtor.io",
			EnvVar: "MAIL_SUPPORT",
		},
	)
}

type Mailer struct {
	sender  string
	support string
	mg      *mailgun.MailgunImpl
}

type View struct {
	Abuse   *m.Abuse
	Support string
}

func NewMailer(c *cli.Context, mg *mailgun.MailgunImpl) *Mailer {
	return &Mailer{
		sender:  c.String(mailSender),
		support: c.String(mailSupport),
		mg:      mg,
	}
}

func (s *Mailer) render(a *m.Abuse, t *template.Template) (string, error) {
	var b bytes.Buffer
	v := &View{
		Abuse:   a,
		Support: s.support,
	}
	err := t.Execute(&b, v)
	if err != nil {
		return "", errors.Wrapf(err, "failed to render template=%v with view=%v", t.Name(), v)
	}
	return b.String(), nil
}

func (s *Mailer) SendUserEmail(a *m.Abuse) error {
	body, err := s.render(a, userTemplate)
	if err != nil {
		return err
	}

	message := s.mg.NewMessage(s.sender, fmt.Sprintf("Re: %s", a.Subject), body, a.Email)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	resp, id, err := s.mg.Send(ctx, message)

	if err != nil {
		return errors.Wrap(err, "failed to send notification")
	} else {
		log.Infof("notification sent to=%v with response=%v and id=%v", a.Email, resp, id)
	}
	return nil
}

func (s *Mailer) SendSupportEmail(a *m.Abuse) error {
	body, err := s.render(a, supportTemplate)
	if err != nil {
		return err
	}

	message := s.mg.NewMessage(s.sender, fmt.Sprintf("[%s] %s", a.NoticeID, a.Subject), body, s.support)
	message.AddHeader("Reply-To", a.Email)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	resp, id, err := s.mg.Send(ctx, message)

	if err != nil {
		return errors.Wrap(err, "failed to send support notification")
	} else {
		log.Infof("support notification sent to=%v with response=%v and id=%v", s.support, resp, id)
	}
	return nil
}
