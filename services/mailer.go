package services

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"slices"
	"strings"
	"text/template"

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
		"IsIllegal": isIllegal,
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
	smtp    *SMTP
}

// Notice is one Push as the letters tell it: the report, and what became of
// each infohash it named.
type Notice struct {
	// Abuse carries the report's fields; its Infohash is the primary one.
	Abuse  *m.Abuse
	Hashes []NoticeHash
	// PurgeNow: the data purge went out with the notice. Otherwise it is
	// scheduled for Abuse.PurgeAfter.
	PurgeNow bool
}

type NoticeHash struct {
	Infohash   string
	Exempt     bool // reviewed and exempt: not stored, never purged
	Existed    bool // already in the stoplist before this notice
	Advanced   bool // purge_now replaced a purge an earlier notice scheduled
	Overridden bool // purge_now cleared its exemption: blocked and purged
}

func (n *Notice) AnyExempt() bool {
	return slices.ContainsFunc(n.Hashes, func(h NoticeHash) bool { return h.Exempt })
}

func (n *Notice) AnyOverridden() bool {
	return slices.ContainsFunc(n.Hashes, func(h NoticeHash) bool { return h.Overridden })
}

func (n *Notice) AllExempt() bool {
	return !slices.ContainsFunc(n.Hashes, func(h NoticeHash) bool { return !h.Exempt })
}

// Added reports whether the notice put a new row in, i.e. scheduled a purge.
func (n *Notice) Added() bool {
	return slices.ContainsFunc(n.Hashes, func(h NoticeHash) bool { return !h.Exempt && !h.Existed })
}

type View struct {
	*Notice
	Support string
}

func NewMailer(c *cli.Context, smtp *SMTP) *Mailer {
	return &Mailer{
		sender:  c.String(mailSender),
		support: c.String(mailSupport),
		smtp:    smtp,
	}
}

func (s *Mailer) render(n *Notice, t *template.Template) (string, error) {
	var b bytes.Buffer
	v := &View{
		Notice:  n,
		Support: s.support,
	}
	err := t.Execute(&b, v)
	if err != nil {
		return "", errors.Wrapf(err, "failed to render template=%v with view=%v", t.Name(), v)
	}
	return b.String(), nil
}

func (s *Mailer) SendUserEmail(n *Notice) error {
	a := n.Abuse
	body, err := s.render(n, userTemplate)
	if err != nil {
		return err
	}

	err = s.smtp.Send(s.sender, a.Email, "", fmt.Sprintf("Re: %s", a.Subject), body)

	if err != nil {
		return errors.Wrap(err, "failed to send notification")
	} else {
		log.Infof("notification sent to=%v", a.Email)
	}
	return nil
}

// SendExemptEmail tells support that h was exempted through the admin port,
// so every exemption set without a hand UPDATE leaves a letter.
func (s *Mailer) SendExemptEmail(h, reason string, rows int) error {
	body := fmt.Sprintf("Exempted through the admin port: %s\nRows set exempt: %d\nReason: %s\n\n"+
		"The block is lifted and the scheduled purge will not go out. To ban it again, push it with purge_now on the admin port.\n",
		h, rows, reason)
	if err := s.smtp.Send(s.sender, s.support, "", fmt.Sprintf("[exempt] %s — %s", h, reason), body); err != nil {
		return errors.Wrap(err, "failed to send exempt notification")
	}
	log.Infof("exempt notification sent to=%v", s.support)
	return nil
}

func (s *Mailer) SendSupportEmail(n *Notice) error {
	a := n.Abuse
	body, err := s.render(n, supportTemplate)
	if err != nil {
		return err
	}

	subject := fmt.Sprintf("[%s] %s", a.NoticeID, a.Subject)
	if n.AnyExempt() {
		subject = "[exempt] " + subject
	}
	err = s.smtp.Send(s.sender, s.support, a.Email, subject, body)

	if err != nil {
		return errors.Wrap(err, "failed to send support notification")
	} else {
		log.Infof("support notification sent to=%v", s.support)
	}
	return nil
}
