package services

import (
	"github.com/mailgun/mailgun-go/v3"
	"github.com/urfave/cli"
)

const (
	mailgunDomain  = "mailgun-domain"
	mailgunKey     = "mailgun-key"
	mailgunApiBase = "mailgun-api-base"
)

func RegisterMailgunFlags(f []cli.Flag) []cli.Flag {
	return append(f,
		cli.StringFlag{
			Name:   mailgunDomain,
			Usage:  "mailgun domain",
			Value:  "webtor.io",
			EnvVar: "MAILGUN_DOMAIN",
		},
		cli.StringFlag{
			Name:   mailgunKey,
			Usage:  "mailgun key",
			EnvVar: "MAILGUN_KEY",
		},
		cli.StringFlag{
			Name:   mailgunApiBase,
			Usage:  "mailgun api base",
			Value:  "https://api.eu.mailgun.net/v3",
			EnvVar: "MAILGUN_API_BASE",
		},
	)
}

func NewMaigun(c *cli.Context) *mailgun.MailgunImpl {
	mg := mailgun.NewMailgun(c.String(mailgunDomain), c.String(mailgunKey))
	mg.SetAPIBase(c.String(mailgunApiBase))
	return mg
}
