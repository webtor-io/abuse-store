package services

import (
	"crypto/tls"
	"fmt"
	"github.com/urfave/cli"
	"net/mail"
	"net/smtp"
)

const (
	smtpHostFlag     = "smtp-host"
	smtpPortFlag     = "smtp-port"
	smtpPassFlag     = "smtp-pass"
	smtpUserFlag     = "smtp-user"
	smtpTLSFlag      = "smtp-tls"
	smtpStartTLSFlag = "smtp-start-tls"
)

func RegisterSMTPFlags(f []cli.Flag) []cli.Flag {
	return append(f,
		cli.StringFlag{
			Name:   smtpHostFlag,
			Usage:  "smtp host",
			EnvVar: "SMTP_HOST",
		},
		cli.IntFlag{
			Name:   smtpPortFlag,
			Usage:  "smtp port",
			EnvVar: "SMTP_PORT",
		},
		cli.StringFlag{
			Name:   smtpUserFlag,
			Usage:  "smtp user",
			EnvVar: "SMTP_USER",
		},
		cli.StringFlag{
			Name:   smtpPassFlag,
			Usage:  "smtp pass",
			EnvVar: "SMTP_PASS",
		},
		cli.BoolFlag{
			Name:   smtpTLSFlag,
			Usage:  "smtp tls",
			EnvVar: "SMTP_TLS",
		},
		cli.BoolFlag{
			Name:   smtpStartTLSFlag,
			Usage:  "smtp starttls",
			EnvVar: "SMTP_STARTTLS",
		},
	)
}

type SMTP struct {
	host     string
	port     int
	user     string
	pass     string
	tls      bool
	startTLS bool
}

func (s *SMTP) Send(from string, to string, subj string, body string) error {
	fromAddr := mail.Address{"", from}
	toAddr := mail.Address{"", to}

	// Setup headers
	headers := make(map[string]string)
	headers["From"] = fromAddr.String()
	headers["To"] = toAddr.String()
	headers["Subject"] = subj

	// Setup message
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	// Connect to the SMTP Server
	servername := fmt.Sprintf("%v:%v", s.host, s.port)

	auth := smtp.PlainAuth("", s.user, s.pass, s.host)
	var c *smtp.Client
	var err error

	if s.tls {
		// TLS config
		tlsconfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         s.host,
		}

		// Here is the key, you need to call tls.Dial instead of smtp.Dial
		// for smtp servers running on 465 that require an ssl connection
		// from the very beginning (no starttls)
		conn, err := tls.Dial("tcp", servername, tlsconfig)
		if err != nil {
			return err
		}

		c, err = smtp.NewClient(conn, s.host)
		if err != nil {
			return err
		}
	} else {
		c, err = smtp.Dial(servername)
		if err != nil {
			return err
		}
		if s.startTLS {
			tlsconfig := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         s.host,
			}
			if err = c.StartTLS(tlsconfig); err != nil {
				return err
			}
		}
	}

	// Auth
	if err = c.Auth(auth); err != nil {
		return err
	}

	// To && From
	if err = c.Mail(fromAddr.Address); err != nil {
		return err
	}

	if err = c.Rcpt(toAddr.Address); err != nil {
		return err
	}

	// Data
	w, err := c.Data()
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(message))
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	c.Quit()

	return nil
}

func NewSMTP(c *cli.Context) *SMTP {
	return &SMTP{
		host:     c.String(smtpHostFlag),
		port:     c.Int(smtpPortFlag),
		user:     c.String(smtpUserFlag),
		pass:     c.String(smtpPassFlag),
		tls:      c.Bool(smtpTLSFlag),
		startTLS: c.Bool(smtpStartTLSFlag),
	}
}
