package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	s "github.com/webtor-io/abuse-store/services"

	cs "github.com/webtor-io/common-services"
)

func makeServeCMD() cli.Command {
	serveCmd := cli.Command{
		Name:    "serve",
		Aliases: []string{"s"},
		Usage:   "Serves web server",
		Action:  serve,
	}
	configureServe(&serveCmd)
	return serveCmd
}

func configureServe(c *cli.Command) {

	c.Flags = cs.RegisterProbeFlags(c.Flags)
	c.Flags = cs.RegisterPGFlags(c.Flags)
	c.Flags = s.RegisterGRPCFlags(c.Flags)
	c.Flags = s.RegisterStoreFlags(c.Flags)
	c.Flags = s.RegisterMailgunFlags(c.Flags)
	c.Flags = s.RegisterMailerFlags(c.Flags)
}

func serve(c *cli.Context) error {
	// Setting DB
	pg := cs.NewPG(c)
	defer pg.Close()

	// Setting Migrations
	m := cs.NewPGMigration(pg)
	err := m.Run()
	if err != nil {
		return err
	}

	// Setting Badger
	b := s.NewBadger(c)
	defer b.Close()

	// Setting Store
	st := s.NewStore(c, b, pg)
	err = st.Sync()
	if err != nil {
		return err
	}

	// Setting Mailgun
	mg := s.NewMaigun(c)

	// Setting Mailer
	mr := s.NewMailer(c, mg)

	// Setting Probe
	probe := cs.NewProbe(c)
	defer probe.Close()

	// Setting GRPC
	grpc := s.NewGRPC(c, st, mr)
	defer grpc.Close()

	// Setting Serve
	serve := cs.NewServe(probe, grpc, st)

	// And SERVE!
	err = serve.Serve()
	if err != nil {
		log.WithError(err).Error("got server error")
	}
	return err
}
