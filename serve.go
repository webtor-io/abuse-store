package main

import (
	"sync"

	"github.com/dgraph-io/badger/v3"
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
	c.Flags = cs.RegisterNATSFlags(c.Flags)
	c.Flags = s.RegisterGRPCFlags(c.Flags)
	c.Flags = s.RegisterStoreFlags(c.Flags)
	c.Flags = s.RegisterSMTPFlags(c.Flags)
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
	b, err := s.NewBadger()
	if err != nil {
		return err
	}
	// Closed last, after the gRPC server has drained: handlers read this DB,
	// and closing it underneath one is what turns a rollout into a nil
	// dereference inside Badger.
	defer func(b *badger.DB) {
		_ = b.Close()
	}(b)

	// Setting NATS — before the Store: Sync fans bans out through it.
	nats := cs.NewNATS(c)
	if nats != nil {
		defer nats.Close()
	}

	// Setting Store
	st := s.NewStore(c, b, pg, nats)
	err = st.Sync()
	if err != nil {
		return err
	}

	// Setting SMTP
	smtp := s.NewSMTP(c)

	// Setting Mailer
	mr := s.NewMailer(c, smtp)

	// Setting Probe
	probe := cs.NewProbe(c)
	defer probe.Close()

	// Setting GRPC: the public listener, and the admin one on 127.0.0.1
	// unless --admin-port is 0.
	servers := []*s.GRPC{s.NewGRPC(c, st, mr)}
	if admin := s.NewAdminGRPC(c, st, mr); admin != nil {
		servers = append(servers, admin)
	}
	// Drained side by side: each waits up to its own graceful-stop timeout,
	// and one after the other would not fit the pod's grace period.
	defer func() {
		var wg sync.WaitGroup
		for _, g := range servers {
			wg.Go(g.Close)
		}
		wg.Wait()
	}()

	// Setting Serve
	servables := []cs.Servable{probe, st}
	for _, g := range servers {
		servables = append(servables, g)
	}
	serve := cs.NewServe(servables...)

	// And SERVE!
	err = serve.Serve()
	if err != nil {
		log.WithError(err).Error("got server error")
	}
	return err
}
