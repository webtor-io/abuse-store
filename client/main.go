package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli"
	pb "github.com/webtor-io/abuse-store/proto"
	"google.golang.org/grpc"
)

func main() {
	app := cli.NewApp()
	app.Name = "abuse-store-cli"
	app.Usage = "interacts with abuse store"
	app.Version = "0.0.1"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "host, H",
			Usage: "listening host",
			Value: "",
		},
		cli.IntFlag{
			Name:  "port, P",
			Usage: "listening port",
			Value: 50051,
		},
		cli.StringFlag{
			Name:  "info-hash, hash, ha",
			Usage: "info hash",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:    "push",
			Aliases: []string{"ps"},
			Usage:   "pushes abuse to the store",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "work, w",
					Usage: "Infringed work (required)",
				},
				cli.StringFlag{
					Name:  "filename, file, f",
					Usage: "Infringed file (empty by default)",
				},
				cli.StringFlag{
					Name:  "infohash, hash, ha",
					Usage: "Infringed torrent infohash (required)",
				},
				cli.StringFlag{
					Name:  "email, mail",
					Usage: "Rightholder notify email (empty by default)",
				},
				cli.StringFlag{
					Name:  "description, desc, d",
					Usage: "Description of DMCA abuse (empty by default)",
				},
				cli.StringFlag{
					Name:  "fingerprint, fp",
					Usage: "hex content fingerprint of the payload; ask torrent-store for it. Without it the ban covers only this infohash, not re-uploads under other names",
				},
				cli.StringFlag{
					Name:  "notice-id, id",
					Usage: "ID of DMCA abuse (uuid by default)",
				},
				cli.StringFlag{
					Name:  "started-at, st",
					Usage: "Start time of abusive activity (current time by default)",
				},
				cli.StringFlag{
					Name:  "subject, subj",
					Usage: "Subject (empty by default)",
				},
			},
			Action: func(c *cli.Context) error {
				addr := fmt.Sprintf("%s:%d", c.GlobalString("host"), c.GlobalInt("port"))
				conn, err := grpc.Dial(addr, grpc.WithInsecure())
				if err != nil {
					return err
				}
				defer conn.Close()
				cl := pb.NewAbuseStoreClient(conn)

				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				var fp []byte
				if h := strings.TrimSpace(c.String("fingerprint")); h != "" {
					d, derr := hex.DecodeString(h)
					if derr != nil {
						return fmt.Errorf("fingerprint %q is not hex: %w", h, derr)
					}
					if len(d) != sha256.Size {
						return fmt.Errorf("fingerprint %q is %d bytes, want %d", h, len(d), sha256.Size)
					}
					fp = d
				}
				_, err = cl.Push(ctx, &pb.PushRequest{
					Fingerprint: fp,
					Work:        c.String("work"),
					Filename:    c.String("filename"),
					Infohash:    c.String("infohash"),
					Email:       c.String("email"),
					Description: c.String("description"),
					NoticeId:    c.String("notice-id"),
					Source:      pb.PushRequest_FORM,
					Cause:       pb.PushRequest_ILLEGAL_CONTENT,
				})
				if err != nil {
					return err
				}
				fmt.Println("Done")

				return nil
			},
		},
		{
			Name:    "check",
			Aliases: []string{"ch"},
			Usage:   "pulls torrent from the store",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "fingerprint, fp",
					Usage: "hex content fingerprint; blocks if this payload is banned under any infohash",
				},
				cli.StringFlag{
					Name:  "infohash, hash, ha",
					Usage: "info hash of the torrent file",
				},
			},
			Action: func(c *cli.Context) error {
				addr := fmt.Sprintf("%s:%d", c.GlobalString("host"), c.GlobalInt("port"))
				conn, err := grpc.Dial(addr, grpc.WithInsecure())
				if err != nil {
					return err
				}
				defer conn.Close()
				cl := pb.NewAbuseStoreClient(conn)

				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				var checkFP []byte
				if h := strings.TrimSpace(c.String("fingerprint")); h != "" {
					d, derr := hex.DecodeString(h)
					if derr != nil || len(d) != sha256.Size {
						return fmt.Errorf("fingerprint %q must be %d hex-encoded bytes", h, sha256.Size)
					}
					checkFP = d
				}
				r, err := cl.Check(ctx, &pb.CheckRequest{
					Infohash:    c.String("infohash"),
					Fingerprint: checkFP,
				})
				if err != nil {
					return err
				}
				fmt.Println(r.Exists)

				return nil
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
