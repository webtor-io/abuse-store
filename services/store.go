package services

import (
	"encoding/json"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	m "github.com/webtor-io/abuse-store/models"
	cs "github.com/webtor-io/common-services"
)

const (
	storeSyncIntervalFlag = "sync-interval"
)

var (
	ErrNotFound = errors.New("store: abuse not found")
)

// fingerprintSize is the length of a SHA-256 digest. Values of any other
// length are refused rather than stored, so a malformed one cannot sit in the
// index matching nothing.
const fingerprintSize = 32

func RegisterStoreFlags(f []cli.Flag) []cli.Flag {
	return append(f,
		cli.IntFlag{
			Name:   storeSyncIntervalFlag + ", si",
			Usage:  "sync interval in minutes",
			Value:  10,
			EnvVar: "STORE_SYNC_INTERVAL",
		},
	)
}

type Store struct {
	b  *badger.DB
	p  *cs.PG
	si time.Duration
}

func NewStore(c *cli.Context, b *badger.DB, p *cs.PG) *Store {
	return &Store{
		b:  b,
		p:  p,
		si: time.Duration(c.Int(storeSyncIntervalFlag)) * time.Minute,
	}
}

func (s *Store) Sync() error {
	pg := s.p.Get()
	if pg == nil {
		return errors.New("database not initialized")
	}
	log.Info("DB syncing started")
	err := pg.Model(&m.Abuse{}).ForEach(func(a *m.Abuse) error {
		err := s.pushToCache(a)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	err = pg.Model(&m.AbuseFingerprint{}).ForEach(func(f *m.AbuseFingerprint) error {
		return s.pushFingerprintToCache(f.Value)
	})
	if err != nil {
		return err
	}
	log.Info("DB syncing finished")
	return nil
}

// fingerprintKey namespaces a raw digest so it can never collide with an
// infohash key, which is a 40-char hex string.
func fingerprintKey(v []byte) []byte {
	return append([]byte("fp:"), v...)
}

// Check reports whether the torrent is blocked, by its own infohash or by the
// fingerprint of its payload. The fingerprint arm is what catches the same
// bytes republished under a new name — a new infohash the caller has never
// been told about.
func (s *Store) Check(i string, fingerprints [][]byte) error {
	return s.b.View(func(txn *badger.Txn) error {
		if i != "" {
			if _, err := txn.Get([]byte(i)); err == nil {
				return nil
			} else if !errors.Is(err, badger.ErrKeyNotFound) {
				return err
			}
		}
		for _, fp := range fingerprints {
			if len(fp) != fingerprintSize {
				continue
			}
			if _, err := txn.Get(fingerprintKey(fp)); err == nil {
				return nil
			} else if !errors.Is(err, badger.ErrKeyNotFound) {
				return err
			}
		}
		return ErrNotFound
	})
}

func (s *Store) Push(a *m.Abuse, fingerprints [][]byte) error {
	pg := s.p.Get()
	_, err := pg.Model(a).Insert()
	if err != nil {
		return errors.Wrapf(err, "failed to push to db abuse=%+v", a)
	}
	for _, fp := range fingerprints {
		if len(fp) != fingerprintSize {
			log.WithField("infohash", a.Infohash).WithField("len", len(fp)).Warn("skipping fingerprint of wrong length")
			continue
		}
		f := &m.AbuseFingerprint{AbuseID: a.ID, Value: fp}
		if _, ferr := pg.Model(f).OnConflict("DO NOTHING").Insert(); ferr != nil {
			// Non-fatal: the abuse row is the legally meaningful record and it
			// is already stored. A missing fingerprint costs coverage of
			// re-uploads, not the block itself.
			log.WithField("infohash", a.Infohash).WithError(ferr).Warn("failed to store fingerprint")
			continue
		}
		if cerr := s.pushFingerprintToCache(fp); cerr != nil {
			log.WithField("infohash", a.Infohash).WithError(cerr).Warn("failed to cache fingerprint")
		}
	}
	err = s.pushToCache(a)
	if err != nil {
		return errors.Wrapf(err, "failed to push to cache abuse=%+v", a)
	}
	return nil
}

// pushToCacheRaw writes an arbitrary cache entry. Split out of pushToCache so
// the blocking logic can be exercised without constructing a full abuse row.
func (s *Store) pushToCacheRaw(key string, val []byte) error {
	return s.b.Update(func(txn *badger.Txn) error {
		return txn.SetEntry(badger.NewEntry([]byte(key), val))
	})
}

func (s *Store) pushFingerprintToCache(v []byte) error {
	return s.b.Update(func(txn *badger.Txn) error {
		return txn.SetEntry(badger.NewEntry(fingerprintKey(v), []byte{1}))
	})
}

func (s *Store) pushToCache(a *m.Abuse) error {
	aa, err := json.Marshal(a)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal data abuse=%v", a)
	}
	return s.b.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(a.Infohash), aa)
		return txn.SetEntry(e)
	})
}

func (s *Store) Serve() error {
	ticker := time.NewTicker(s.si)
	for range ticker.C {
		err := s.Sync()
		if err != nil {
			log.WithError(err).Error("failed to sync db")
		}
	}
	return nil
}
