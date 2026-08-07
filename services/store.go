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

// Sync loads the whole abuse table into the local cache. A row that cannot be
// cached is logged and skipped rather than aborting the walk: ForEach stops at
// the first error, so one unusable row would leave every row after it
// uncached — and, because serve() treats the startup Sync as fatal, would put
// the pod in a crash loop. The stoplist must degrade by one entry, not
// wholesale.
func (s *Store) Sync() error {
	pg := s.p.Get()
	if pg == nil {
		return errors.New("database not initialized")
	}
	log.Info("DB syncing started")
	var synced, failed int
	err := pg.Model(&m.Abuse{}).ForEach(func(a *m.Abuse) error {
		if s.syncRow(a) {
			synced++
		} else {
			failed++
		}
		return nil
	})
	if err != nil {
		return err
	}
	if failed > 0 {
		log.WithField("synced", synced).WithField("failed", failed).Warn("DB syncing finished with unusable rows")
		return nil
	}
	log.WithField("synced", synced).Info("DB syncing finished")
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
func (s *Store) Check(i string, fingerprint []byte) error {
	return s.b.View(func(txn *badger.Txn) error {
		if i != "" {
			if _, err := txn.Get([]byte(i)); err == nil {
				return nil
			} else if !errors.Is(err, badger.ErrKeyNotFound) {
				return err
			}
		}
		if len(fingerprint) == fingerprintSize {
			if _, err := txn.Get(fingerprintKey(fingerprint)); err == nil {
				return nil
			} else if !errors.Is(err, badger.ErrKeyNotFound) {
				return err
			}
		}
		return ErrNotFound
	})
}

func (s *Store) Push(a *m.Abuse) error {
	if len(a.Fingerprint) != 0 && len(a.Fingerprint) != fingerprintSize {
		// Refuse rather than store: a malformed digest would sit in the index
		// matching nothing while looking like coverage.
		log.WithField("infohash", a.Infohash).WithField("len", len(a.Fingerprint)).Warn("dropping fingerprint of wrong length")
		a.Fingerprint = nil
	}
	pg := s.p.Get()
	_, err := pg.Model(a).Insert()
	if err != nil {
		return errors.Wrapf(err, "failed to push to db abuse=%+v", a)
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

// syncRow caches one row and reports whether it made it. It never returns an
// error: it is the ForEach callback's whole body, and ForEach stops the walk
// on the first error returned.
func (s *Store) syncRow(a *m.Abuse) bool {
	if err := s.pushToCache(a); err != nil {
		log.WithError(err).WithField("infohash", a.Infohash).WithField("notice_id", a.NoticeID).Error("failed to cache abuse row, skipping")
		return false
	}
	return true
}

// pushToCache mirrors one abuse row into the local cache: the payload
// fingerprint first, then the infohash entry.
//
// The fingerprint goes first deliberately. Badger refuses an empty key, so a
// row with no infohash — which the RPC now rejects, but which older rows and
// other writers can still produce — used to fail before its fingerprint was
// ever written, losing the one part of it that was usable. An empty infohash
// is now skipped with a warning instead.
func (s *Store) pushToCache(a *m.Abuse) error {
	if len(a.Fingerprint) == fingerprintSize {
		if err := s.pushFingerprintToCache(a.Fingerprint); err != nil {
			return errors.Wrap(err, "failed to cache fingerprint")
		}
	}
	if a.Infohash == "" {
		log.WithField("notice_id", a.NoticeID).Warn("abuse row has no infohash, caching fingerprint only")
		return nil
	}
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
