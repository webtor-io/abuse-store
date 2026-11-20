package services

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"sync"
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
	// mu serializes Push with Sync. Sync prunes every cached key its walk did
	// not see, so a row inserted after the walk read the table but before the
	// prune would otherwise be dropped from the cache — a fresh ban lifted for
	// a whole sync interval.
	mu sync.Mutex
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

// Sync loads the whole abuse table into the local cache, then prunes cached
// keys whose rows are gone or exempt, so deleting a row or marking it exempt
// lifts the ban at the next sync rather than at the next pod restart. A read
// that errors returns before the prune: a partial read must never look like
// deleted rows.
func (s *Store) Sync() error {
	pg := s.p.Get()
	if pg == nil {
		return errors.New("database not initialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	log.Info("DB syncing started")
	var rows []*m.Abuse
	if err := pg.Model(&rows).Select(); err != nil {
		return err
	}
	keep, synced, failed, exempt := s.load(rows)
	pruned, err := s.prune(keep)
	if err != nil {
		return errors.Wrap(err, "failed to prune cache")
	}
	l := log.WithField("synced", synced).WithField("exempt", exempt).WithField("pruned", pruned)
	if failed > 0 {
		l.WithField("failed", failed).Warn("DB syncing finished with unusable rows")
		return nil
	}
	l.Info("DB syncing finished")
	return nil
}

// load caches every row that blocks and returns the keys to keep. A row that
// cannot be cached is logged and skipped rather than aborting the sync: the
// startup Sync is fatal, so one unusable row would otherwise crash-loop the
// pod. The stoplist must degrade by one entry, not wholesale.
//
// An exempt row shadows every row for its infohash, both arms, whatever order
// the rows come in: the owner's review beats any report of the same torrent.
// The fingerprint arm of a row for a DIFFERENT infohash can still match the
// exempt torrent's payload — exemption is per infohash, not per payload.
func (s *Store) load(rows []*m.Abuse) (keep map[string]struct{}, synced, failed, exempt int) {
	ex := map[string]struct{}{}
	for _, a := range rows {
		if a.Exempt && a.Infohash != "" {
			ex[a.Infohash] = struct{}{}
		}
	}
	keep = map[string]struct{}{}
	for _, a := range rows {
		if a.Exempt {
			continue
		}
		if _, ok := ex[a.Infohash]; ok {
			continue
		}
		// Kept even when caching fails below, so an entry cached earlier for
		// this row survives the prune.
		keep[a.Infohash] = struct{}{}
		if len(a.Fingerprint) == fingerprintSize {
			keep[string(fingerprintKey(a.Fingerprint))] = struct{}{}
		}
		if s.syncRow(a) {
			synced++
		} else {
			failed++
		}
	}
	return keep, synced, failed, len(ex)
}

// IsExempt reports whether the infohash was reviewed and exempted. It asks
// Postgres, not the cache: Push is rare, and an exemption set by hand must
// hold for the very next report, not after the next sync.
func (s *Store) IsExempt(h string) (bool, error) {
	if h == "" {
		return false, nil
	}
	pg := s.p.Get()
	if pg == nil {
		return false, errors.New("database not initialized")
	}
	return pg.Model((*m.Abuse)(nil)).Where("infohash = ? AND exempt", h).Exists()
}

// prune deletes every cached key not in keep and reports how many it removed.
func (s *Store) prune(keep map[string]struct{}) (int, error) {
	var stale [][]byte
	err := s.b.View(func(txn *badger.Txn) error {
		opt := badger.DefaultIteratorOptions
		opt.PrefetchValues = false
		it := txn.NewIterator(opt)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			if _, ok := keep[string(it.Item().Key())]; !ok {
				stale = append(stale, it.Item().KeyCopy(nil))
			}
		}
		return nil
	})
	if err != nil || len(stale) == 0 {
		return 0, err
	}
	wb := s.b.NewWriteBatch()
	defer wb.Cancel()
	for _, k := range stale {
		if err := wb.Delete(k); err != nil {
			return 0, err
		}
	}
	if err := wb.Flush(); err != nil {
		return 0, err
	}
	for _, k := range stale {
		key := string(k)
		if fp, ok := bytes.CutPrefix(k, []byte("fp:")); ok {
			key = "fp:" + hex.EncodeToString(fp)
		}
		log.WithField("key", key).Info("pruned cache entry: row deleted or exempt")
	}
	return len(stale), nil
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
	s.mu.Lock()
	defer s.mu.Unlock()
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
// error: load must go on past an unusable row, and the startup Sync is fatal.
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
