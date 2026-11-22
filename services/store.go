package services

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/go-pg/pg/v10"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	m "github.com/webtor-io/abuse-store/models"
	cs "github.com/webtor-io/common-services"
)

const (
	storeSyncIntervalFlag = "sync-interval"
	purgeDelayFlag        = "purge-delay"
)

var (
	ErrNotFound = errors.New("store: abuse not found")
	// ErrPurgeDue is Exempt refusing an infohash outside its review window.
	ErrPurgeDue = errors.New("store: purge due, not in the review window")
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
		cli.DurationFlag{
			Name:   purgeDelayFlag,
			Usage:  "how long a ban blocks before its data is purged (resource.banned), so a report can be set exempt or deleted first; 0 purges at Push",
			Value:  72 * time.Hour,
			EnvVar: "PURGE_DELAY",
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
	n  *cs.NATS
	si time.Duration
	// pd is the purge delay; <= 0 publishes resource.banned at Push.
	pd time.Duration
}

// NewStore takes NATS for the resource.banned fan-out; nil disables it.
func NewStore(c *cli.Context, b *badger.DB, p *cs.PG, n *cs.NATS) *Store {
	return &Store{
		b:  b,
		p:  p,
		n:  n,
		si: time.Duration(c.Int(storeSyncIntervalFlag)) * time.Minute,
		pd: c.Duration(purgeDelayFlag),
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
	// The fan-out is housekeeping: its failure is logged and retried next
	// sync, never allowed to fail Sync — the startup Sync is fatal, and the
	// stoplist itself is already in place.
	published, cleared, err := s.fanOut(blockingInfohashes(keep), dueInfohashes(rows, time.Now()))
	if err != nil {
		log.WithError(err).Error("failed to fan out bans")
	}
	l := log.WithField("synced", synced).WithField("exempt", exempt).WithField("pruned", pruned).
		WithField("published", published).WithField("unpublished", cleared)
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

// dueInfohashes returns the infohashes whose data purge is due: at least one
// row has no purge_after (rows from before the delay) or one that has passed.
// Any row, not every row: the first notice whose window ran out without a
// review is the binding one, and a later row for the same hash — Push does
// not insert one, but a race between replicas or a hand insert can — must not
// postpone a purge that is already due. Exempt rows need no test here: fanOut
// publishes only what also blocks, and an exempt row unblocks its infohash.
func dueInfohashes(rows []*m.Abuse, now time.Time) map[string]struct{} {
	d := map[string]struct{}{}
	for _, a := range rows {
		if !a.PurgeAfter.After(now) {
			d[a.Infohash] = struct{}{}
		}
	}
	return d
}

// blockingInfohashes picks the infohash keys out of a load's keep set: what
// blocks by infohash right now, and so what web-ui and vault must have purged.
func blockingInfohashes(keep map[string]struct{}) map[string]struct{} {
	b := map[string]struct{}{}
	for k := range keep {
		if k != "" && !strings.HasPrefix(k, "fp:") {
			b[k] = struct{}{}
		}
	}
	return b
}

const resourceBannedSubject = "resource.banned"

// PublishBanned fans a ban out as resource.banned and records it, so Sync
// does not publish it again. Best effort: a failure is logged, and since
// nothing is recorded, Sync retries it on its next pass.
func (s *Store) PublishBanned(h string) {
	if !s.publish(h) {
		return
	}
	pg := s.p.Get()
	if pg == nil {
		return
	}
	if _, err := pg.Exec(`INSERT INTO banned_published (infohash) VALUES (?)
		ON CONFLICT (infohash) DO UPDATE SET published_at = now()`, h); err != nil {
		log.WithError(err).WithField("infohash", h).Error("failed to record resource.banned publish")
	}
}

// fanOut publishes resource.banned for every infohash that blocks and is due
// but was never published, and forgets every recorded one that no longer
// blocks, so a ban that comes back — an exemption lifted, a deleted row
// re-added, a row inserted by hand — reaches web-ui and vault like a fresh
// report. One still inside its purge delay is left for a later sync; if it is
// set exempt or deleted meanwhile it stops blocking and is never published.
// Without NATS nothing is published or recorded.
func (s *Store) fanOut(blocking, due map[string]struct{}) (published, cleared int, err error) {
	if s.n == nil {
		return 0, 0, nil
	}
	pg := s.p.Get()
	if pg == nil {
		return 0, 0, errors.New("database not initialized")
	}
	var done []string
	if _, err := pg.Query(&done, `SELECT infohash FROM banned_published`); err != nil {
		return 0, 0, errors.Wrap(err, "failed to list published bans")
	}
	recorded := make(map[string]struct{}, len(done))
	for _, h := range done {
		recorded[h] = struct{}{}
		if _, ok := blocking[h]; ok {
			continue
		}
		if _, err := pg.Exec(`DELETE FROM banned_published WHERE infohash = ?`, h); err != nil {
			return published, cleared, errors.Wrap(err, "failed to forget unblocked ban")
		}
		cleared++
	}
	for h := range blocking {
		if _, ok := recorded[h]; ok {
			continue
		}
		if _, ok := due[h]; !ok {
			continue
		}
		if !s.publish(h) {
			continue
		}
		if _, err := pg.Exec(`INSERT INTO banned_published (infohash) VALUES (?) ON CONFLICT DO NOTHING`, h); err != nil {
			return published, cleared, errors.Wrap(err, "failed to record published ban")
		}
		published++
	}
	return published, cleared, nil
}

// publish sends resource.banned and reports whether it went out.
func (s *Store) publish(h string) bool {
	if s.n == nil || h == "" {
		return false
	}
	nc := s.n.Get()
	if nc == nil {
		log.WithField("infohash", h).Error("failed to get nats connection, skipping resource.banned publish")
		return false
	}
	body, err := json.Marshal(struct {
		Infohash string `json:"infohash"`
	}{Infohash: h})
	if err != nil {
		log.WithError(err).WithField("infohash", h).Error("failed to marshal resource.banned payload")
		return false
	}
	if err := nc.Publish(resourceBannedSubject, body); err != nil {
		log.WithError(err).WithField("infohash", h).Error("failed to publish resource.banned")
		return false
	}
	log.WithField("infohash", h).Info("published resource.banned")
	return true
}

// Exempt sets exempt on the rows of h it read and lifts its block at once, but
// only while the ban is in its review window: h has rows, and every non-exempt
// one has a purge_after still ahead. An immediate purge (purge_now: the
// agents' bans), a row from before the delay (NULL) or a purge already due is
// ErrPurgeDue, left to a hand UPDATE in Postgres; no rows is ErrNotFound.
// Returns the rows changed, 0 when h was already exempt. ctx bounds the
// transaction, so a caller that gave up is not exempted later, when a row
// lock it waited on is released.
//
// It takes mu like Push and Sync, but only after the commit, for the cache
// reload: a Sync that read the table before the commit holds mu until its
// prune is done, so the reload runs after it on a fresh read and the stale
// rows cannot put h back. Waiting on a row lock while holding mu would stall
// every Push and Sync on the replica until that lock is released.
func (s *Store) Exempt(ctx context.Context, h string) (int, error) {
	db := s.p.Get()
	if db == nil {
		return 0, errors.New("database not initialized")
	}
	tx, err := db.BeginContext(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Close() }()
	// FOR UPDATE: an immediate ban of h (Push, maybe on another replica)
	// either commits first, and the rows it made due are refused below, or
	// waits for this commit and then clears the exemption.
	var rows []*m.Abuse
	if err := tx.Model(&rows).Where("infohash = ?", h).For("UPDATE").Select(); err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, ErrNotFound
	}
	// The same clock and rule as dueInfohashes, so what Sync would publish
	// is exactly what is refused.
	now := time.Now()
	ids := make([]string, 0, len(rows))
	for _, a := range rows {
		if !a.Exempt && !a.PurgeAfter.After(now) {
			return 0, ErrPurgeDue
		}
		ids = append(ids, a.ID.String())
	}
	// Only the rows checked above: one inserted since the read is not locked
	// and was never checked.
	r, err := tx.Exec(`UPDATE abuse SET exempt = true WHERE abuse_id IN (?) AND NOT exempt`, pg.In(ids))
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// The cache half of Sync on a fresh read, also when nothing changed, so a
	// retry repairs a failed one. Deleting only h's key would leave the
	// fingerprint of its row blocking the payload until the next sync.
	var all []*m.Abuse
	if err := db.Model(&all).Select(); err != nil {
		return r.RowsAffected(), errors.Wrap(err, "exempted, but failed to reload the cache")
	}
	keep, _, _, _ := s.load(all)
	if _, err := s.prune(keep); err != nil {
		return r.RowsAffected(), errors.Wrap(err, "exempted, but failed to prune the cache")
	}
	return r.RowsAffected(), nil
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

// Push stores one infohash of a notice and reports what became of it. It
// holds mu throughout, so Sync's prune and Exempt's cache reload come before
// or after it, never in the middle, and one transaction makes the decision
// and the write.
//
// An ordinary report of an exempt infohash is absorbed (Exempt, nothing
// stored); one of an infohash already blocked gets no new row (Existed).
//
// An override (purge_now on the admin port: the owner's or the agents' ban)
// beats every exemption, set by hand or with Exempt: in the same transaction
// it clears exempt on the infohash's rows (Overridden), brings any pending
// purge forward (Advanced) and stores the row, and the caller publishes. The
// rows are read FOR UPDATE, so an Exempt racing it either commits first and
// is cleared here, or waits and then finds the ban due and refuses.
//
// ponytail: an override waits for a row lock held elsewhere (an open hand
// UPDATE in psql) while holding mu, stalling Push and Sync on the replica
// until the lock goes or ctx ends; take the row locks before mu if that bites.
func (s *Store) Push(ctx context.Context, a *m.Abuse, override bool) (NoticeHash, error) {
	nh := NoticeHash{Infohash: a.Infohash}
	if len(a.Fingerprint) != 0 && len(a.Fingerprint) != fingerprintSize {
		// Refuse rather than store: a malformed digest would sit in the index
		// matching nothing while looking like coverage.
		log.WithField("infohash", a.Infohash).WithField("len", len(a.Fingerprint)).Warn("dropping fingerprint of wrong length")
		a.Fingerprint = nil
	}
	db := s.p.Get()
	if db == nil {
		return nh, errors.New("database not initialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := db.BeginContext(ctx)
	if err != nil {
		return nh, err
	}
	defer func() { _ = tx.Close() }()
	// Postgres, not the cache: an exemption set by hand must hold for the very
	// next report, not after the next sync.
	var rows []*m.Abuse
	if a.Infohash != "" {
		q := tx.Model(&rows).Where("infohash = ?", a.Infohash)
		if override {
			q = q.For("UPDATE")
		}
		if err := q.Select(); err != nil {
			return nh, errors.Wrap(err, "failed to read the infohash's rows")
		}
	}
	now := time.Now()
	exempt := false
	for _, r := range rows {
		exempt = exempt || r.Exempt
		nh.Advanced = nh.Advanced || override && !r.Exempt && r.PurgeAfter.After(now)
	}
	if exempt && !override {
		nh.Exempt = true
		return nh, nil
	}
	nh.Overridden = exempt
	// Deduplicate on the REPORT, not on the payload: no fingerprint here. A
	// newly reported infohash whose payload is already blocked still gets its
	// own row, or the audit trail loses the fact that it was reported at all.
	// An exempt one was not blocked, whatever the cache still says.
	if err := s.Check(a.Infohash, nil); err == nil {
		nh.Existed = !exempt
	} else if !errors.Is(err, ErrNotFound) {
		return nh, err
	}
	if nh.Overridden || nh.Advanced {
		if _, err := tx.Exec(`UPDATE abuse SET exempt = false, purge_after = ? WHERE infohash = ? AND (exempt OR purge_after > ?)`,
			now, a.Infohash, now); err != nil {
			return nh, errors.Wrap(err, "failed to override the exemption")
		}
	}
	if !nh.Existed {
		if _, err := tx.Model(a).Insert(); err != nil {
			return nh, errors.Wrapf(err, "failed to push to db abuse=%+v", a)
		}
		rows = append(rows, a)
	}
	if err := tx.Commit(); err != nil {
		return nh, errors.Wrap(err, "failed to commit")
	}
	// Every row of the infohash now blocks, the fingerprints of rows an
	// override set blocking again included.
	for _, r := range rows {
		r.Exempt = false
		if err := s.pushToCache(r); err != nil {
			return nh, errors.Wrapf(err, "failed to push to cache abuse=%+v", r)
		}
	}
	return nh, nil
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
