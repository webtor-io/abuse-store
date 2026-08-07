package services

import (
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/pkg/errors"
)

// NewBadger opens the local stoplist cache. The open error used to be
// discarded, so a locked directory or a full disk produced a nil DB that
// booted fine and panicked on the first Check.
func NewBadger() (*badger.DB, error) {
	opt := badger.DefaultOptions("/tmp/badger")
	db, err := badger.Open(opt)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open badger db")
	}
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if err := db.RunValueLogGC(0.7); err != nil {
				return
			}
		}
	}()
	return db, nil
}
