package models

import (
	"time"

	uuid "github.com/satori/go.uuid"
)

type Abuse struct {
	tableName   struct{}  `pg:"public.abuse,alias:a"`
	ID          uuid.UUID `pg:"abuse_id,type:uuid,pk,default:uuid_generate_v4()"`
	NoticeID    string    `pg:"notice_id"`
	Work        string    `pg:"work"`
	Filename    string    `pg:"filename"`
	Infohash    string    `pg:"infohash"`
	Description string    `pg:"description"`
	Email       string    `pg:"email"`
	Subject     string    `pg:"subject"`
	Cause       int       `pg:"cause"`
	Source      int       `pg:"source"`
	StartedAt   time.Time `pg:"started_at"`
	// Fingerprint is the raw SHA-256 identifying the blocked payload, or nil
	// when the report is not about one (DMCA notices, questions) or predates
	// the column.
	Fingerprint []byte    `pg:"fingerprint"`
	CreatedAt   time.Time `pg:",default:now()"`
}
