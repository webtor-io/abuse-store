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
	// use_zero on both: go-pg omits zero-valued fields from an INSERT, and
	// the zero values here are the common ones — ILLEGAL_CONTENT is cause 0
	// and MAIL is source 0. Without the tag they land as NULL, which is how
	// 942 of 1092 rows ended up with no cause at all: every audit query
	// filtering `cause = 0` silently missed them.
	Cause     int       `pg:"cause,use_zero"`
	Source    int       `pg:"source,use_zero"`
	StartedAt time.Time `pg:"started_at"`
	// Fingerprint is the raw SHA-256 identifying the blocked payload, or nil
	// when the report is not about one (DMCA notices, questions) or predates
	// the column.
	Fingerprint []byte    `pg:"fingerprint"`
	CreatedAt   time.Time `pg:",default:now()"`
}
