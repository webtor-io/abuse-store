package models

import (
	uuid "github.com/satori/go.uuid"
)

// AbuseFingerprint ties a content fingerprint to the abuse record that caused
// the block. Value is a raw SHA-256 digest (32 bytes), not hex.
type AbuseFingerprint struct {
	tableName struct{}  `pg:"public.abuse_fingerprint,alias:af"`
	AbuseID   uuid.UUID `pg:"abuse_id,type:uuid,pk"`
	Value     []byte    `pg:"value,pk"`
}
