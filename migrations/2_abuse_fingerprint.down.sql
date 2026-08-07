DROP INDEX IF EXISTS abuse_fingerprint_idx;
ALTER TABLE abuse DROP CONSTRAINT IF EXISTS abuse_fingerprint_len;
ALTER TABLE abuse DROP COLUMN IF EXISTS fingerprint;
