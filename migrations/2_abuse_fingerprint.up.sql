-- Content fingerprint of the blocked payload.
--
-- An infohash covers the whole torrent info dict, so republishing one payload
-- under a different name yields a different infohash and walks past a
-- per-infohash block. The fingerprint identifies the payload itself, so one
-- decision covers every copy including ones uploaded later.
--
-- A column on abuse rather than a side table: exactly one fingerprint exists
-- per torrent, so a separate row per abuse would buy nothing and cost a join.
-- Living on the abuse row also makes the audit link automatic — a block is
-- always traceable to the record that caused it.
--
-- Nullable: most rows are DMCA notices and questions, where a payload
-- fingerprint is meaningless, and older rows predate this column.
ALTER TABLE abuse ADD COLUMN fingerprint bytea;

-- Raw SHA-256, not hex: half the bytes, and the length check makes a
-- malformed digest impossible to store.
ALTER TABLE abuse ADD CONSTRAINT abuse_fingerprint_len
	CHECK (fingerprint IS NULL OR length(fingerprint) = 32);

-- Lookup is always "is this payload blocked", so only the rows that carry one
-- are worth indexing.
CREATE INDEX abuse_fingerprint_idx ON abuse (fingerprint) WHERE fingerprint IS NOT NULL;
