-- Content fingerprints of blocked material.
--
-- An infohash covers the whole torrent info dict, so republishing the same
-- payload under a different name yields a different infohash and escapes a
-- per-infohash block. A fingerprint identifies the payload itself, so one
-- decision covers every copy, including ones uploaded later.
--
-- Always tied to an abuse row: a block must be traceable to the record that
-- caused it, otherwise a fingerprint-driven block is invisible to an audit.
CREATE TABLE abuse_fingerprint (
	abuse_id uuid  NOT NULL REFERENCES abuse (abuse_id) ON DELETE CASCADE,
	-- Raw SHA-256, not hex: half the bytes and the length check below makes a
	-- malformed value impossible to store.
	value    bytea NOT NULL,
	CONSTRAINT abuse_fingerprint_pk PRIMARY KEY (abuse_id, value),
	CONSTRAINT abuse_fingerprint_value_len CHECK (length(value) = 32)
);

-- Lookup is always "is this payload blocked", never "which payloads does this
-- record cover", so the index leads with value.
CREATE INDEX abuse_fingerprint_value_idx ON abuse_fingerprint (value);
