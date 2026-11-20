-- Which infohashes have been fanned out as resource.banned.
--
-- Push publishes when a report lands, but a ban can also start blocking
-- without one: an exemption lifted (exempt flipped back to false), a row
-- inserted by hand. Sync publishes every blocking infohash missing here and
-- drops the ones that no longer block, so a ban that comes back is fanned out
-- again. A failed publish is not recorded and is retried on the next sync.
CREATE TABLE banned_published (
	infohash     text PRIMARY KEY,
	published_at timestamptz NOT NULL DEFAULT now()
);

-- Seed with everything that blocks today, so the first sync does not
-- re-publish the whole stoplist. Rows reported through Push were fanned out
-- then; older ones predate the fan-out, and purging them all at once now is
-- not wanted. The predicate mirrors Store.load: an exempt row shadows every
-- row for its infohash.
INSERT INTO banned_published (infohash)
SELECT DISTINCT a.infohash FROM abuse a
WHERE a.infohash IS NOT NULL AND a.infohash <> '' AND NOT a.exempt
	AND NOT EXISTS (SELECT 1 FROM abuse e WHERE e.exempt AND e.infohash = a.infohash);
