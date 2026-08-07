-- The backfilled values are not distinguishable from values written normally,
-- so the down migration only lifts the constraints; it cannot un-backfill.
ALTER TABLE abuse ALTER COLUMN cause DROP NOT NULL;
ALTER TABLE abuse ALTER COLUMN cause DROP DEFAULT;
ALTER TABLE abuse ALTER COLUMN source DROP NOT NULL;
ALTER TABLE abuse ALTER COLUMN source DROP DEFAULT;
