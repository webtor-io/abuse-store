-- Backfill the cause column and stop it going missing again.
--
-- go-pg omits zero-valued struct fields from an INSERT unless the field is
-- tagged use_zero, and this table's zero values are the common ones:
-- ILLEGAL_CONTENT is cause 0, MAIL is source 0. The column had no default, so
-- every such insert since 2022 landed as NULL — 942 of 1092 rows, including
-- every recent one. Only source, whose production value is FORM (1), survived
-- intact. The model now carries use_zero; this migration repairs the history
-- and makes a regression impossible to store silently.
--
-- Reading NULL as "lost zero" rather than "unknown" is sound here: Push has
-- persisted a row only when Cause == ILLEGAL_CONTENT since the service's
-- first commit in 2019, so every stored row is an illegal-content report by
-- construction. Non-illegal reports are emailed and never written.
UPDATE abuse SET cause = 0 WHERE cause IS NULL;

-- Same reasoning for source: a NULL can only be the omitted zero, MAIL.
-- Production currently holds no such row (all 1092 are FORM), so this is a
-- guard for older data rather than a repair.
UPDATE abuse SET source = 0 WHERE source IS NULL;

ALTER TABLE abuse ALTER COLUMN cause SET DEFAULT 0;
ALTER TABLE abuse ALTER COLUMN cause SET NOT NULL;
ALTER TABLE abuse ALTER COLUMN source SET DEFAULT 0;
ALTER TABLE abuse ALTER COLUMN source SET NOT NULL;
