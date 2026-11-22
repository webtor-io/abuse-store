-- Form notices waiting for the reporter to confirm them by email
-- (--form-confirm), and who stood behind each stored notice.
--
-- A table of its own, never rows of abuse: every reader of abuse (Sync's
-- load and fan-out, Check through the cache, Exempt, Push's own dedup, the
-- review queries run by hand or by the agents) takes a row there as a ban.
-- An unconfirmed notice must block nothing, and keeping it out of abuse means
-- none of them has to learn a new filter. Confirm replays the stored notice
-- through Push's path, which writes the abuse rows then.
--
-- token_hash is sha256 of the 32 random bytes mailed in the link, so the
-- table alone confirms nothing. confirmed_at marks a used token; the row stays
-- until expires_at so a repeat is told apart from an unknown token, and Sync
-- drops every row past expires_at.
CREATE TABLE unconfirmed_notice (
	id           uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
	token_hash   bytea NOT NULL UNIQUE,
	-- Push's normalized notice and its infohashes, as Confirm replays them.
	notice       jsonb NOT NULL,
	email        text NOT NULL,
	created_at   timestamptz NOT NULL DEFAULT now(),
	expires_at   timestamptz NOT NULL,
	confirmed_at timestamptz
);

-- The reporter's name and the two statements of a takedown notice (the use
-- is not authorized; they own the work or act for its owner), for audit.
-- Rows from before them, and causes that carry none, read empty and false.
ALTER TABLE abuse ADD COLUMN reporter_name text;
ALTER TABLE abuse ADD COLUMN good_faith boolean NOT NULL DEFAULT false;
ALTER TABLE abuse ADD COLUMN authorized boolean NOT NULL DEFAULT false;
