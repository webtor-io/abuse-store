# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Service role

`abuse-store` is the DMCA / abuse-notice sink for the Webtor platform. It does three distinct jobs that share one gRPC surface:

1. **Stoplist** for torrents reported as illegal content. Other components (web-ui, torrent-http-proxy) call `Check(infohash)` before serving content; a positive answer blocks playback.
2. **Mail relay** for every kind of incoming notice (illegal content, malware, app error, generic question), forwarding to support and acknowledging the reporter.
3. **Cleanup fan-out** via NATS: once a `Cause = ILLEGAL_CONTENT` ban's purge delay (`--purge-delay`, default 72h) has passed, it publishes `resource.banned` so downstream services (web-ui, vault) purge their data for that infohash. The block is immediate; only the irreversible purge waits.

Only notices whose cause bans (`bans()` in `services/grpc.go`: `ILLEGAL_CONTENT`, and `INTIMATE_IMAGE` exactly like it) are persisted in the stoplist or fan out via NATS. Other causes (`MALWARE`, `APP_ERROR`, `QUESTION`) are passed through to email only, and `CSAM_REPORT` goes to support only (subject prefixed `[CSAM report]`, no reporter letter), whatever the port, source or flag: CSAM bans go through the admin port as `ILLEGAL_CONTENT` with `purge_now`. Don't add `store.Push` calls for other causes without understanding this split; a new cause that bans goes into `bans()`, which the letters read too. With `--form-confirm`, a banning notice from the form on the public port is held in `unconfirmed_notice` until its reporter confirms it by email (see below).

## Build & run

```bash
go build ./...                 # binary `abuse-store` (server) + `client/` CLI
go vet ./...
go run . serve [flags...]      # run the server locally
go run ./client push --hash ... --work ... --email ...   # smoke-test the gRPC API
make protoc                    # regenerate proto/abuse-store.pb.go + _grpc.pb.go
```

Migrations are **not** a separate command — `serve` runs `cs.NewPGMigration(pg).Run()` at startup, so a new file under `migrations/` applies itself on the next deploy. A migration that fails takes the pod down with it, so dry-run new ones against the target database in a rolled-back transaction first.

⚠️ Migration 1 ends with `ALTER TABLE abuse OWNER TO abusestore;`, and **that role does not exist on the current database** — it last ran in 2022 on the old self-hosted cluster, and the table is owned by the connecting user now. Do not copy that line into a new migration; it would fail at pod start.

Tests cover the `Check` blocking decision, the sync load/prune (deletions and exempt rows), the purge-due rule, the letters, the two listeners (public `Exempt` is Unimplemented, the admin one binds `127.0.0.1`, `--admin-port 0` turns it off) and the mail headers (a CR LF subject cannot add a header; Push drops CR and LF from `subject` and `notice_id`) (`services/*_test.go`), against an in-memory Badger with no Postgres. `services/push_pg_test.go` drives `Push` and `Sync` against a real Postgres and NATS (delayed and immediate purge, `purge_now` ignored on the public port, delay 0 not overriding an exemption, review inside the window, several hashes per notice); it is skipped unless `ABUSE_STORE_TEST_PG` and `ABUSE_STORE_TEST_NATS` are set — the file header has the two `docker run` lines. It wipes the database, so the name must end in `_test`. `services/exempt_pg_test.go` drives `Exempt` and the override the same way: each refused case, the block lifted on both arms without a Sync and never purged, the letter to support, a purge brought forward concurrently, the store lock, a row-lock wait that stalls no Push or Sync and ends at the caller's deadline, a row inserted while Exempt waits left alone, an immediate ban overriding an exemption set either way (every arm blocks, the exempted row's fingerprint included), one racing an Exempt that waits on a row lock, and the override's clearing and insert failing together. `services/confirm_test.go` covers `--form-confirm` the same way (held notice blocks and stores nothing, one confirmation letter with no caller text in it, CR LF and HTML included; the required fields; confirm, repeat and racing confirms on both ports applying once; expired, unknown, Sync's drop; the per-address, daily and racing rate limits; MAIL source, flag off and the admin port not held; `INTIMATE_IMAGE` banning once confirmed; `CSAM_REPORT` never banning; a failed letter freeing its slot; a failed ban leaving the token usable). `client/main_test.go` checks the push, exempt and confirm flags reach the request.

The `Dockerfile` produces a static linux binary, copies `migrations/` into `/migrations`, and exposes `8081` (probes) + `50051` (public gRPC). The admin gRPC port (`50052`) binds `127.0.0.1` inside the pod and is deliberately not exposed: no `EXPOSE`, no `containerPort`, no Service port. HTTP serving is *not* exposed (the service has no HTTP handlers).

## Architecture

### Two-tier storage, async sync

The store has a non-obvious dual layout:

- **PostgreSQL** (`models.Abuse` via `go-pg`) — source of truth, persistent.
- **BadgerDB** at `/tmp/badger` — keyed by infohash, in-memory hot cache used only by the `Check` RPC.

Lifecycle (see `services/store.go`):
- On startup, `Store.Sync()` iterates **the whole `abuse` table** and pushes every row into Badger. This is intentional — the entire stoplist is loaded on boot so `Check` is O(1) on a local KV with no PG hop.
- `Push` writes to PG first, in one transaction under the store mutex, then mirrors into Badger (`pushToCache`).
- `Store.Serve()` re-runs `Sync()` every `STORE_SYNC_INTERVAL` minutes (default 10) to pick up rows inserted by other replicas and to prune keys whose rows were deleted (deleting a row lifts the ban within one interval). Push and Sync share a mutex so the prune cannot drop a row inserted mid-walk. **This is the only cross-replica consistency mechanism** — there is no pub/sub.
- Badger lives on the pod's local filesystem at `/tmp/badger`; it is treated as ephemeral cache and rebuilt from PG on every restart.
- **Exempt rows** (`abuse.exempt`, migration 4) record a reviewed infohash that must not block. `Store.load` drops every row for an exempt infohash, both arms, regardless of row order. Exemption is per infohash: another row whose fingerprint matches the same payload still blocks it via torrent-store's fingerprint-only `Check`. Exemptions are owner decisions, never automatic: set with `Exempt` on the admin port while the ban is in its review window, otherwise by hand: `UPDATE abuse SET exempt = true WHERE infohash = '<hash>'` (or `INSERT INTO abuse (infohash, exempt, description) VALUES (...)` if the row is gone). An ordinary report of an exempt infohash is absorbed; **an immediate ban (`purge_now` on the admin port) beats any exemption**, set by hand or with `Exempt`, and clears it. There is one flag: who set it does not matter.

Implication: if you add a write path, write to PG first and let `pushToCache` mirror it. Do not add Badger-only writes — other replicas will not see them until the next sync tick.

### gRPC entry point: two listeners

`services/grpc.go` implements `pb.AbuseStoreServer` once (`GRPC`, with an `admin` bool) and `serve.go` runs it on two `grpc.Server`s:

| Listener | Bind | Serves | Used by |
|---|---|---|---|
| public, `--grpc-port` (50051) | `--grpc-host` (all interfaces); the Kubernetes Service points here | `Push` (`purge_now` ignored, logged at warn; with `--form-confirm`, form notices that ban are held), `Check`, `Confirm`; `Exempt` answers `Unimplemented` | web-ui (DMCA form, `Check` on playback, `Confirm` from its confirmation page), torrent-http-proxy (`Check`), the automated intake of forwarded abuse reports |
| admin, `--admin-port` / `ADMIN_GRPC_PORT` (50052; 0 disables it) | `127.0.0.1` only, no Service port, no `containerPort` | `Push` with `purge_now` honoured (never held), `Check`, `Exempt`, `Confirm` | the agent's CSAM ban script and owner decisions, through `kubectl port-forward deploy/abuse-store <local>:50052` |

The admin port's only access control is reaching the pod's loopback: `kubectl port-forward` or `exec` rights in the namespace. Both decisions it carries override an earlier one (an immediate ban beats an exemption, an exemption lifts a ban), which is why neither is on the public port. A server with `--purge-delay 0` purges every report at once, but only `purge_now` on the admin port overrides an exemption.

- `Push` takes the primary `infohash` plus any `extra_infohashes` of the same notice, validates each (anchored `^[0-9a-f]{40}$` after trim + lowercase; the primary may be empty for a fingerprint-only ban, an extra may not), drops repeats, validates `email`, drops CR and LF from `subject` and `notice_id` (both go into a mail header), fills defaults (`notice_id` → uuid, `subject` → `Abuse notice <id>`, `started_at` → now), and:
  - For `ILLEGAL_CONTENT`, per hash, `Store.Push` decides and writes in one transaction under the store mutex, reading the hash's rows from Postgres (not the cache, so a hand exemption holds for the very next report). An ordinary report of an **exempt** hash gets no row and no `resource.banned`; one already blocked (the cache has it, and it is not exempt) gets no new row; every other gets its own row under the same `notice_id` (the fingerprint goes on the primary's row only), with `purge_after` = now + `--purge-delay`, or now for an immediate purge.
  - **An override** (`purge_now` on the admin port) reads the rows `FOR UPDATE`, then in the same transaction clears `exempt` on them, brings every pending `purge_after` forward to now and inserts its row, and caches every row of the hash (so the exempted row's fingerprint blocks again at once). A failure of any part is the RPC's error and rolls back the rest. An `Exempt` racing it either commits first and is cleared, or waits and then finds the ban due and refuses.
  - `resource.banned` goes out at Push only for an immediate purge (override, or a server with `--purge-delay 0`), after the commit, for every non-exempt hash including already-blocked ones. Otherwise Sync publishes once due. **A duplicate report without an immediate purge publishes nothing**: it must not purge a delayed ban early, and a dropped publish is retried by Sync anyway.
  - Returns `AlreadyExists` only when every hash was already blocked and no pending purge was brought forward, and then sends no mail. An override that brought one forward or cleared an exemption succeeds and mails support, the hash marked as replacing its schedule or as overriding its exemption ("an exemption was overridden by an immediate ban"). Exempt hashes are mailed as before: support subject gets `[exempt]` and the hash is marked; the reporter is told it is "under moderation", never "added to stoplist", and the RPC succeeds. Callers cannot tell it apart: a ban script sees only that the post-push `Check` stays false.
  - For other causes: skips persistence and NATS entirely.
  - Mails once per notice, whatever the number of hashes: `SendUserEmail` (only if reporter supplied an email) and `SendSupportEmail` in goroutines — failures are logged, not returned. Mail delivery is best-effort and not part of the RPC's success contract.
- `Check` reads only Badger.
- `Confirm` applies a held form notice (next section); on both listeners, since the token is the credential.
- `Exempt` (`Store.Exempt`, admin port only) sets `exempt` on exactly the rows it read (`WHERE abuse_id IN (<checked ids>) AND NOT exempt`) of a validated infohash, only inside the review window: rows exist and every non-exempt one has `purge_after` ahead, by the same clock and rule as `dueInfohashes`. Otherwise `FailedPrecondition` (`purge_now`, `purge_after` NULL or passed); no rows `NotFound`; already exempt is OK with `rows = 0`. Bans outside the window (the agents' CSAM bans are `purge_now`; one whose purge already went out) take a hand UPDATE with database credentials; do not widen the guard. The rows are read `FOR UPDATE` in a transaction under the RPC's context, so a caller that gave up while it waited on a row lock is not exempted later. It takes `Store.mu` only after the commit, for the cache reload (Sync's load + prune on a fresh read, no fan-out): a Sync that read the table before the commit holds the lock until its prune is done, and a row lock held elsewhere never stalls Push or Sync behind it. The reload drops the row's fingerprint key too unless another blocking row holds it; other replicas lift it at their next sync. Each exemption that changed rows mails support `[exempt] <hash> — <reason>`, so every unban through the RPC is audited.

### Form notices confirmed by email (`--form-confirm`)

`--form-confirm` / `FORM_CONFIRM` (default false; off, everything behaves as before it existed, so web-ui can deploy before or after) holds a `Push` on the **public** listener with `source = FORM` and a cause that bans until the reporter confirms it. `source = MAIL` (the automated intake) and the admin port are never held: only `NewGRPC` reads the flag.

1. **Push** validates as always, then requires `email` (both causes) and, for `ILLEGAL_CONTENT`, a non-blank `reporter_name`, `good_faith` and `authorized` (`InvalidArgument`). A notice whose every infohash already blocks (the cache, as `Store.Push` dedups) is `AlreadyExists` and mails no one, as without the flag. The notice id is rewritten as a canonical uuid, or replaced by a new one, since it goes into the letter's subject. `Store.AddUnconfirmed` stores the normalized notice and its infohashes as `jsonb` in `unconfirmed_notice` (migration 7) under `token_hash` = sha256 of 32 random bytes, `expires_at` = now + 72h by the database's clock. Then **one** letter goes to the reporter, **synchronously** (unlike every other letter here, since without it the notice can never be confirmed): subject `Confirm your report <notice id>`, a fixed English body with the link, the number of torrents, their validated infohashes and the expiry. No caller-typed text (subject, description, work, file name, name) ever goes into it. No support letter, no "added to stoplist" letter. Reply: `confirmation_sent = true`. A letter that fails is `Unavailable`, and its row is deleted so it does not hold a slot.
2. **Rate limits**, counted over `created_at` in the last 24 hours: at most 3 held notices per address (case-insensitive) and 200 in all, else `ResourceExhausted`. The count and the insert run under `LOCK TABLE unconfirmed_notice IN SHARE ROW EXCLUSIVE MODE`, so racing pushes on any replica cannot all take the last slot. They bound the mail the public form can make this service send to a stranger.
3. **The link** is `<--confirm-url>?t=<base64url token>` (`CONFIRM_URL`, default `https://webtor.io/support/confirm`). web-ui's `GET /support/confirm` only shows a page with a button; its `POST` calls `Confirm`. **The page must not confirm on GET**: mail scanners, link previewers and prefetchers open every link in a letter, and a confirming GET would confirm every notice without the reporter.
4. **Confirm** (`Store.Confirm`) claims the notice with one `UPDATE ... SET confirmed_at = now() WHERE token_hash = ? AND confirmed_at IS NULL AND expires_at > now() RETURNING notice`, so of Confirms racing on a token exactly one applies it, then replays it through `ban` (the ordinary path: rows, `purge_after` = now + `--purge-delay`, never `purge_now`) and mails support (name, both statements, the address marked confirmed) and the reporter as usual. `CONFIRMED` with the number of infohashes. No transaction is held across the ban: it needs connections of its own, and Confirms waiting on a held row would each hold one of the pool's 5. A ban that fails releases the claim, so the reporter can retry; a notice whose every hash got blocked meanwhile is `CONFIRMED` with no letters (as a repeat `Push` is `AlreadyExists` and silent). A used token is `ALREADY_CONFIRMED`; an unused one past `expires_at` is `EXPIRED`; an unknown or malformed one `UNKNOWN`.
5. **Sync** deletes every `unconfirmed_notice` row past `expires_at`, confirmed or not (a failure is logged). A used token answers `ALREADY_CONFIRMED` until then; afterwards every expired token reads `UNKNOWN`, so `EXPIRED` is seen only until the next sync — web-ui should word `UNKNOWN` as "invalid or expired".

**Why a separate table, not rows of `abuse`:** everything that reads `abuse` treats a row as a ban — Sync's load and fan-out, `Check` through the cache, `Exempt`, `Push`'s own dedup, the review queries run by hand or by the agents. A held notice must block nothing, and in its own table none of them has to learn a new filter.

Every `abuse` row also carries `reporter_name`, `good_faith` and `authorized` (migration 7; empty and false on older rows) for audit, whatever the flag.

### Known gaps

Stated plainly; none is closed by this service:

- **The public `Push` is unauthenticated.** Anything that reaches the Service can ban any infohash. The block is immediate; the purge waits out `--purge-delay`, so a reviewer can still exempt it inside the window. `--form-confirm` holds only what says `source = FORM`; `source` is the caller's word, so a caller that reaches the Service directly bans unconfirmed by sending `MAIL`. It guards the web form, which web-ui always sends as `FORM`.
- **Reporter mail goes to any address.** `email` is only syntax-checked, so a caller can have the service send its acknowledgement, quoting a description of the caller's choosing, to any address. With `--form-confirm`, a held form notice gets only the fixed confirmation letter, at most 3 per address and 200 a day; the other causes still quote. The per-address limit counts the address as typed (lower-cased): `+tags` and provider aliases count apart, and only the daily 200 bounds them.
- **Multi-replica races.** The store mutex is per process. `Exempt` lifts the block at once only on the replica that served it (others at their next sync), and two replicas pushing the same new hash can both insert a row. An exemption **inserted** by hand (a new row) while an override is in flight is not among the rows it locked: the ban is stored and purged and the hash ends exempt.
- **An override waits under the store mutex.** If another transaction holds a row lock on the hash (an open hand UPDATE in psql), the immediate ban waits for it, and Push and Sync on that replica wait behind it, until the lock goes or the caller's deadline ends the wait.

### NATS fan-out (`resource.banned`)

`Store.PublishBanned` / `Store.publish` in `services/store.go` publish `{"infohash":"..."}` to subject `resource.banned` (JetStream stream `common`, declared in the platform's helmfile streams values with subject filter `resource.*`). Consumers purge irreversibly.

Non-obvious choices:

- **The purge waits; the block does not.** `abuse.purge_after` (migration 6) is when the purge may go out; NULL means due, so rows from before the column behave as they always did. Setting `exempt` or deleting the row before then cancels the automatic purge: the infohash stops blocking and is never published. It does not guard the data against web-ui's manual metadata-only enrich backfill, which purges any stoplisted hash on its own.
- **Best-effort, not RPC-blocking.** Marshal/connect/publish errors are logged but never fail the RPC — mirrors the mailer's behaviour. `Store.PublishBanned` records a successful publish in `banned_published` (migration 5); a failed one is not recorded.
- **Sync fans out what blocks and is due, not only what is reported.** Each `Sync` publishes `resource.banned` for every blocking infohash missing from `banned_published` that has at least one row with `purge_after` NULL or passed (`dueInfohashes`: any row, so a later duplicate row cannot postpone a purge already due; exempt rows need no test, they unblock the infohash), and deletes the records of infohashes that no longer block. So a ban that starts blocking without a report — `exempt` flipped back to false, a row inserted by hand, a failed publish — reaches web-ui and vault within one interval of being due; setting `exempt` clears the record in the same pass that lifts the block, so lifting the exemption later re-publishes. The table is seeded with the stoplist as of the migration, so a restart or the first deploy does not re-publish everything. Fan-out errors are logged and never fail `Sync`.
- **A rollback below migration 6 purges every pending ban at its next sync**: the old code ignores `purge_after`. So does an old replica still running during a rollout.

`cs.NATS` is created from `--nats-service-host` / `--nats-service-port` (env vars `NATS_SERVICE_HOST/PORT` are auto-injected by Kubernetes from the `nats` Service in the `webtor` namespace; no chart wiring required). If the host flag is empty, `NewNATS` returns `nil` and `publishBanned` becomes a no-op — useful for local runs without NATS.

### Mailer

`services/mailer.go` renders two embedded templates (`services/templates/{user,support}.go.tpl`) from a `Notice` (the report plus what became of each hash) — `text/template`, plain-text email body, headers prepended manually in `services/smtp.go`. The user template branches on `AllExempt` / `IsIllegal` to send an "under moderation", "added to stoplist" or "we'll look into it" body. The support letter says until when the automatic purge waits, that setting exempt or deleting the row before then cancels it, and that a manual metadata backfill can still remove the data meanwhile; or that it was immediate, and which hash's schedule it replaced.

The support letter shows `reporter_name` and the two statements when any is set, and marks the address as confirmed for a notice that came through `Confirm`; for `CSAM_REPORT` its subject is prefixed `[CSAM report]`. `SendConfirmEmail` is the template-free confirmation letter of `--form-confirm`: fixed subject and body, no caller text.

`SendExemptEmail` is a third, template-free letter to support, `[exempt] <hash> — <reason>`, sent by `Exempt` when it changed rows. `services/smtp.go` RFC 2047-encodes the Subject (`mime.QEncoding`; plain ASCII passes unchanged), so a CR LF that reaches it cannot start a header of the caller's choosing; `To` and `Reply-To` are the syntax-checked `email`.

`services/smtp.go` handles three connection modes selected by flags:
- `SMTP_TLS=true` → implicit TLS via `tls.Dial` (port 465 style).
- `SMTP_TLS=false, SMTP_STARTTLS=true` → plaintext dial, then `STARTTLS`.
- Both false → plaintext.
- `SMTP_TLS_SECURE` (default true) controls cert verification; set false only for self-signed dev SMTP.

### Wiring

`serve.go` is the canonical wiring read for this service: PG → migrations → Badger → Store (with initial Sync) → SMTP → Mailer → Probe → GRPC (public, plus admin unless `--admin-port 0`) → `cs.NewServe(probe, store, grpcs...)`. On shutdown both gRPC servers drain side by side, each within its 15 s graceful-stop timeout, so the pair fits the pod's 30 s grace period before Badger closes. The `serve` runner from `common-services` runs `Probe`, `GRPC`, and `Store.Serve()` (the periodic-sync ticker) concurrently. Adding a new long-running component means passing it into `cs.NewServe(...)`; otherwise it never starts.

## Conventions inherited from the platform

- CLI flags via `urfave/cli` v1, env-var fallbacks via `EnvVar`. Flag registration is split into `Register*Flags` helpers per service file — keep this pattern.
- Common infra (PG, migrations, Probe, Serve) comes from `github.com/webtor-io/common-services`; do not reimplement.
- Errors wrapped with `github.com/pkg/errors`; logs via `logrus` with `WithError` / `WithField`.
- Migrations are SQL-only files under `migrations/`, numbered `N_name.{up,down}.sql`. The Dockerfile copies the directory into `/migrations` so the `migrate` subcommand finds them at runtime.

## Cross-service touchpoints

Callers in this monorepo: `web-ui` (`services/abuse_store/client.go` — DMCA form + Check on playback). The proto contract in `proto/abuse-store.proto` is the public surface; bumping field numbers or removing enum values is a breaking change for every caller.
