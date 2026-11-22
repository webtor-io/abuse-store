# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Service role

`abuse-store` is the DMCA / abuse-notice sink for the Webtor platform. It does three distinct jobs that share one gRPC surface:

1. **Stoplist** for torrents reported as illegal content. Other components (web-ui, torrent-http-proxy) call `Check(infohash)` before serving content; a positive answer blocks playback.
2. **Mail relay** for every kind of incoming notice (illegal content, malware, app error, generic question), forwarding to support and acknowledging the reporter.
3. **Cleanup fan-out** via NATS: once a `Cause = ILLEGAL_CONTENT` ban's purge delay (`--purge-delay`, default 72h) has passed, it publishes `resource.banned` so downstream services (web-ui, vault) purge their data for that infohash. The block is immediate; only the irreversible purge waits.

Only `Cause = ILLEGAL_CONTENT` notices are persisted in the stoplist or fan out via NATS. Other causes (`MALWARE`, `APP_ERROR`, `QUESTION`) are passed through to email only — see `services/grpc.go` `Push`. Don't add `store.Push` calls for non-illegal causes without understanding this split.

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

Tests cover the `Check` blocking decision, the sync load/prune (deletions and exempt rows), the purge-due rule and the letters (`services/*_test.go`), against an in-memory Badger with no Postgres. `services/push_pg_test.go` drives `Push` and `Sync` against a real Postgres and NATS (delayed and immediate purge, review inside the window, several hashes per notice); it is skipped unless `ABUSE_STORE_TEST_PG` and `ABUSE_STORE_TEST_NATS` are set — the file header has the two `docker run` lines. It wipes the database, so the name must end in `_test`. `services/exempt_pg_test.go` drives `Exempt` the same way: each refused case, `Store.Push` refusing a row exempted since its caller asked, the block lifted on both arms without a Sync and never purged, a purge brought forward concurrently, the store lock, a row-lock wait that stalls no Push or Sync and ends at the caller's deadline, an immediate ban overriding an RPC exemption, a row that lands while Exempt waits left alone. `client/main_test.go` checks the push and exempt flags reach the request.

The `Dockerfile` produces a static linux binary, copies `migrations/` into `/migrations`, and exposes `8081` (probes) + `50051` (gRPC). HTTP serving is *not* exposed (the service has no HTTP handlers).

## Architecture

### Two-tier storage, async sync

The store has a non-obvious dual layout:

- **PostgreSQL** (`models.Abuse` via `go-pg`) — source of truth, persistent.
- **BadgerDB** at `/tmp/badger` — keyed by infohash, in-memory hot cache used only by the `Check` RPC.

Lifecycle (see `services/store.go`):
- On startup, `Store.Sync()` iterates **the whole `abuse` table** and pushes every row into Badger. This is intentional — the entire stoplist is loaded on boot so `Check` is O(1) on a local KV with no PG hop.
- `Push` writes to PG first, then mirrors into Badger (`pushToCache`).
- `Store.Serve()` re-runs `Sync()` every `STORE_SYNC_INTERVAL` minutes (default 10) to pick up rows inserted by other replicas and to prune keys whose rows were deleted (deleting a row lifts the ban within one interval). Push and Sync share a mutex so the prune cannot drop a row inserted mid-walk. **This is the only cross-replica consistency mechanism** — there is no pub/sub.
- Badger lives on the pod's local filesystem at `/tmp/badger`; it is treated as ephemeral cache and rebuilt from PG on every restart.
- **Exempt rows** (`abuse.exempt`, migration 4) record a reviewed infohash that must never block. `Store.load` drops every row for an exempt infohash, both arms, regardless of row order. Exemption is per infohash: another row whose fingerprint matches the same payload still blocks it via torrent-store's fingerprint-only `Check`. Set with the `Exempt` RPC while the ban is in its review window, otherwise by hand: `UPDATE abuse SET exempt = true WHERE infohash = '<hash>'` (or `INSERT INTO abuse (infohash, exempt, description) VALUES (...)` if the row is gone). An exemption set through the RPC is marked `exempt_by_rpc` (migration 7) and gives way to an immediate ban (`purge_now`, or a server with `--purge-delay 0`): that Push stores its row, purges, and `Store.PurgeNow` clears the exemption. One set by hand holds against every report; to make one set through the RPC hold as well, `UPDATE abuse SET exempt_by_rpc = false WHERE infohash = '<hash>'`.

Implication: if you add a write path, write to PG first and let `pushToCache` mirror it. Do not add Badger-only writes — other replicas will not see them until the next sync tick.

### gRPC entry point

`services/grpc.go` implements `pb.AbuseStoreServer`:

- `Push` takes the primary `infohash` plus any `extra_infohashes` of the same notice, validates each (anchored `^[0-9a-f]{40}$` after trim + lowercase; the primary may be empty for a fingerprint-only ban, an extra may not), drops repeats, validates `email`, fills defaults (`notice_id` → uuid, `subject` → `Abuse notice <id>`, `started_at` → now), and:
  - For `ILLEGAL_CONTENT`, per hash: an **exempt** one (`Store.IsExempt`, asks PG directly, and `Store.Push` asks again under the store lock, so a Push racing `Exempt` on the same replica does not cache the hash again) gets no row and no `resource.banned` (for an immediate ban only an exemption set by hand counts, see the exempt rows above); one already blocked (`Check`) gets no new row; every other gets its own row under the same `notice_id` (the fingerprint goes on the primary's row only), with `purge_after` = now + `--purge-delay`, or now for `purge_now`.
  - `resource.banned` goes out at Push only for an immediate purge (`purge_now`, or a server with `--purge-delay 0`), for every non-exempt hash including already-blocked ones, whose pending `purge_after` is brought forward to now first (`Store.PurgeNow`, which in the same UPDATE clears an exemption set through the RPC). Otherwise Sync publishes once due. **A duplicate report without `purge_now` publishes nothing**: it must not purge a delayed ban early, and a dropped publish is retried by Sync anyway.
  - Returns `AlreadyExists` only when every hash was already blocked and no pending purge was brought forward (`Store.PurgeNow` reports whether its UPDATE moved a row), and then sends no mail. A `purge_now` that did bring one forward succeeds and mails support, the hash marked as replacing its schedule. Exempt hashes are mailed as before: support subject gets `[exempt]` and the hash is marked; the reporter is told it is "under moderation", never "added to stoplist", and the RPC succeeds. Callers cannot tell it apart: a ban script sees only that the post-push `Check` stays false.
  - For other causes: skips persistence and NATS entirely.
  - Mails once per notice, whatever the number of hashes: `SendUserEmail` (only if reporter supplied an email) and `SendSupportEmail` in goroutines — failures are logged, not returned. Mail delivery is best-effort and not part of the RPC's success contract.
- `Check` reads only Badger.
- `Exempt` (`Store.Exempt`) sets `exempt` on every row of a validated infohash, only inside the review window: rows exist and every non-exempt one has `purge_after` ahead, by the same clock and rule as `dueInfohashes`. Otherwise `FailedPrecondition` (`purge_now`, `purge_after` NULL or passed); no rows `NotFound`; already exempt is OK with `rows = 0`. **Why the guard:** the port has no authentication, so an in-cluster caller must never be able to unban a CSAM or other agent ban (those are `purge_now`) or one whose purge already went out; those take a hand UPDATE with database credentials. Do not widen it. The guard alone covers only bans that exist when Exempt runs, so the override above is what stops a caller from reporting a hash, exempting it inside the window, and so making it immune to a later CSAM ban. Exempt marks only the rows it checked (`purge_after` ahead): an immediate row that lands while its read waits on a lock stays non-exempt, and its Push's `PurgeNow` clears the exemption. The rows are read `FOR UPDATE` in a transaction, so a `PurgeNow` racing it is either seen and refused or waits. The transaction runs under the RPC's context, so a caller that gave up while it waited on a row lock is not exempted later. It takes `Store.mu` only after the commit, for the cache reload (Sync's load + prune on a fresh read, no fan-out): a Sync that read the table before the commit holds the lock until its prune is done, so it cannot re-cache the hash, and a row lock held elsewhere (an open hand UPDATE) never stalls Push or Sync behind it. The reload drops the row's fingerprint key too unless another blocking row holds it; other replicas lift it at their next sync. It logs the reason and sends no mail. Not closed: a hand exemption set while a `purge_now` Push is past its `IsExempt` read still lets that Push publish, leaving the hash exempt and purged; and a Sync on the replica that runs between an overriding Push's insert and its `PurgeNow` still sees the RPC exemption and drops the hash from that replica's cache until the next sync (the table is right, and the purge goes out).

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

`services/smtp.go` handles three connection modes selected by flags:
- `SMTP_TLS=true` → implicit TLS via `tls.Dial` (port 465 style).
- `SMTP_TLS=false, SMTP_STARTTLS=true` → plaintext dial, then `STARTTLS`.
- Both false → plaintext.
- `SMTP_TLS_SECURE` (default true) controls cert verification; set false only for self-signed dev SMTP.

### Wiring

`serve.go` is the canonical wiring read for this service: PG → migrations → Badger → Store (with initial Sync) → SMTP → Mailer → Probe → GRPC → `cs.NewServe(probe, grpc, store)`. The `serve` runner from `common-services` runs `Probe`, `GRPC`, and `Store.Serve()` (the periodic-sync ticker) concurrently. Adding a new long-running component means passing it into `cs.NewServe(...)`; otherwise it never starts.

## Conventions inherited from the platform

- CLI flags via `urfave/cli` v1, env-var fallbacks via `EnvVar`. Flag registration is split into `Register*Flags` helpers per service file — keep this pattern.
- Common infra (PG, migrations, Probe, Serve) comes from `github.com/webtor-io/common-services`; do not reimplement.
- Errors wrapped with `github.com/pkg/errors`; logs via `logrus` with `WithError` / `WithField`.
- Migrations are SQL-only files under `migrations/`, numbered `N_name.{up,down}.sql`. The Dockerfile copies the directory into `/migrations` so the `migrate` subcommand finds them at runtime.

## Cross-service touchpoints

Callers in this monorepo: `web-ui` (`services/abuse_store/client.go` — DMCA form + Check on playback). The proto contract in `proto/abuse-store.proto` is the public surface; bumping field numbers or removing enum values is a breaking change for every caller.
