# abuse-store

DMCA / abuse-notice service for the [Webtor](https://github.com/webtor-io) platform.

It does three things behind a single gRPC API:

- **Stoplist for illegal content.** Reports with `cause = ILLEGAL_CONTENT` are persisted, and other services (`web-ui`, `torrent-http-proxy`) call `Check(infohash)` before serving content to block playback of reported torrents.
- **Mail relay.** Every accepted notice (illegal content, malware, app error, generic question) generates a support email and, when the reporter provided a return address, an acknowledgement.
- **Cleanup fan-out via NATS.** Once an `ILLEGAL_CONTENT` ban's purge delay (`--purge-delay`, default 72h) has passed, it publishes `resource.banned` so `web-ui` and `vault` purge data tied to the banned infohash. The block itself is immediate; the delay leaves time to review a report before data is irreversibly deleted.

## Architecture

```
gRPC client ──► Push / Check  ─┬─► PostgreSQL  (source of truth, persisted abuses)
                               ├─► BadgerDB    (in-memory hot cache, rebuilt from PG on boot)
                               ├─► Mailer ──► SMTP ──► support + reporter
                               └─► NATS  ──► resource.banned ──► web-ui / vault cleanup
```

- **PostgreSQL** stores the canonical abuse records (`migrations/1_abuse.up.sql`).
- **BadgerDB** at `/tmp/badger` holds an infohash-keyed cache used by `Check`. It is loaded from the full `abuse` table on startup (`Store.Sync`) and refreshed every `--sync-interval` minutes — this is the only mechanism that propagates inserts and deletions between replicas (a deleted row stops blocking within one interval), so don't expect sub-second cross-pod consistency.
- **SMTP** delivery is best-effort and runs in goroutines; failures are logged but don't fail the RPC.

## gRPC API

Defined in [`proto/abuse-store.proto`](proto/abuse-store.proto):

- `Push(PushRequest) → PushReply` — submit an abuse notice naming `infohash` and, optionally, more `extra_infohashes`. Each hash must be a full 40-character hex infohash (case and surrounding whitespace are normalized), repeats are dropped, `email` is validated; `notice_id` and `started_at` default to a fresh UUID and the current time. Only `ILLEGAL_CONTENT` causes a database write: one row per hash not yet blocked, under the same `notice_id`, purged after `--purge-delay` — or at once with `purge_now = true`, which also brings forward a pending purge of an already-blocked hash. A notice whose every hash is already blocked, and that brought no pending purge forward, is rejected with `ALREADY_EXISTS` and mailed to no one; a repeat report without `purge_now` publishes nothing. A hash marked `exempt` in the table is mailed as usual (the reporter is told it is under moderation, support sees it marked `[exempt]`) but is neither stored nor fanned out, except that an immediate ban (`purge_now`, or `--purge-delay 0`) overrides an exemption set through `Exempt`: it is stored and purged, and the exemption is cleared. One set by hand absorbs every report. One letter goes to support and at most one to the reporter per notice, listing every hash.
- `Check(CheckRequest) → CheckReply` — returns `exists = true` if the infohash is in the stoplist (Badger lookup). Deleting a row or setting `exempt = true` lifts the block at the next sync; `Exempt` lifts it at once.
- `Exempt(ExemptRequest) → ExemptReply` — sets `exempt` on every row of `infohash`, but only while its ban is in the review window: it has rows, and every non-exempt one has a `purge_after` still ahead. The block lifts at once on the replica that serves the call, fingerprint included (other replicas follow at their next sync), and the purge never goes out. `rows` is the number of rows changed, 0 if the hash was already exempt. A `purge_now` ban, a row from before the purge delay (`purge_after` NULL) or a ban whose purge is due is refused with `FAILED_PRECONDITION`; an unknown hash is `NOT_FOUND`. The guard is there because the gRPC port has no authentication: anything in the cluster can call it, and that must never unban an immediate ban (the CSAM ban script sends `purge_now`) or one whose data is already gone. Those are exempted by hand in the database. For the same reason a later immediate ban overrides an exemption set here (`abuse.exempt_by_rpc`), so reporting and exempting a hash first cannot shield it from one; `UPDATE abuse SET exempt_by_rpc = false WHERE infohash = '<hash>'` makes it hold. `reason` goes to the server log; no mail is sent.

## NATS events

`ILLEGAL_CONTENT` bans publish to subject **`resource.banned`**, once their purge is due, with body:

```json
{ "infohash": "<lowercase hex>" }
```

The platform's JetStream stream `common` captures `resource.*`, so any consumer in the cluster can subscribe via a durable pull consumer. Existing subscribers:

- `web-ui` — drops the resource from `library`, `watch_history`, `cache_index`, `torrent_resource`, media metadata and the `vault.pledge` / `vault.tx_log` / `vault.resource` tables (refunding VP).
- `vault` — queues the resource for deletion (S3 + own DB) via `ResourceQueueForDeletion`.

Publishing is best-effort and never fails the RPC. Consumers must be idempotent — a `purge_now` repeat re-fires the event. Each periodic sync publishes every blocking infohash that is due (a row with `purge_after` NULL or passed) and not yet recorded in `banned_published`, and forgets the ones that stopped blocking, so a delayed ban, a failed publish, a row inserted by hand, or an exemption lifted (`exempt` back to false) is fanned out within one `--sync-interval` of being due. Setting `exempt` (by hand or with `Exempt`) or deleting the row before `purge_after` cancels the automatic purge; web-ui's manual metadata backfill, if run meanwhile, can still remove the data.

## Build & run

```bash
go build ./...                           # main server binary + ./client CLI
go run . serve [flags...]                # start the server
go run . migrate up                      # apply PostgreSQL migrations
make protoc                              # regenerate proto/*.pb.go
```

### Server flags

```
--probe-host                       probe host                                [$PROBE_HOST]
--probe-port           (8081)      probe port                                [$PROBE_PORT]
--use-probe                        enable probe                              [$USE_PROBE]
--postgres-host                    postgres host                             [$PG_HOST]
--postgres-port        (5432)      postgres port                             [$PG_PORT]
--postgres-user                                                              [$PG_USER]
--postgres-password                                                          [$PG_PASSWORD]
--postgres-database                                                          [$PG_DATABASE]
--postgres-ssl                                                               [$PG_SSL]
--grpc-host                        grpc listening host                       [$GRPC_HOST]
--grpc-port            (50051)     grpc listening port                       [$GRPC_PORT]
--nats-service-host                nats host (auto-injected in K8s)          [$NATS_SERVICE_HOST]
--nats-service-port    (4222)      nats port                                 [$NATS_SERVICE_PORT]
--sync-interval, --si  (10)        PG → Badger resync interval, minutes      [$STORE_SYNC_INTERVAL]
--purge-delay          (72h)       ban → resource.banned delay; 0 = at Push  [$PURGE_DELAY]
--smtp-host                                                                  [$SMTP_HOST]
--smtp-port                                                                  [$SMTP_PORT]
--smtp-user                                                                  [$SMTP_USER]
--smtp-pass                                                                  [$SMTP_PASS]
--smtp-tls                         use implicit TLS (port 465 style)         [$SMTP_TLS]
--smtp-start-tls                   use STARTTLS over plaintext connection    [$SMTP_STARTTLS]
--smtp-tls-secure      (true)      verify TLS certificates                   [$SMTP_TLS_SECURE]
--mail-sender          (noreply@webtor.io)                                   [$MAIL_SENDER]
--mail-support         (support@webtor.io)                                   [$MAIL_SUPPORT]
```

`--smtp-tls` and `--smtp-start-tls` are mutually exclusive. Set `--smtp-tls-secure=false` only against a self-signed dev SMTP.

### Client CLI

The `client/` directory contains a small `urfave/cli` tool for smoke-testing:

```bash
go run ./client --host 127.0.0.1 --port 50051 push \
    --hash <infohash> --work "..." --email reporter@example.com --description "..."
# also: --extra-hash <infohash> (repeatable), --purge-now, --source form|mail (default form),
#       --subject, --started-at (RFC 3339 or unix seconds), --notice-id, --fingerprint

go run ./client --host 127.0.0.1 --port 50051 check --hash <infohash>

go run ./client -H 127.0.0.1 -P 50051 exempt --hash <infohash> --reason "..."
# prints the rows set exempt; exits 1 with the gRPC error (code = FailedPrecondition / NotFound) otherwise
```

## Migrations

SQL files in [`migrations/`](migrations/), numbered `N_name.{up,down}.sql`, run by the `migrate` subcommand from [`webtor-io/common-services`](https://github.com/webtor-io/common-services). The Docker image copies the directory to `/migrations` so migrations are available at runtime.

## Docker

```bash
docker build -t webtor/abuse-store .
docker run --rm -p 50051:50051 -p 8081:8081 \
    -e PG_HOST=... -e PG_USER=... -e PG_PASSWORD=... -e PG_DATABASE=... \
    -e SMTP_HOST=... -e SMTP_PORT=587 -e SMTP_USER=... -e SMTP_PASS=... -e SMTP_STARTTLS=true \
    webtor/abuse-store
```

Built and pushed to `ghcr.io/webtor-io/abuse-store` by [`.github/workflows/docker-image.yml`](.github/workflows/docker-image.yml) on push to `main` and on `v*` tags.

## License

[MIT](LICENSE)
