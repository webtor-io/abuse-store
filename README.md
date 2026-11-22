# abuse-store

DMCA / abuse-notice service for the [Webtor](https://github.com/webtor-io) platform.

It does three things behind a single gRPC API:

- **Stoplist for illegal content.** Reports with `cause = ILLEGAL_CONTENT` or `INTIMATE_IMAGE` are persisted, and other services (`web-ui`, `torrent-http-proxy`) call `Check(infohash)` before serving content to block playback of reported torrents. With `--form-confirm`, such a report from the web form waits until its reporter confirms it by email.
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

Defined in [`proto/abuse-store.proto`](proto/abuse-store.proto), served on two listeners:

| Listener | Bind | Serves | Who uses it |
|---|---|---|---|
| public, `--grpc-port` (50051) | `--grpc-host`; the Kubernetes Service | `Push` (`purge_now` ignored; form notices held with `--form-confirm`), `Check`, `Confirm`; `Exempt` is `UNIMPLEMENTED` | web-ui (DMCA form, `Check` on playback, its confirmation page), torrent-http-proxy (`Check`), the automated intake of forwarded abuse reports |
| admin, `--admin-port` (50052; 0 disables it) | `127.0.0.1` inside the pod only | `Push` with `purge_now` honoured, `Check`, `Exempt`, `Confirm` | the CSAM ban script of the platform's monitoring agent, and owner decisions |

The admin port has no Service port and no `containerPort`. It is reached with `kubectl port-forward deploy/abuse-store <local>:50052`, so its access control is Kubernetes RBAC (`pods/portforward` or `exec` in the namespace). It carries the two calls that override an earlier decision: an immediate ban beats an exemption, and an exemption lifts a ban.

- `Push(PushRequest) → PushReply` — submit an abuse notice naming `infohash` and, optionally, more `extra_infohashes`. Each hash must be a full 40-character hex infohash (case and surrounding whitespace are normalized), repeats are dropped, `email` is validated, CR and LF are dropped from `subject` and `notice_id`; `notice_id` and `started_at` default to a fresh UUID and the current time. Only `ILLEGAL_CONTENT` and `INTIMATE_IMAGE` cause a database write (`reporter_name`, `good_faith` and `authorized` are kept on the rows); `CSAM_REPORT` is mailed to support only, with its subject prefixed `[CSAM report]`, and never stored or banned, from any port or source. A write is one row per hash not yet blocked, under the same `notice_id`, purged after `--purge-delay`. On the admin port, `purge_now = true` purges at once and brings forward a pending purge of an already-blocked hash; the public port ignores it (the delay applies, and the server logs a warning). A notice whose every hash is already blocked, and that brought no pending purge forward, is rejected with `ALREADY_EXISTS` and mailed to no one; a repeat report without an immediate purge publishes nothing. A hash marked `exempt` in the table absorbs ordinary reports: they are mailed as usual (the reporter is told it is under moderation, support sees it marked `[exempt]`) but neither stored nor fanned out. **`purge_now` on the admin port beats any exemption**, set by hand or with `Exempt`: in one transaction it clears the exemption, brings every pending purge of the hash forward and stores its row, then publishes, and support is told "an exemption was overridden by an immediate ban". A server with `--purge-delay 0` purges every report at once but does not override exemptions. One letter goes to support and at most one to the reporter per notice, listing every hash.
- `Confirm(ConfirmRequest) → ConfirmReply` — confirms a notice held by `--form-confirm` with the `t` token of its link. `CONFIRMED` (and `hashes`, the number of infohashes) stores and mails it as `Push` would have; `ALREADY_CONFIRMED` for a token used before, `EXPIRED` for one not used within 72 hours, `UNKNOWN` otherwise, including an expired one after the next sync dropped it. Served on both ports.
- `Check(CheckRequest) → CheckReply` — returns `exists = true` if the infohash is in the stoplist (Badger lookup). Deleting a row or setting `exempt = true` lifts the block at the next sync; `Exempt` lifts it at once.
- `Exempt(ExemptRequest) → ExemptReply` — admin port only. Sets `exempt` on exactly the rows of `infohash` it checked, and only while its ban is in the review window: it has rows, and every non-exempt one has a `purge_after` still ahead. The block lifts at once on the replica that serves the call, fingerprint included (other replicas follow at their next sync), and the purge never goes out. `rows` is the number of rows changed, 0 if the hash was already exempt. A `purge_now` ban, a row from before the purge delay (`purge_after` NULL) or a ban whose purge is due is refused with `FAILED_PRECONDITION`; an unknown hash is `NOT_FOUND`. Those bans are exempted by hand in the database. Every exemption that changed rows is mailed to support as `[exempt] <hash> — <reason>`; `reason` also goes to the server log.

### Form notices confirmed by email

`--form-confirm` (`FORM_CONFIRM`, default false; off, nothing changes) holds an `ILLEGAL_CONTENT` or `INTIMATE_IMAGE` `Push` that arrives on the public port with `source = FORM`. `source = MAIL` and the admin port ban as before.

- A held takedown (`ILLEGAL_CONTENT`) needs `email`, `reporter_name`, `good_faith` and `authorized`; `INTIMATE_IMAGE` needs `email`. Otherwise `INVALID_ARGUMENT`. One whose every infohash is already blocked is `ALREADY_EXISTS` and mailed to no one, as without the flag.
- It is stored in the `unconfirmed_notice` table, never in `abuse`, so it blocks nothing and nothing that reads `abuse` (the cache, `Check`, the fan-out, `Exempt`, review queries) needs a new filter. The token is 32 random bytes, kept only as its sha256.
- The reporter gets one letter, sent before `Push` returns: subject `Confirm your report <notice id>`, a fixed body with the link `<--confirm-url>?t=<token>` (`CONFIRM_URL`, default `https://webtor.io/support/confirm`), the number of torrents, their infohashes and the 72-hour expiry, and nothing else the caller typed. The reply has `confirmation_sent = true`; support hears nothing yet. A letter that cannot be sent is `UNAVAILABLE`.
- At most 3 held notices per address and 200 in all per 24 hours, else `RESOURCE_EXHAUSTED`.
- The page behind the link must confirm on `POST` only: mail scanners and link previewers open every link they see, and a confirming `GET` would confirm every notice for the reporter.
- `Confirm` applies a notice once, however many times or on however many replicas it is called; a failed one can be retried. Each sync deletes held notices past their expiry.

### Known gaps

- **The public `Push` is unauthenticated**: anything that reaches the Service can ban any infohash. The block is immediate; the purge waits out the delay, so a reviewer can still exempt it in time. `--form-confirm` trusts the caller's `source`: it guards the web form, not a caller that reaches the Service and says `MAIL`.
- **Reporter mail can be sent to any address**: `email` is only syntax-checked, so a caller can have the acknowledgement, quoting its own description, sent anywhere. Held form notices get only the fixed confirmation letter, rate-limited per address and per day; other causes still quote.
- **Several replicas race**: the store lock is per process. `Exempt` lifts the block at once only on the replica that served it, two replicas pushing the same new hash can both insert a row, and an exempt row inserted by hand while an immediate ban is in flight is not seen by it (the hash ends exempt, its data purged).
- **An immediate ban waits for row locks under the store lock**: an open transaction holding a row of the hash (a hand UPDATE in psql) holds up that ban, and Push and Sync on the replica, until it ends or the caller's deadline does.

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
--admin-port           (50052)     admin grpc port on 127.0.0.1; 0 = off     [$ADMIN_GRPC_PORT]
--form-confirm                     hold form notices until confirmed by mail [$FORM_CONFIRM]
--confirm-url          (https://webtor.io/support/confirm)  confirmation page [$CONFIRM_URL]
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
# also: --extra-hash <infohash> (repeatable), --purge-now (admin port only), --source form|mail (default form),
#       --subject, --started-at (RFC 3339 or unix seconds), --notice-id, --fingerprint,
#       --cause illegal|malware|app_error|question|csam_report|intimate_image (default illegal),
#       --reporter-name, --good-faith, --authorized

# a notice held by --form-confirm: the t parameter of the mailed link; prints e.g. "CONFIRMED 2"
go run ./client --host 127.0.0.1 --port 50051 confirm --token <t>

go run ./client --host 127.0.0.1 --port 50051 check --hash <infohash>

# admin port: Exempt, and Push with --purge-now honoured
kubectl port-forward deploy/abuse-store 50052:50052 &
go run ./client -H 127.0.0.1 -P 50052 exempt --hash <infohash> --reason "..."
# prints the rows set exempt; exits 1 with the gRPC error (code = FailedPrecondition / NotFound) otherwise;
# against the public port it exits 1 with code = Unimplemented
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
