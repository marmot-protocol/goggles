# Upload lock chains: investigation and proposed fix

## Evidence and confidence

This investigation made **no production mutations**. The owner separately paused
uploads during the investigation. No sessions were terminated, services restarted,
evidence deleted, or deployment performed by this work.

At 12:37–12:38 UTC on September 20, production had recurred after the earlier
recovery. The host checkout and freshly fetched upstream master both resolved to
`77286d98c7184902df947d68fd593498a5af5f6e`. SHA-256 checks of the running container's
`ingest.py`, `projections.py`, `source_metadata.py` and `config/settings.py` matched
that checkout. Running image ID:
`sha256:51fd1be550258a2e09c6e7652a549a0de5f6f1d70e4a1b8d9ea3927439a13b2e`.
Compose services were `web`, `db`, `static`, and `retention`; `web` was unhealthy.
The running Gunicorn command had **3 workers × 2 threads**, not the historical
12-slot setting. `ATOMIC_REQUESTS=False`.

Sanitized 12:38 UTC snapshot (ages rounded, SQL values never collected into the
report; PIDs are ephemeral operational identifiers):

| Backend | Transaction age | State / wait | SQL shape | Blocks / blocked by |
| --- | ---: | --- | --- | --- |
| 771253 | 619s | idle in transaction / ClientRead | INSERT network observation | blocks 771298, 771541 |
| 771245 | 582s | idle in transaction / ClientRead | INSERT observation evidence link | blocks 771297 |
| 771298 | 534s | active / transactionid lock | SELECT audit group FOR UPDATE | waits for 771253; blocks 771678 |
| 771297 | 545s | active / transactionid lock | SELECT audit group FOR UPDATE | waits for 771245 |
| 771541 | 220s | active / transactionid lock | INSERT audit file | waits for 771253 |
| 771678 | 42s | active / transactionid lock | INSERT audit file | waits for 771298 |

The two owners' last queries were only **1–2 milliseconds old**. Across samples,
their inserts changed while transaction age increased. They were actively doing
many small projection writes between brief client-side intervals, not demonstrably
abandoned idle transactions. The web container used about 418 MiB of its 16 GiB
limit and 102% CPU at one sample. Retention used 0% CPU and had only its scheduler
processes, so it was not the observed active blocker. A sanitized completed POST
at 12:37:03 had status 201 and duration **584.281s**. RAM exhaustion is not supported
by this evidence. Cumulative block-I/O counters are not disk-latency measurements.

In a fresh connection from the running application, `lock_timeout`,
`statement_timeout`, `idle_in_transaction_session_timeout`, and PostgreSQL 17
`transaction_timeout` were all **0**. An earlier diagnostic session set its own
statement timeout to 5s; that was not an application setting or live timeout change.

**Confirmed failure mechanism:** expensive projection work holds an upload's
outer transaction open; group row locks serialize other uploads, and duplicate
file inserts form additional uniqueness waits behind those transactions. Those
requests occupy the same finite request pool as reads and health. The local HTTP
reproduction below demonstrates that this is sufficient to make reads time out.
The running threaded worker's heartbeat does not bound a request's duration.
[Gunicorn explains that distinction](https://docs.gunicorn.org/en/stable/design.html#gthread-workers).

**Demonstrated contributor:** the backfill detector compared devices against each
other even though inferred convergence runs are keyed by `(group, engine)`. A new
device's earlier convergence event could cause every projection of an existing
group to be deleted and replayed. The regression fixture demonstrates 31 existing
events needlessly being replayed for one new event. This is a proven code defect
and staging reproduction, not proof that these exact production owners took that
branch: the live samples did not contain their Python stacks or upload identity.

**Other contributors / remaining unknowns:** real same-recorder backfills still
need ordered replay; the divergence rollup still scans a touched group's retained
history. New-group uniqueness conflicts and line-dedup races were also possible
before early locking. We did not recover the terminated September 10 / earlier
September 20 sessions, identify those incidents' first SQL statement, collect
Caddy request-start attribution, or sample production disk latency. There is no
evidence here of a database-wide exclusive lock, PostgreSQL deadlock, or a
retention-caused outage. This is unrelated to the client's
`account_delivery_queue_overflow` mechanism.

## Request and transaction boundaries

Source references are relative to this patch:

- `forensics/views.py:3197`: both upload routes share token authentication and the
  upload toggle. `verified_audit_bytes` at line 3392 reads the entire bounded raw
  or in-memory multipart body, checking Content-Length and truncation. There is
  no inbound decompression stage. These reads happen before the ingestion atomic
  block. Missing/invalid bearer credentials remain 401.
- `forensics/ingest.py:222`: v4 schema validation, JSON parsing/normalization,
  hash computation, committed-file lookup, and body metadata extraction precede
  the write transaction. Identical committed files still validate first.
- `forensics/ingest.py:246`: the outer atomic write holds locks through raw file
  persistence, event deduplication/bulk insert, file/group provenance links,
  projections and divergence rollups. Nested projection `atomic()` blocks are
  savepoints, not independent commits. There is no external file/network I/O
  inside it; Python loops, database round trips and historical scans occur there.
- `forensics/projections.py:139`: per-file projection takes group locks in ID order.
  `groups_with_out_of_order_convergence_backfill` (line 178) chooses ordered full
  replay when required; `rebuild_locked_group_projections` (line 327) performs it.
  `active_inferred_runs_for_events` (line 249) already keys state by group/engine.
- `forensics/source_metadata.py`: PR #358 resolves validated session metadata on
  reads; it does not fan out metadata UPDATEs during ingestion. This fix leaves
  session/account/engine isolation and raw metadata unchanged.
- `prune_audit_data` deletes in batches then rebuilds affected groups. Compose
  `web` startup runs migrations/collectstatic, not pruning. The separate scheduler
  waits for its child, runs at startup and nightly at 03:00 UTC, and retries failed
  jobs after five minutes. The new session advisory lock excludes additional
  scheduler/manual invocations without holding a prune-wide transaction.

```mermaid
sequenceDiagram
    participant C as Client
    participant E as Caddy
    participant U as Upload sync workers (2)
    participant D as PostgreSQL 17
    participant R as Read workers (6 slots)
    C->>E: POST either upload route
    alt Upload pool at capacity
        E-->>C: 503 + Retry-After (no acceptance)
    else Admitted
        E->>U: Authenticate, bounded body read, validate
        U->>D: BEGIN + transaction-local deadlines
        U->>D: Try recorder lock; resolve groups; group NOWAIT locks
        alt Conflict
            D-->>U: Busy / bounded lock error
            U->>D: ROLLBACK
            U-->>C: 503 + Retry-After
        else Locks acquired
            U->>D: Raw evidence, canonical events, provenance, projections, rollups
            U->>D: COMMIT (release all transaction locks)
            U-->>C: 201 (or 200 for a committed duplicate)
        end
    end
    C->>E: Browse / export / health
    E->>R: Independent read pool
    R->>D: Reads under normal MVCC semantics
    R-->>C: Response
```

Previously all requests went to the same six slots; blocked uploads occupied
those slots until the owning transaction finished. A client disconnect during
post-body processing does not itself cancel Python work. The new sync worker
deadline bounds CPU/body stalls, PostgreSQL bounds the transaction, and ordinary
exceptions/BaseException paths leave `atomic()` through rollback. A disconnect
after commit can still lose the response; retrying the identical file returns 200.

## Patch choices and limits

1. Compare backfills only within `(group, engine)` and prefilter irrelevant event
   types/context before reading history. Do not rewrite convergence semantics or
   introduce eventually consistent projections. Real same-engine historical
   backfills retain full replay. The regression compares normalized projections
   and evidence links with an explicit full rebuild.
2. Acquire a nonblocking transaction advisory lock per validated recorder before
   deduplication, including ungrouped source events. Acquire existing group row
   locks with NOWAIT before child writes. Create new groups in deterministic key
   order and use a 1s lock deadline for unavoidable uniqueness/foreign-key waits.
   This protects canonical deduplication and prevents file-hash wait chains.
   Independent recorders/groups are not globally serialized.
3. Use a separate two-process **sync** ingest service. Caddy limits simultaneous
   proxied uploads, without buffering them in a durable job queue; excess load
   receives 503/Retry-After. The read service always disables uploads, so a stale
   proxy route fails closed rather than consuming its pool. The upload service
   does not migrate, collect static assets or prune on startup.
4. Set local database safeguards inside each ingestion transaction: 1s lock,
   30s statement, 15s idle, **90s total transaction**. A 120s sync worker deadline
   covers validation and CPU stalls outside SQL after the last body progress.
   A separately bounded 900s body-transfer phase heartbeats only on reads of at
   most 64 KiB; idle socket waits still have a 120s bound. The proxy allows
   125s for upstream response headers after sending the body. The hierarchy leaves time for rollback
   and response handling; it is an initial protection budget, not an observed
   upper bound for every legitimate retained history. PostgreSQL terminates the
   connection on total/idle deadlines; the caller discards it before recording a
   fixed failure and retrying. Reads and retention do not inherit these settings.
   [PostgreSQL documents transaction-local configuration and timeout behavior](https://www.postgresql.org/docs/17/runtime-config-client.html).

No migration, raw-storage change, auth relaxation, validation bypass, silent
record omission, or early-success response is introduced. Busy errors do not
write rejection rows on the contended path; operational ingest HTTP logs count
503s without sensitive labels. Other processing failures retain body-free
rejection recording. The edge also sheds unauthenticated overload without
accepting data; admitted uploads still authenticate normally.

The fix deliberately **does not guarantee every valid file completes within the
budget**. Same-recorder replay and divergence aggregation remain proportional to
history. A repeatedly over-budget file needs a further measured projection design,
not repeated timeout increases or evidence deletion. This is visible failure with
retry safety, not an asynchronous queue that promises eventual processing. Do not
roll out without considering how clients retain/retry these 503s.

## Reproduction and measurements

The original before/after measurements below belong to the initial PR head
`a053fe5`. The self-review follow-up separates transfer and processing deadlines;
its additional verification is recorded below without rewriting those results.

### Self-review follow-up

The original 120s sync timeout also charged slow client transfers. The upload
worker now has a 900s total transfer budget, heartbeating only when bytes are
read, while preserving the 120s processing watchdog and 90s DB transaction
deadline. Raw and multipart parsing still uses the existing bounded RAM path.
Two slow uploads can fill the isolated upload pool for a finite period; excess
uploads are shed and browsing retains its own slots.

Caddy `request_buffers` was considered but not used: its
[proxy implementation](https://github.com/caddyserver/caddy/blob/v2.11.4/modules/caddyhttp/reverseproxy/reverseproxy.go)
buffers during request preparation, before upstream selection/in-flight request
counting. Therefore the configured two-request upstream cap would not bound
concurrent pre-admission body buffers.

Real Gunicorn subprocess regressions use scaled deadlines: a 4.8s progressing
transfer succeeds with the same worker under a 2s watchdog; continued progress
cannot defeat a 1.5s total transfer limit; idle body reads terminate; and CPU
work after the completed body is killed and replaced. These prove deadline
separation, not measured WAN throughput or production peak memory. Stream tests
cover byte fidelity and WSGI read/iteration methods. Deployment checks reject
PostgreSQL before 17 before accepting traffic; the per-ingest guard remains for
internal callers. The retention windows, startup drain and explicit `--no-deps`
service recreation are documented in the rollout instructions.

The committed Caddyfile syntax was validated locally using Caddy 2.11.4 with
synthetic unreachable upstreams. Both POST upload routes returned 503 with
`Retry-After: 30`; health, static and non-POST upload routes retained empty 502
responses without a retry header. No production request or config was changed.

The revised worker also passed the real HTTP lab with `--split --messages 1
--large`: exactly 67,108,864 raw bytes committed with 201, the multipart duplicate
returned 200, all four shed requests succeeded on retry, and all 122 samples per
read surface returned 200. No database lock waiters were observed. Numeric
results are in [upload-worker-review.json](benchmarks/upload-worker-review.json).
The host was also running the PostgreSQL test suite, so this is correctness
coverage under additional load, not a latency comparison with the original run.

### Original comparison

`scripts/benchmark_ingestion.py` accepts only an empty `goggles_lab_*` database on
loopback, never deletes existing evidence, and generates synthetic identities,
message delivery, source metadata and convergence. It starts real Gunicorn and
Caddy and samples `pg_stat_activity` every 20ms. No production fixture or token
is copied. `ingestion_lab_wsgi.py` gates the first projection **after its group
lock**, using a TCP synchronization signal; the comparison holds both owners
for the same 3.5s. Four contenders then exercise shared groups.

The deterministic comparison uses one six-thread shared pool, and then the same
six read slots plus two sync upload processes. This avoids stochastic uneven
accept distribution between Gunicorn processes; it is not a production process
layout or CPU benchmark. An additional 3×2 run also reproduced all three read
timeouts, but strict saturation was not reproducible on every accept distribution.
Production defaults remain 3×2 read workers. Mac Python 3.12/local Docker PostgreSQL
17 and Caddy are not Brain's Linux/CPU/memory environment.

Same inputs: two groups, two devices per group, 100 messages per group, **1,210
retained events** in four 128–242kB files; six one-event older convergence uploads
from new recorders. Raw results:
[before](benchmarks/upload-lock-before.json), [after](benchmarks/upload-lock-after.json).

| Measurement | Before `77286d9` | Patch |
| --- | ---: | ---: |
| Initial history upload latency | 0.75–1.74s | 0.72–1.57s |
| Burst HTTP completion | 6 × 201 in 6.01–10.30s | 2 × 201 in 3.54s; 4 × 503 in 1–2ms |
| Retrying the four shed files | Already committed | 4 × 201 in 24–29ms each |
| Completion throughput including immediate lab retries | ~0.58 files/s | ~1.64 files/s |
| Longest sampled transaction, including injected stall | 10.27s | 3.53s |
| Longest sampled lock wait | 8.06s | 0 observed |
| Maximum database lock waiters | 4 | 0 |
| Health while both owners held | timed out at 1s | 200, 3.4ms |
| Authenticated group index while held | timed out at 1s | 200, 37.5ms |
| Authenticated streaming export while held | timed out at 1s | 200, 159.8ms |
| Final exact-file duplicate | 200 | 200 |
| Durable queue | none | none |

Immediate lab retries intentionally bypass the advertised 30s delay to verify
correctness and processing cost; these are not client-visible wall-clock retry
SLAs. Lock-wait maxima are sampled, not proof that no microsecond waits occurred.
Read probes are taken at synchronized maximum occupancy, not a production p99
latency campaign. Throughput includes the artificial stall and is not steady-state
capacity. A local bounded `EXPLAIN ANALYZE` of the revised recorder/history lookup
used `forensics_a_grp_stat_time_idx`, returning one row in 0.080ms. No new index or
production ANALYZE/large scan was needed.

A repeat run continuously probed all three read surfaces during the burst and
retries: before, 31 probes per surface included 3 health, 2 browse and 2 export
timeouts; after, all 11 probes per surface returned 200, with maxima of 5.1ms,
53.9ms and 394.8ms respectively. These runs also overlapped local CI, so use them
as an availability check, not a clean throughput comparison. Raw samples:
[continuous before](benchmarks/upload-continuous-before.json),
[continuous after](benchmarks/upload-continuous-after.json).

A separate byte-boundary run accepted an exactly **67,108,864-byte** valid raw
file: 201 in 12.52s before and 11.48s after. Its multipart duplicate returned 200
in 2.45s / 2.73s respectively. Results:
[large before](benchmarks/upload-large-before.json),
[large after](benchmarks/upload-large-after.json). This uses 64 large-field
records, not 100,000 small records; concurrent worst-case memory and the longest
production same-recorder histories remain rollout validation gaps.

History scaling for the same one-event, new-recorder upload is visible in the
two runs: with 11 retained events per group, the two owners finished about 0.11s
beyond the injected 3.5s stall before, versus 0.04s after. With 605 events per
group, that overhead grew to 2.51s before and remained about 0.04s after. This
includes HTTP/SQL work, not just projection CPU. The old path's full replay is
confirmed independently by the regression's event-call count.

Example (use separate empty databases for before and after):

```sh
GOGGLES_ENV_FILE=.env.example GOGGLES_TEST_DB_PORT=55439 \
  docker compose -p goggles-lock-lab up -d --wait db-test
docker exec goggles-lock-lab-db-test-1 createdb -U goggles goggles_lab_before
docker exec goggles-lock-lab-db-test-1 createdb -U goggles goggles_lab_after
git worktree add --detach /tmp/goggles-lock-before 77286d9
.venv/bin/python scripts/benchmark_ingestion.py \
  --source /tmp/goggles-lock-before --port 58100 \
  --database-url postgres://goggles:goggles@127.0.0.1:55439/goggles_lab_before
.venv/bin/python scripts/benchmark_ingestion.py --source "$PWD" --split --port 58110 \
  --database-url postgres://goggles:goggles@127.0.0.1:55439/goggles_lab_after
```

The password above is solely the committed disposable test-service credential.
`--large` additionally exercises a valid exactly-64-MiB raw file and a multipart
duplicate, with large fields rather than worst-case tiny-event count. Use
`--messages N` for history scaling; genuine same-recorder replay still scales with
history and can hit the deadline. The script cleans its HTTP processes/containers
but retains the named disposable database for inspection.

## Verification and rollout

PostgreSQL-specific regression tests live in `test_ingestion_concurrency.py`:
held same-group, disjoint groups, identical in-flight files, overlapping ungrouped
segments, reverse multi-group ordering, rollback after exception/cancellation,
statement/total/idle deadlines, both API routes with PAT-vs-upload-token auth,
and retention overlap. Events/gates control order rather than sleeps. Existing
body/truncation, v4, projection, metadata and retention suites are also required.
The deployment Caddyfile validates with Caddy; model drift checks report no
migrations. Keep production smoke/near-limit concurrent memory checks as rollout
gates; a synthetic local 64-MiB success is not a worst-case RSS certification.

Final local `just ci` passed: 360 tests on PostgreSQL; 360 discovered on SQLite
with the 11 PostgreSQL-only tests appropriately skipped; Django system checks,
Ruff lint/format, migration drift and dependency audit all passed. A final Caddy
adapt/validation and diff-whitespace check also passed. These are local results;
they do not claim a deployment or hosted CI result.

Rollout requires separate owner authorization:

1. Keep the owner's current tagged edge pause. Snapshot only necessary current
   route/config fragments and record current image IDs. Verify a fresh database
   backup and its archive listing; the historical September 18 backup/image were
   **not reverified by this work** and must not be assumed available.
2. Inspect oldest transactions and workers. Let old in-flight uploads drain while
   paused. Do not restart over an unknown active transaction or automatically
   terminate it; escalate a bounded recovery separately. No durable jobs need
   migrating: uncommitted requests roll back, committed files deduplicate retries.
3. Build/tag a single reviewed revision for both web and ingest. Under the pause,
   recreate web/ingest and the retention service so it receives the singleton
   guard. Keep the 30-day retention setting and 03:00 UTC scheduler. No migration
   or historical purge is part of this patch. Verify effective positive DB
   deadlines, worker geometry, resource limits and loopback-only port 8002.
   Use explicit service targets with `--no-deps` when recreating upload/web
   containers. Ingest startup must pass its PostgreSQL 17 deployment check.
   Wait for any startup retention catch-up to complete before unpausing uploads;
   its rebuild locks cause fail-fast 503s for uploads touching affected groups.
4. Merge the upload matcher/overload/error handling into the **current** Caddy
   route. Validate before reload. Preserve the current pause, logging, body cap,
   static/read routes and unrelated services. Never restore historical saved
   Caddy JSON wholesale. Both valid POST route shapes must target ingest; web
   must return 503 for an authenticated misrouted POST.
5. With the pause retained, test authorized synthetic ingestion through the
   loopback ingest service: 201, exact retry 200, overlapping recorder retry,
   invalid/truncated 400, oversize 413 and bad token 401. Check raw file bytes,
   canonical event counts, provenance links, convergence, summaries and metadata.
   While holding synthetic uploads, verify authenticated browsing/export and
   health via the normal edge. Verify no stale transaction/advisory locks remain.
6. Only on approval remove the specific current pause rule. Monitor upload 503
   rate and retry progress as well as read latency. A 401 probe alone proves
   routing/auth responsiveness, not working ingestion.

Rollback: retain/reapply the scoped upload pause and drain the new sync pool.
Transfers may take up to 900s plus the 120s processing watchdog; do not assume
a 120s whole-request drain. Record unconfirmed client requests for retry. The patch
has no schema/storage migration: deploy the verified prior application image to
the read service and stop the isolated ingest service if necessary. Restore only
the reviewed upload-route change under the pause; do **not** reopen uploads into
the old unbounded shared pool. Keep retention and accounts/tokens/evidence/backups
intact. Review status of any retention child before changing that service.

## Monitoring

Use fixed labels such as service role, route name, status class and outcome:

- Alert on oldest ingest transaction approaching 60s; track max and distribution.
- Count idle transactions over 10s and blocked sessions over 1s; capture a bounded
  blocker graph with SQL operation/table shapes, never parameters or payloads.
- Track ingest request duration, 201/200/503 counts, worker timeout/restart/OOM
  counts, and active proxied requests. No durable queue exists; 503s are shed
  backlog requiring client retry. Do not call rejected work accepted/queued.
- Probe health plus authenticated index and a bounded export; alert on sustained
  latency/error changes rather than assuming health implies browsing works.
- Track retention last success, duration and singleton contention. Scheduler
  failures retry sequentially; multiple invocations now fail fast. Correlate
  upload 503s with startup/nightly rebuild windows and alert if they persist
  after pruning completes. The singleton requires a direct/session-pooled DB
  connection, as configured by Compose.
- Correlate CPU, memory and actual disk-latency/IOPS measurements with DB waits.
  Do not add arbitrary engine/group/file/message/account IDs as metric labels.

Repeated deadline failures are actionable evidence of a remaining expensive
workload. Escalate that workload for staging analysis rather than silently
discarding it, purging evidence or increasing concurrency/timeouts blindly.
