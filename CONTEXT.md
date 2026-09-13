# Project Context: Exasol Integration

## Purpose

This project registers MCP servers, scans their source repositories, and
combines code-level findings with runtime proxy telemetry to support a
trust/reputation view. PostgreSQL is the operational system of record.
Exasol is the analytics store and scoring surface.

The Exasol integration is currently focused on:

- Loading normalized scan findings and scan lifecycle state.
- Preserving manifest-history data for audit and analysis.
- Receiving runtime egress events from the proxy path.
- Computing a daily trust score from static findings and recent runtime
  behavior.

## Important source files

- [`server_management/exasol/star.sql`](server_management/exasol/star.sql):
  Exasol schema bootstrap for dimensions, facts, staging, and ETL bookkeeping.
- [`server_management/exasol/trust_score.sql`](server_management/exasol/trust_score.sql):
  daily `FACT_TRUST_SCORE` rollup.
- [`server_management/services/sync.py`](server_management/services/sync.py):
  Postgres-to-Exasol synchronization functions.
- [`server_management/services/runtime_telemetry.py`](server_management/services/runtime_telemetry.py):
  Postgres-free runtime proxy telemetry persistence and Exasol reads.
- [`server_management/api/telemetry_api.py`](server_management/api/telemetry_api.py):
  Dedicated HTTP contract used by the Go proxy in `Exasol/`.
- [`server_management/services/scan_pipeline.py`](server_management/services/scan_pipeline.py):
  direct in-process scan execution and its Exasol sync trigger points.
- [`server_management/api/api.py`](server_management/api/api.py):
  HTTP endpoints and FastAPI background-task sync hooks.
- [`server_management/api/githubapp.py`](server_management/api/githubapp.py):
  GitHub webhook entry point that creates a scan run and starts the pipeline.
- [`server_management/database/db_models.py`](server_management/database/db_models.py):
  PostgreSQL models mirrored or normalized into Exasol.

## System boundary and data flow

### PostgreSQL: operational state

PostgreSQL stores registration and workflow state:

- `servers` and `server_manifests` hold registered repositories and current
  declarations.
- `manifest_history` records versioned operator/static-analysis changes.
- `scan_runs` tracks a push-triggered scan and its lifecycle.
- `rule_analysis_results`, `rule_findings`, and `tool_declarations` store Phase
  1 output.
- `llm_analysis_results` and `tool_behavioral_findings` store Phase 2 output.

The scan pipeline updates PostgreSQL first. Exasol is intentionally
best-effort: a slow or unavailable Exasol connection must not make a scan fail
after its PostgreSQL transaction has committed.

### Exasol: analytical model

The schema is `MCP_ANALYTICS`.

Dimensions:

- `DIM_SERVER`: one row per registered server.
- `DIM_TOOL`: server-scoped tool names. The natural key is
  `(SERVER_ID, TOOL_NAME)` and is maintained by the synchronization code.
- `DIM_ANALYZER`: analyzer names such as SAST, supply-chain, and behavioral
  analyzers.
- `DIM_DATE`: date attributes keyed by `YYYYMMDD`. The schema expects this
  dimension to be populated before dependent facts are useful.

Facts:

- `FACT_STATIC_FINDINGS`: union of rule and LLM findings. `PHASE` distinguishes
  `rule` and `llm`; `SOURCE_TABLE` and `SOURCE_ID` provide drill-through to
  PostgreSQL. Variable-shaped analyzer details are serialized as JSON text in
  `DETAILS`.
- `FACT_RUNTIME_EVENTS`: proxy call audit data. This is landed directly from
  the runtime/egress path rather than copied from PostgreSQL.
- `FACT_RUNTIME_FINDINGS` and `FACT_SESSION`: runtime detector findings and
  completed proxy-session summaries, also landed through the telemetry API.
- `FACT_SCAN_RUN`: one upserted row per scan run, including status and phase
  verdicts. This keeps rejected and infrastructure-failed scans visible even
  when they have no findings.
- `FACT_MANIFEST_HISTORY`: immutable manifest-version audit rows.
- `FACT_TRUST_SCORE`: one daily rollup per server; dashboards should query this
  table rather than recomputing the upstream facts.

Supporting tables:

- `STG_STATIC_FINDINGS` is a narrow staging table used because
  `pyexasol.import_from_iterable` should not be asked to populate the identity
  and default columns on `FACT_STATIC_FINDINGS`.
- `ETL_SYNC_STATE` exists for incremental ETL bookkeeping, although the current
  per-scan sync functions do not use a watermark workflow.

Exasol primary and foreign keys are informational/optimizer metadata rather
than PostgreSQL-style enforced constraints. ETL code is responsible for
idempotency, natural-key handling, and load ordering. Fact tables distribute by
`SERVER_ID`; small dimensions are left without an explicit distribution clause
so Exasol can replicate them.

## Synchronization behavior

`server_management/services/sync.py` uses `pyexasol` and reads connection
settings from the process environment. It provides:

- `sync_rule_phase_findings`: ensures the server and tools exist, writes Phase
  1 findings through the staging table, and preserves SCA reachability in
  `REACHABLE`.
- `sync_llm_phase_findings`: writes behavioral findings into the same static
  findings fact table with `PHASE = 'llm'`.
- `sync_scan_run`: idempotently merges lifecycle status, verdicts, timestamps,
  and duration into `FACT_SCAN_RUN`.
- `sync_latest_manifest_history`: merges the latest PostgreSQL manifest-history
  version into Exasol.

The standalone runtime path uses
`server_management.api.telemetry_api:app`. It deliberately does not import
the PostgreSQL session setup: the proxy can resolve a server and write
runtime events, findings, tools, and sessions when PostgreSQL is unavailable.
Runtime event upserts are keyed by the proxy's stable
`<session>:<request>` event ID, so fire-and-forget retries do not duplicate
calls. The same telemetry router is included in `server_management.api.api`
so the normal application exposes both API surfaces on one port. Run the
standalone telemetry app on a separate port only for a PostgreSQL-free
deployment.

The API path schedules these functions as FastAPI background tasks after the
corresponding PostgreSQL result call. The direct pipeline path is equally
important: `trigger_scan()` calls the recording services in-process, so it
explicitly runs rule/manifest sync and LLM sync using fresh database sessions
via `asyncio.to_thread()`. `scan_pass()` and `scan_fail()` also synchronize
`FACT_SCAN_RUN`.

Sync helpers are best-effort wrappers in the pipeline. They log a failure and
close their session rather than changing the already-committed PostgreSQL
scan outcome.

## Trust-score calculation

[`trust_score.sql`](server_management/exasol/trust_score.sql) is intended to
run daily from an external scheduler such as cron or Airflow; Exasol itself is
not assumed to provide the job scheduler.

Current scoring policy:

- Static and behavioral findings use a 45-day half-life.
- Runtime events use a 3-day half-life and are bounded to the most recent
  90 days for the scan.
- Severity weights are `CRITICAL = 40`, `HIGH = 20`, `MEDIUM = 8`, and
  `LOW = 2`.
- Reachable SCA findings receive a 2x multiplier.
- Runtime destination violations receive a 3x penalty and sensitive-data
  exfiltration flags receive a 5x penalty.
- `SECURITY_SCORE` starts at 100 and is clipped at zero.
- `OPERATIONAL_SCORE` blends weighted success rate, p95 latency against a
  5-second reference, and call-volume confidence.
- `OVERALL_SCORE` is 60% security and 40% operational.

The rollup uses `MERGE` keyed by `(SERVER_ID, DATE_KEY)`, so rerunning the
daily calculation updates the current day's row.

## Operational setup

1. Provision the PostgreSQL database and run the Alembic migrations for the
   server-management tables.
2. Provision Exasol and execute
   [`star.sql`](server_management/exasol/star.sql) in the target database.
3. Populate `DIM_DATE` for the reporting period before relying on date joins
   and score calculations.
4. Configure the Exasol connection environment variables expected by
   `sync.py` (DSN, user, and password) without committing their values.
   Exasol Nano's local self-signed certificate can use the explicit
   `/nocertcheck` DSN suffix for development only; production should use
   certificate validation or a pinned certificate fingerprint.
5. Run the application with the normal API command/container configuration.
6. Schedule `trust_score.sql` after runtime events and scan syncs are expected
   to have landed.

The application also needs its existing PostgreSQL, GitHub, and scanner
configuration. Keep all credentials and API keys in deployment secret
management; this document intentionally contains names and behavior only.

## Failure modes and troubleshooting

- **No scan row in Exasol:** check `sync_scan_run` execution and Exasol
  connectivity. The PostgreSQL scan may still be healthy.
- **No findings:** verify the corresponding phase committed in PostgreSQL,
  then inspect the staging-table load and analyzer/tool dimension lookups.
- **Manifest history missing:** confirm the rule phase completed and that
  `manifest_history` contains a version for the server.
- **Trust score missing or stale:** verify `DIM_DATE`, runtime event dates,
  the external scheduler, and the SQL job's Exasol execution result.
- **Duplicate analytical rows:** inspect natural-key `MERGE` predicates and
  concurrent sync behavior; Exasol does not enforce the declared relational
  constraints.

Do not treat an Exasol outage as evidence that the scan itself failed. First
check PostgreSQL state, then retry or replay the analytical load deliberately.

## Known limitations and next areas

- Runtime event ingestion is represented by the schema but is not implemented
  in the scan synchronization module.
- The current static-finding load is per-scan and the shared staging table
  should be reviewed if multiple workers can sync concurrently.
- Exasol sync failures are logged but are not persisted in an ETL error table
  or retry queue.
- `sync.py` imports `pyexasol`; verify that the deployment dependency manifest
  includes the Exasol driver before building a production image.
- `ETL_SYNC_STATE` is present for a future watermark-based process but is not
  currently integrated.
- The trust-score SQL is a policy artifact: changes to weights, half-lives, or
  score blending should be reviewed as product/data-contract changes, not
  treated as incidental query refactors.

## Warden/Exasol boundary

The `Exasol/` directory is not another MCP server that the registry scans.
It is the Go security runtime that can launch a separate MCP server command,
confine it with gVisor/runsc, drive MCP JSON-RPC requests, observe its
behaviour, and publish telemetry. The Python `server_management` application
owns registration, GitHub scanning, PostgreSQL workflow state, and the HTTP
telemetry contract. Exasol stores the analytical copy of the resulting facts.

The supported runtime path is:

```text
registered source
  -> static scan and capability profile
  -> reviewed/approved profile
  -> warden launches the target MCP command
  -> client or test driver sends MCP requests through warden
  -> warden observes the confined process
  -> telemetry API writes Exasol facts
```

Warden does not monitor arbitrary host processes, Docker containers started
independently with `docker run`, or a server that receives no request. It is
not a passive network scanner. For a private or stdio MCP server, this is
expected: warden must own the process and either receive requests through its
HTTP `/rpc` endpoint, use the console, or drive a request file.

## What warden does before live traffic

Warden has two distinct execution phases:

1. **Learning/profile phase.** `warden-observe` or `warden-launch` runs the
   target without the final enforcement policy and records observed syscalls,
   filesystem paths, network dials, process activity, and MCP responses. The
   request set matters: the default handshake and `tools/list` exercise only
   startup/discovery. They do not prove that every tool or code path was
   exercised.
2. **Enforcing/live phase.** An approved capability profile is compiled into
   confinement rules. `warden-serve` keeps a pool of confined target
   instances, exposes `/rpc`, and attributes observations to each completed
   MCP request. `warden-run` is a finite request-replay command; it is useful
   for tests, not a persistent gateway.

The learning phase is not a proof of safety. It is a measurement pass used to
build a candidate profile. It can miss code paths and, depending on its
network-mode configuration, may run with network access. The profile requires
approval before the strict enforcing commands accept it. The `warden-launch`
fast path intentionally auto-approves and should not be treated as a
production approval workflow.

## What can be extracted

For each observed or completed request, the runtime can collect:

- MCP method/tool name, request identity, response size, latency, failure and
  denial outcome;
- syscalls and denied operations;
- filesystem paths and read/write byte counts;
- network destinations, dial attempts, and network byte counts;
- process spawns and unexpected execution;
- response secret/injection pattern hits;
- declared-versus-actual network destination comparisons;
- session-level totals and behavioural findings;
- discovered tool names, descriptions, and parameter schemas.

The telemetry API maps these to `DIM_TOOL`, `FACT_RUNTIME_EVENTS`,
`FACT_RUNTIME_FINDINGS`, and `FACT_SESSION`. Static analysis separately writes
`FACT_STATIC_FINDINGS`, scan lifecycle rows, and manifest history.

Some fields are intentionally unavailable in the current integration:

- no caller/agent identity (`AGENT_ID` is null);
- no intent decision (`INTENT_MATCH` is null);
- no automatic retries within a request (`RETRY_COUNT` is zero);
- no runtime data when no request reaches the warden;
- no guarantee that an unexercised tool or branch is safe;
- no automatic Docker-container interception.

Per-call trace counters can be temporarily unknown because gVisor trace output
is asynchronous. The final session summary is the more reliable aggregate.

## What the existing tests prove

The Go tests are primarily unit and package-integration tests. They validate
policy compilation, profile generation and approval rules, request attribution,
descriptor/path accounting, syscall and network detectors, audit-chain
integrity, pool lifecycle, registry HTTP delivery, and runsc bundle/hardening
behaviour. The malicious fixture tests exercise expected refusals and
findings.

They do not prove that a real registered GitHub server is continuously
reachable through a production client, that every tool was exercised, or that
Docker traffic is intercepted. A real end-to-end telemetry check requires:

1. an approved profile;
2. a running telemetry API with valid Exasol credentials;
3. a warden-owned target process;
4. at least one real `tools/call` request;
5. an Exasol query against `FACT_RUNTIME_EVENTS`.

## Session lifecycle integration

Registration and static scanning identify a server. Once a scan is eligible,
the API coordinator submits the repository identity, exact commit hash, and
structured launch specification to a separate Warden runner. The runner owns
the repository checkout, learning/profile subprocess, profile storage, and
one long-lived `warden-serve` subprocess per server. It replaces the process
only when the requested commit changes; starting a new session for every tool
call is incorrect.

Approval is a domain event, not merely a process flag: the manifest records
the profile path, approver, approval timestamp, and approved commit so the
trust view can explain which artifact is running. For the current automated
flow, profile generation and approval are performed by the runner and recorded
as `vedika`; this is an automation placeholder, not evidence of human review.
The API stores the runner's profile reference as metadata but does not require
the profile file to be mounted into the API container.

The launch specification must be structured executable plus arguments, not an
HTTP string passed through `shell=True` or `split()`. Repository registration
stores the repository identity and the complete structured runtime command.
The runner is the execution boundary: it checks out the exact commit rather
than receiving a copied source tree from the API. Missing runner configuration,
checkout errors, profile-generation errors, or Warden process failures are
surfaced as reconciliation failures rather than silently launching an
unconfined process.

The scan pipeline does not retain or copy its temporary checkout for Warden.
This is intentional: the runner independently fetches the same repository and
commit, so scan cleanup and Warden execution have separate filesystem
lifecycles.

For private GitHub repositories, the scan exchanges the registered GitHub App
installation identity for a short-lived installation access token. When the
scan reaches the Warden-start transition, that same in-memory token is passed
over the authenticated API-to-runner request. The runner uses it only for its
own clone and exact-commit fetch, through a temporary Git askpass helper. It is
not stored in PostgreSQL, manifests, profiles, Warden process arguments, or
logs, and the helper is removed after checkout. If recovery happens without a
token from the active scan, the API mints a fresh installation token before
submitting the runner request.

The scan and Warden therefore perform two independent pulls of the same
repository state. They do not share a filesystem checkout; the commit hash is
the consistency boundary.

The GitHub webhook's signature and event headers do not contain a reusable Git
installation access token. The webhook supplies installation identity in its
payload; the API exchanges that identity using the App private key before
scanning or asking Warden to fetch. Recovery reconciliation mints a fresh
token when there is no active scan token. This exchange is performed in a
loop-safe helper because startup reconciliation can run while Uvicorn's event
loop is active; it must not call `asyncio.run()` directly from that loop.

Runner network reachability is a separate deployment concern from GitHub
authentication. An error such as `Network is unreachable` means the API
container cannot reach `WARDEN_RUNNER_URL`; it does not mean GitHub rejected
the installation token. The runner must be listening on an address reachable
from the API container, and Docker-to-WSL routing/firewall rules must allow
that port.

The runner has a separate dependency boundary from the API. Its minimal
Python environment is defined by `warden-runner-requirements.txt` and contains
only FastAPI, Uvicorn, HTTPX, and Pydantic. It does not need SQLAlchemy,
PostgreSQL, Exasol, scanner, or API application dependencies.
