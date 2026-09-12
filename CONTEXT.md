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
