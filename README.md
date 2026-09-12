# MCP Server Registry and Exasol Analytics

This service registers MCP server repositories, scans their source code, stores
scan results in PostgreSQL, and synchronizes analytics data into Exasol.
Exasol is used for analytical queries and daily trust-score calculations; it is
not the operational system of record.

## What the project does

The application supports this workflow:

1. Register an MCP server repository and its allowed network destinations.
2. Receive a GitHub push webhook for the `main` branch.
3. Clone the pushed commit.
4. Run deterministic rule-based analysis and extract declared tools.
5. Run the behavioral LLM analysis when Phase 1 is not rejected.
6. Persist scan lifecycle, findings, manifests, and verdicts in PostgreSQL.
7. Synchronize the committed results into Exasol.
8. Calculate a daily security, operational, and overall trust score.

PostgreSQL remains usable when Exasol is unavailable. Exasol synchronization is
best effort and must not turn an already-committed PostgreSQL scan into a
failed scan.

## Repository layout

### `server_management/api`

- `api.py` defines the FastAPI application and the main HTTP endpoints.
  It handles server registration, manifest reads and updates, scan-run
  creation, and recording Phase 1 and Phase 2 results.
- `githubapp.py` handles GitHub App registration and push webhooks. It verifies
  the webhook signature, accepts only pushes to `main`, creates a scan run,
  and starts the scan pipeline in the background.
- `models.py` contains the Pydantic request and response models used by the
  API.
- `github_auth.py` creates GitHub App installation tokens used to clone
  private repositories.

### `server_management/database`

- `db_config.py` loads `DATABASE_URL`, creates the SQLAlchemy engine and
  session factory, and provides the FastAPI database dependency.
- `db_models.py` defines the PostgreSQL operational model:
  - `Server` and `ServerManifest` store registration and current manifest state.
  - `ManifestHistory` stores versioned manifest changes.
  - `ScanRun` stores scan lifecycle and commit information.
  - `RuleAnalysisResult`, `RuleFinding`, and `ToolDeclaration` store Phase 1
    output.
  - `LlmAnalysisResult` and `ToolBehavioralFinding` store Phase 2 output.
  - `ScanStatus`, `RuleVerdict`, `LlmVerdict`, and `Severity` define the
    allowed workflow values.

### `server_management/services`

- `onboard_services.py` contains registration, manifest, scan-run, and result
  persistence operations for PostgreSQL.
- `static_analysis.py` runs the scanner commands and extracts tool
  declarations from the checked-out repository.
- `scan_pipeline.py` orchestrates cloning, Phase 1, Phase 2, status changes,
  cleanup, and Exasol synchronization calls.
- `sync.py` is the PostgreSQL-to-Exasol integration. It:
  - connects with `pyexasol`;
  - initializes the Exasol schema by executing `server_management/exasol/star.sql`;
  - synchronizes servers, tools, analyzers, findings, scan runs, and manifest
    history;
  - writes failures to logs without changing the PostgreSQL scan result.

### `server_management/exasol`

- `star.sql` creates the `MCP_ANALYTICS` schema and its dimensions, facts,
  staging table, and ETL bookkeeping table. It is idempotent because its
  schema and table statements use `IF NOT EXISTS`.
- `trust_score.sql` calculates the daily trust rollup and merges it into
  `MCP_ANALYTICS.FACT_TRUST_SCORE`.

### Root files

- `Dockerfile` builds and runs the FastAPI service with Uvicorn.
- `requirements.txt` lists Python dependencies, including `pyexasol`.
- `alembic.ini` and `alembic/` contain PostgreSQL migration configuration and
  revisions.
- `.env` contains local secrets and connection settings. It is ignored by Git
  and must not be committed.
- `registry.db` is an old/local SQLite database file. It is not the Exasol
  database and is not used by the current PostgreSQL configuration unless a
  separate process points `DATABASE_URL` at it.

## Data flow

```text
GitHub push to main
        |
        v
GitHub webhook -> create ScanRun in PostgreSQL
        |
        v
scan_pipeline.py
        |
        +--> clone repository at commit
        +--> Phase 1: scanner and tool extraction
        |       |
        |       +--> PostgreSQL rule findings and tool declarations
        |       +--> Exasol Phase 1 synchronization
        |
        +--> Phase 2: behavioral LLM analysis
        |       |
        |       +--> PostgreSQL behavioral findings
        |       +--> Exasol Phase 2 synchronization
        |
        +--> PostgreSQL scan status and verdict update
        +--> Exasol FACT_SCAN_RUN synchronization
```

The API path and the direct in-process pipeline both write PostgreSQL first.
Exasol synchronization runs after the PostgreSQL commit, so Exasol can lag
without losing the operational scan result.

## Exasol model

The Exasol schema is `MCP_ANALYTICS`.

### Dimensions

- `DIM_SERVER`: one row per registered server.
- `DIM_TOOL`: server-scoped tool names.
- `DIM_ANALYZER`: analyzer names used by findings.
- `DIM_DATE`: date attributes keyed by `YYYYMMDD`.

### Facts

- `FACT_STATIC_FINDINGS`: rule and behavioral findings. `PHASE` distinguishes
  `rule` and `llm`.
- `FACT_RUNTIME_EVENTS`: runtime proxy or egress events.
- `FACT_SCAN_RUN`: scan status, verdicts, timestamps, and duration.
- `FACT_MANIFEST_HISTORY`: immutable manifest-version records.
- `FACT_TRUST_SCORE`: daily scores intended for dashboards.

### Supporting tables

- `STG_STATIC_FINDINGS`: staging area used when loading findings while leaving
  identity/default columns to Exasol.
- `ETL_SYNC_STATE`: reserved for incremental ETL bookkeeping.

## Configuration

Create a local `.env` file and provide the required values through deployment
secret management. Do not copy real credentials into this README.

Required groups of settings include:

```text
DATABASE_URL
EXASOL_DSN
EXASOL_USER
EXASOL_PASSWORD
GITHUB_WEBHOOK_SECRET
GITHUB_APP_ID
GITHUB_PRIVATE_KEY
MCP_SCANNER_LLM_MODEL
MCP_SCANNER_LLM_API_KEY
MCP_SCANNER_ENDPOINT
SEMGREP_APP_TOKEN
```

For local Docker Desktop development, the API container cannot use
`localhost` to reach Exasol running in another container or on the host.
Use `host.docker.internal` when Exasol is exposed through Docker Desktop:

```text
EXASOL_DSN=host.docker.internal/<fingerprint>:8563
```

For a non-containerized local API, `localhost/<fingerprint>:8563` can be used
when Exasol is listening on the local machine.

The `/nocertcheck` DSN suffix is acceptable only for a local self-signed
certificate. Production deployments should use certificate validation or a
pinned fingerprint.

## Local setup

### 1. Install dependencies

Use Python 3.12 or a compatible supported version, create a virtual
environment, and install the requirements:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure PostgreSQL and secrets

Set `DATABASE_URL` and the other required values in `.env`. Apply PostgreSQL
migrations:

```powershell
alembic upgrade head
```

### 3. Start Exasol

Start Exasol Nano or another local Exasol instance and ensure its SQL port is
reachable at the host and port in `EXASOL_DSN`.

The first Exasol synchronization automatically executes `star.sql`. No manual
schema bootstrap is required for a fresh instance.

### 4. Start the API

```powershell
uvicorn server_management.api.api:app --host 0.0.0.0 --port 8000
```

Open the FastAPI documentation at `http://localhost:8000/docs`.

## Typical API operations

Register a server through `POST /servers` or the GitHub setup page:

```text
GET /github/setup?installation_id=<github-installation-id>
```

Useful endpoints include:

- `POST /servers`: register a repository.
- `GET /servers/{server_id}/manifest`: read the current manifest.
- `PATCH /servers/{server_id}/manifest`: update allowed destinations.
- `POST /scan-runs`: create an internal scan run.
- `GET /scan-runs/{scan_run_id}`: inspect scan status.
- `POST /github/webhook`: receive GitHub push events.

In normal operation, GitHub pushes to `main` trigger scans automatically after
the webhook is configured and the repository has been registered.

## Trust-score calculation

`sync.py` initializes and populates the Exasol tables, but
`trust_score.sql` is a separate rollup operation. Run it from ExaPlus or an
external scheduler after synchronization has landed:

```sql
OPEN SCHEMA MCP_ANALYTICS;
```

Then execute the contents of `server_management/exasol/trust_score.sql`.

Inspect the result with:

```sql
SELECT
    SERVER_ID,
    DATE_KEY,
    SECURITY_SCORE,
    OPERATIONAL_SCORE,
    OVERALL_SCORE,
    STATIC_PENALTY,
    RUNTIME_VIOLATION_COUNT,
    RUNTIME_EXFIL_FLAG_COUNT,
    SUCCESS_RATE,
    P95_LATENCY_MS,
    TOTAL_CALLS_IN_WINDOW,
    COMPUTED_AT
FROM MCP_ANALYTICS.FACT_TRUST_SCORE
ORDER BY DATE_KEY DESC, OVERALL_SCORE ASC;
```

The current scoring policy uses:

- 45-day half-life for static and behavioral findings.
- 3-day half-life for runtime events, limited to 90 days of input.
- Severity weights of 40, 20, 8, and 2 for critical, high, medium, and low.
- A 2x multiplier for reachable SCA findings.
- A 3x penalty for destination violations.
- A 5x penalty for sensitive-data exfiltration flags.
- A 60% security and 40% operational blend.

`DIM_DATE` must contain the dates referenced by fact rows for the static score
calculation to work correctly.


## Troubleshooting

### `Connection refused` to Exasol

Check where the application is running:

- Host process to local Exasol: use `localhost`.
- Docker container to Exasol published by Docker Desktop: use
  `host.docker.internal`.
- Separate containers on the same Docker network: use the Exasol container
  name or service name and port `8563`.

Also verify that Exasol is running and that port `8563` is published.

### Schema or table does not exist

The synchronization connection executes `star.sql` automatically. If the error
occurs before initialization, check Exasol connectivity first. If initialization
was interrupted, reconnect and retry; the SQL is idempotent.

### PostgreSQL scan succeeds but Exasol is empty

Exasol is best effort. Inspect application logs for synchronization errors,
then check:

```sql
SELECT COUNT(*) FROM MCP_ANALYTICS.DIM_SERVER;
SELECT COUNT(*) FROM MCP_ANALYTICS.FACT_SCAN_RUN;
SELECT COUNT(*) FROM MCP_ANALYTICS.FACT_STATIC_FINDINGS;
SELECT COUNT(*) FROM MCP_ANALYTICS.FACT_TRUST_SCORE;
```

### `FACT_TRUST_SCORE` is empty

Confirm that:

1. `DIM_SERVER` contains a server.
2. Findings or runtime events have been synchronized.
3. `DIM_DATE` contains the needed dates.
4. `trust_score.sql` has been executed after synchronization.

## Security notes

- Keep `.env`, private keys, passwords, and API tokens out of Git.
- Rotate credentials if they have been pasted into logs, chats, screenshots, or
  public repositories.
- Validate GitHub webhook signatures before processing payloads.
- Do not expose the Exasol SQL port publicly for convenience.
- Use certificate validation or a pinned fingerprint outside local development.
