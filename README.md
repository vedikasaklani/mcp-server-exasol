# MCP Server Registry, Confinement, and Exasol Analytics

Any AI agent can point at any MCP server and start calling its tools within
seconds. There is no app-store review, no registry security scan, not even a
changelog — agents cannot read source code before invoking a tool, so the
ecosystem runs on trust with nothing behind it. Static scanners (SAST,
dependency checks) grade code quality once; none of them score the
**behavioral** trust of a live, evolving MCP server over time, and a server
that behaves well for a month can still change.

This project is that missing layer: it registers an MCP server's repository,
re-scans every push to `main`, can run the server confined under **gVisor**
to observe what it actually does, and rolls all of it into a security score,
an operational score, and a blended trust score per server — queryable and
dashboard-ready.

## What the project does

Two analysis layers feed one Exasol-backed scoring engine:

1. **Static, on every push — always on.** A signature-verified GitHub App
   webhook (scoped to `main`, short-lived installation tokens instead of
   static PATs) fires a two-phase scan on every commit:
   - *Deterministic:* Semgrep SAST + supply-chain scanning, vulnerable-package
     detection, and tool-declaration extraction.
   - *Behavioral:* an LLM review comparing what a tool claims to do against
     what its code actually does.

   Findings, manifests, and scan history land in PostgreSQL first, then sync
   into Exasol. This layer needs nothing beyond registering the repo, and it
   never stops — Exasol gets a fresh rollup on every repo change whether or
   not the runtime layer below is ever used.
2. **Runtime, on demand.** Give a registered server a launch command, the
   env vars its own code needs, and a **stdio**-transport entry point (Warden
   drives MCP over stdio, not HTTP), and Warden runs it confined under
   **gVisor**, observing real tool calls — syscalls, network destinations,
   sensitive-data flags — and streams that telemetry into the same Exasol
   facts as the static layer.

PostgreSQL is the operational system of record for both layers. Exasol is
purely analytical for queries and daily trust-score calculations;
synchronization is best effort and must not turn an already-committed
PostgreSQL scan into a failed scan.

## Dashboard

A Next.js console (`dashboard/`) is the operator's view into all of this:
look up any registered server, its scan history, its live confined-session
status, its runtime audit trail, and its current trust score at a glance.
Security and operational scores are shown separately on purpose — a server
can be functionally reliable but security-risky, and that distinction
matters to whoever is deciding whether to connect it.

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
  - `ScanStatus`, `RuleVerdict`, and `LlmVerdict` define the
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
- `FACT_RUNTIME_FINDINGS`: detector findings emitted by the runtime proxy.
- `FACT_SESSION`: completed proxy-session summaries.
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

### Runtime telemetry API

The Go proxy in [`Exasol/`](Exasol/) sends runtime data to the telemetry
routes included in the main API:

```powershell
uvicorn server_management.api.api:app --host 0.0.0.0 --port 8000
```

The main API now exposes the telemetry routes alongside the existing
registration and scan routes: `/health`,
`/servers/resolve`, runtime event/finding/session writes and reads,
`/servers/{server_id}/tools`, `/servers/{server_id}/trust-score`, and
`/compute-scores`. Runtime event writes are idempotent by `event_id`, so the
proxy can retry delivery safely. Keep this API on a private network; do not
expose Exasol port `8563` publicly.

For a PostgreSQL-free telemetry-only deployment, run the standalone app on a
different port:

```powershell
uvicorn server_management.api.telemetry_api:app --host 0.0.0.0 --port 8001
```

When the telemetry API runs on the Windows host, use an Exasol DSN reachable
from the host (typically `localhost`). Use `host.docker.internal` only when
the API process itself runs inside Docker; that hostname is not guaranteed to
resolve from a host PowerShell process.

For local Docker Desktop development, the API container cannot use
`localhost` to reach Exasol running in another container or on the host.
Use `host.docker.internal` when Exasol is exposed through Docker Desktop:

```text
EXASOL_DSN=host.docker.internal/<fingerprint>:8563
```

For a non-containerized local API, `localhost/<fingerprint>:8563` can be used
when Exasol is listening on the local machine.

`Exasol/scripts/watch.sh` starts the telemetry API automatically when
`/health` is unavailable, then passes its URL to `warden-serve`. Set
`WARDEN_TELEMETRY_AUTOSTART=0` when the API is managed separately. Runtime
events are sent asynchronously during calls and drained during shutdown so a
short live run does not lose its final events.

The telemetry path only observes requests that pass through warden:

```text
MCP client -> warden-console or warden-serve/watch.sh -> MCP server -> telemetry API -> Exasol
```

Starting the MCP image separately with `docker run` does not attach it to this
path and cannot populate `FACT_RUNTIME_EVENTS`. The warden launcher executes
the server command it owns; it is not a Docker-container activity collector.
For a runtime smoke test, provide a request file containing at least one real
tool call (not only `initialize` or `tools/list`) and launch the server with
`Exasol/scripts/watch.sh`. After the call completes, verify delivery with:

```sql
SELECT SERVER_ID, EVENT_ID, TOOL_NAME, EVENT_TS, DECISION, STATUS_CODE
FROM MCP_ANALYTICS.FACT_RUNTIME_EVENTS
ORDER BY EVENT_TS DESC
LIMIT 20;
```

The warden process prints either `telemetry enabled: server_id=...` or a
diagnostic containing the telemetry URL and source when server resolution
fails. If the latter appears, fix the API/Exasol configuration before
checking the fact table.

### Registered server launch specification

The registration form accepts the executable and arguments that Warden is
allowed to launch. The values are stored on `server_manifests` as
`launch_executable` and `launch_args`; they are data, not a shell command.
For example:

```json
{
  "launch_executable": "python3",
  "launch_args": ["-m", "my_mcp_server"]
}
```

Apply the migration before registering or updating launch specifications:

```powershell
alembic upgrade head
```

A `launch_executable` intended for the automated runner must be a real binary
on the runner's native Linux filesystem (see the session section above) and
must start an MCP server in **stdio** transport. The warden bridge drives
JSON-RPC over the process's standard input for the warm-up handshake and every
live call; a server launched in `streamable-http` or SSE mode never reads
stdin, so it always times out during warm-up regardless of how fast or native
the environment is. Serve such servers through a stdio-capable entry point
when warden owns them.

To make runtime and static Exasol facts use the same repository identity,
start Warden with the registered canonical repository source:

```bash
export WARDEN_SERVER_SOURCE="owner/repository"
```

The static sync path resolves that same source with `kind=github`. Do not use
the arbitrary executable string as the Warden source when validating the
identity join.

### Automated long-lived Warden sessions

The API is only the coordinator. After a scan reaches an eligible status, it
sends the registered repository, exact scan commit, and structured launch
specification to a separate Ubuntu/WSL Warden runner. The runner clones the
repository, checks out that commit, runs `warden-observe`, records the profile
as approved by `vedika` for now, and keeps one `warden-serve` subprocess per
server. It replaces that subprocess when the approved commit changes.

Configure the API container with the runner URL:

```bash
export WARDEN_RUNNER_URL=http://host.docker.internal:8100
export WARDEN_RUNNER_TOKEN=change-me
```

On Ubuntu/WSL, start the runner on the host that has `runsc`, Warden, and git:

```bash
python3 -m venv /opt/mcp-warden/venv
/opt/mcp-warden/venv/bin/pip install -r warden-runner-requirements.txt
export WARDEN_RUNNER_TOKEN=change-me
export WARDEN_OBSERVE_BIN=/opt/mcp-warden/warden-observe
export WARDEN_SERVE_BIN=/opt/mcp-warden/warden-serve
export WARDEN_PROBE_BIN=/opt/mcp-warden/probe
export WARDEN_PROFILE_ROOT=/var/lib/mcp-warden/profiles
export WARDEN_TELEMETRY_API=http://127.0.0.1:8000
export WARDEN_APPROVER=vedika
/opt/mcp-warden/venv/bin/uvicorn server_management.warden_runner:app --host 0.0.0.0 --port 8100
```

Optional runner timeouts, all in seconds unless noted:

- `WARDEN_OBSERVE_TIMEOUT` (default `300`): wall-clock limit for one
  `warden-observe` run.
- `WARDEN_REQUEST_TIMEOUT`: forwarded to `warden-serve` as
  `-request-timeout`, the per-request/response budget for the warm-up
  handshake and for each live call.
- `WARDEN_INSTALL_TIMEOUT` (default `300`): limit for installing the
  checked-out server's own dependencies.

The runner fetches by repository identity and performs an explicit detached
checkout of the requested SHA. After checkout it installs the server's own
declared dependencies (a root `package.json` or root `requirements.txt`) so a
plain `node index.js` or `python3 -m ...` launch can actually start. That
install runs **unconfined on the runner host**, with this host's full
privileges, and only the detected server process is sandboxed; this is the
same tradeoff `Exasol/sandbox/fetch` documents, and it means repository
credentials or host secrets must never be reachable from a server whose
install step you do not trust. Servers that do not vendor or declare their
dependencies in one of those two files must resolve them through
`launch_executable` itself (a real interpreter binary, not an `npx`/`npm exec`
wrapper).

Before profiling, the runner also checks that the launch executable is on a
native Linux filesystem. A `launch_executable` on a WSL2 Windows-drive mount
(`/mnt/c/...`) or any other slow network/virtio filesystem makes gVisor's
per-syscall interception too slow for the container to start inside the warm-up
window, which shows up as `warmup:initialize timed out after 30s`; the runner
fails fast with that exact explanation. Keep the project (and any venv the
launch executable points at) on a native path such as `~/mcp-server-exasol`.

For private repositories, the API forwards the short-lived GitHub App
installation token obtained for the scan; no static `WARDEN_GIT_TOKEN` is
required. The API never needs the runner's source tree, profile file, `runsc`,
or Warden binaries. `WARDEN_SOURCE_ROOT` is no longer part of the automated
flow. The existing profile-upload endpoint remains a manual fallback, not a
prerequisite for normal registration.

The runner launches `warden-serve` with `WARDEN_SERVER_SOURCE` and
`WARDEN_SERVER_ID` set as **host-side process environment**, not as `-env`
injections. `warden-serve` reads those before confinement to resolve the
server's telemetry identity, so runtime events land under the same server id
the API uses for registration, manifests, and dashboard queries. `-env` only
injects variables into the confined guest and is invisible to `warden-serve`
itself.


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

### Warm pool fails with `warmup:initialize timed out after 30s`

The confined container never answered the MCP `initialize` handshake inside
the warm-up window. Check in this order:

1. **Slow filesystem.** The launch executable (or its venv/interpreter) is on
   a WSL2 Windows-drive mount, `/mnt/c/...`, CIFS, NFS, or FUSE. The runner's
   preflight rejects that before profiling; if you are seeing the raw timeout
   anyway (manual `warden-serve`, or an older runner), move the project and
   its venv to a native Linux path, e.g. `~/mcp-server-exasol`, recreate the
   venv there, and register that path as `launch_executable`.
2. **Transport mismatch.** The server was launched in `streamable-http`/SSE
   mode and never reads stdin, so the handshake request is never consumed.
   Warden drives MCP over stdio; launch a stdio-capable entry point.
3. **Startup work or blocked I/O.** A server that performs slow network work,
   lazy JIT/compile steps, or a blocking connect during startup can consume
   the whole window. Increase `WARDEN_REQUEST_TIMEOUT` and observe the
   container's trace; a stderr of a consistent import crash instead of a
   timeout usually means a missing dependency or an unmet required
   environment variable at import time.

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
