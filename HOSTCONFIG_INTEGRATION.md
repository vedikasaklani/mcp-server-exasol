# Integration handoff: code-functionality → hostconfig

This document is for whoever owns `hostconfig`. It explains what landed on
`code-functionality`, why, what was battle-tested and how, and exactly what's
left for you to do to bring it into `hostconfig`. `hostconfig` itself has not
been touched — everything below lives only on `code-functionality`.

**Status:** the tool-calling + discovery/audit/reputation/telemetry backend is
complete and battle-tested against real MCP servers. The only remaining work
before this is a usable product is frontend integration (see "What's left"
at the bottom).

## 0. Troubleshooting: `warmup:initialize timed out after 30s` / `timed out after 15s waiting for canary handshake`

If `warden_runner.py` logs either of these when starting a session:

```
warden-serve: warm pool (a sandbox that cannot be verified must not serve traffic): pool: warm container 1/2: pool: container sbx_... failed warmup step 1/3: runtime: exec on container sbx_...: runsc: request warmup:initialize to container sbx_... timed out after 30s
warden session exited: server_id=... exit_code=1
```

or

```
runsc: canary handshake with container sbx_...: read handshake line: EOF (stderr: ... cannot read client sync file: waiting for sandbox to start: EOF)
```

**Root cause: the `launch_executable` (and/or the project it lives in) is on
a slow, non-native filesystem — almost always a WSL2 Windows-drive mount
(`/mnt/c/...`, filesystem type `9p`).** This is confirmed, not speculative:
`warmup:initialize` is a real MCP JSON-RPC `initialize` request sent to the
confined process and the code blocks on the container's own stdout
(`sandbox/bridge/bridge.go`'s `Handshake()`, read by
`sandbox/runtime/runsc/runtime.go`) — so this timeout is bounded entirely by
how fast *your* executable starts and answers, not by anything independent
of it. gVisor intercepts every syscall the confined process makes; running a
Python interpreter with a heavy venv (numpy, onnxruntime, fastembed,
huggingface_hub, per `requirements.txt`) from a 9p-backed drvfs mount means
every file read gVisor intercepts during interpreter/import startup pays 9p
network-protocol latency on top of gVisor's own overhead — comfortably
enough to blow through both the 15s canary-handshake budget and the 30s
request-handshake budget.

**Fix:** move the whole project (and recreate any venv you register as a
`launch_executable`) onto a **native Linux path inside WSL** — e.g.
`~/mcp-server-exasol`, not `C:\Users\...\mcp-server-exasol` /
`/mnt/c/Users/.../mcp-server-exasol`. Then register the native-path
interpreter (e.g. `/home/<you>/mcp-server-exasol/.venv/bin/python`) as
`launch_executable`, not the drvfs one.

This branch now catches this class of failure immediately instead of after
a 15–30s hang: `warden_runner.py`'s `ensure_session` runs a preflight check
(`_preflight_native_fs`) on the resolved `launch_executable` path before
doing any checkout/observe/serve work, and raises a `RuntimeError`
naming the exact path and filesystem type (`9p`, `cifs`, `nfs`, etc. —
anything outside a small native allowlist: `ext4`, `ext3`, `ext2`, `xfs`,
`btrfs`, `overlay`, `tmpfs`, `f2fs`, `zfs`) if it's on anything suspect, so
you get an answer in milliseconds via the `POST /sessions/{server_id}` HTTP
response instead of a silent timeout.

If a workload is legitimately slow to start but *is* on a native
filesystem (a genuinely heavy native binary, not a filesystem problem), the
handshake timeout itself is configurable: set `WARDEN_REQUEST_TIMEOUT`
(e.g. `WARDEN_REQUEST_TIMEOUT=90s`) in the environment `warden_runner.py`
runs in, and it's passed through to `warden-serve -request-timeout`. This
does not help the drvfs case above — moving off drvfs is the only real fix
for that — it's for a separate, legitimate "my server is just slow"
scenario.

## 1. What this branch now contains

`code-functionality` used to have an older copy of the Python backend nested
under `Exasol/mcp-server-exasol/`. That copy is gone (superseded). In its
place, at the repo root, matching the layout `hostconfig` already uses:

```
server_management/
  api/
    api.py              # main FastAPI app: registration, manifest, scan-run lifecycle
    telemetry_api.py     # router mounted into api.py: discovery/audit/reputation/telemetry
    githubapp.py         # GitHub webhook -> scan pipeline
    github_auth.py        # GitHub App installation token exchange
    frontend.py           # additional frontend-facing endpoints
    models.py             # Pydantic request/response models
  database/
    db_config.py           # SQLAlchemy engine/session (Postgres, via DATABASE_URL)
    db_models.py            # ORM models + Alembic target metadata
  services/
    onboard_services.py      # registration, manifest, scan-run state machine
    scan_pipeline.py          # SAST + LLM analysis orchestration
    static_analysis.py         # semgrep wrapper
    sync.py                     # Postgres -> Exasol sync (static findings, scan runs, manifests)
    runtime_telemetry.py         # Postgres-free Exasol writer/reader for the runtime/discovery path
    warden_session_manager.py     # talks to warden_runner.py to start/stop a server's sandbox session, tracks its gateway address
    tool_catalog.py                # Postgres mirror of discovered tools, for GET /tools (global dashboard catalog)
  exasol/
    star.sql                      # Exasol schema (MCP_ANALYTICS)
    trust_score.sql                # daily trust-score rollup
  warden_runner.py                  # separate FastAPI service: host-side git checkout + sandbox launch
alembic/, alembic.ini                # Postgres migrations
Dockerfile, .dockerignore
requirements.txt, warden-runner-requirements.txt
scripts/warden_healthcheck.py, .ps1
```

The Go side (`Exasol/cmd/*`, `Exasol/sandbox/*`) is unchanged in structure;
it received the wiring `warden_runner.py` depends on — the `-telemetry-api`
flag on `warden-serve` plus matching updates in `warden-console`,
`warden-observe`, and `sandbox/registry`.

### How the pieces fit together (the tool-call path)

```
operator/webhook → api.py (register server, manifest, scan-run)
                       │
                       ├─ scan_pipeline.py → static_analysis.py (SAST) → sync.py → Exasol (FACT_STATIC_FINDINGS, DIM_TOOL)
                       │
                       └─ warden_session_manager.py → warden_runner.py (host-side: git clone, warden-observe,
                                                        then spawns warden-serve on 127.0.0.1:<port>)
                                                              │
                                             warden-serve IS the live MCP gateway:
                                             every tool call to the registered server flows through it,
                                             gVisor-confined, and it posts runtime events/findings/session
                                             summaries to telemetry_api.py's routes as it goes.
```

`telemetry_api.py`'s router (mounted into `api.py`, so it's one process) is
what makes discovery/audit/reputation queryable — it's the same router a
frontend or `warden-console` talks to.

## 2. Bugs found and fixed during the port

These existed in `hostconfig`'s code already (never exercised end-to-end
before). If `hostconfig` has its own copy of these files, pull this branch's
fixes across rather than re-discovering them:

1. **`runtime_telemetry.py` — `LIMIT` as a bind parameter.** Exasol's `LIMIT`
   clause requires a literal integer; pyexasol binds parameters as quoted
   strings, which Exasol rejects (`non-negative integer value expected in
   LIMIT clause`). Fixed in `get_runtime_events`, `get_runtime_findings`,
   `get_sessions` by interpolating the clamped `int(limit)` directly (safe:
   it's our own validated int, never user text — same pattern the old code
   used).
2. **`trust_score.sql` — `WITH ... MERGE` is invalid Exasol syntax.** A CTE
   can only scope a `SELECT`, not a `MERGE`. Fixed by moving the `WITH`
   clause inside the `MERGE`'s `USING (...)` subquery.
3. **`.isoformat()` calls crashed on TIMESTAMP columns.** pyexasol returns
   `TIMESTAMP` columns as plain `str` by default, not `datetime`. Added an
   `_iso()` helper that handles either shape, used everywhere a timestamp is
   serialized.
4. **`get_trust_score` returned numeric fields as strings.** Exasol
   `DECIMAL` columns come back as strings over the wire (documented
   elsewhere in the same file for other functions, just missed here). Now
   coerced through `_num()`.
5. **`FACT_RUNTIME_FINDINGS` writes 500'd** whenever the live schema
   predates the `FINDING_ID` dedup key hostconfig's schema introduced —
   caught because a fresh Exasol instance seeded long ago (before this
   schema shape existed) had the old `FINDING_KEY`/`DATE_KEY` layout. If
   `hostconfig` deploys against an Exasol instance that's ever run an older
   version of `star.sql`, it will hit the same wall — see §4.
6. **`DIM_DATE` was never seeded anywhere in the ported code.** The old,
   pre-restructure tree had a `server_management/cli.py init` command that
   seeded it (mentioned in `docs/TESTING.md`); that file didn't make it into
   `hostconfig`'s restructure. `trust_score.sql` inner-joins
   `FACT_STATIC_FINDINGS` to `DIM_DATE`, so an empty dimension silently drops
   every static (SAST) finding out of the security score — reputation
   scores would look artificially perfect. Fixed by self-seeding `DIM_DATE`
   (2020-01-01 through ~2031, idempotent) inside `runtime_telemetry.py`'s
   `_connect()`, the same place the existing `EVENT_ID` column-width
   self-heal already lives.
7. **`GET /servers` and `GET /servers/{id}/summary` were missing** from the
   new `telemetry_api.py` router — both existed in the pre-restructure
   telemetry API and are the two endpoints a dashboard landing page needs
   most. Restored, backed by a new `list_servers()` in `runtime_telemetry.py`.
8. **`DIM_TOOL` had no `DESCRIPTION`/`PARAMETER_SCHEMA` columns at all** —
   `GET /servers/{id}/tools` always returned `description: ""` and
   `parameter_schema: {}` for every tool, which is useless for a dashboard
   tool picker that needs to show what arguments a tool takes. Added both
   columns to `star.sql`'s `DIM_TOOL`, and `write_tools()`/`get_tools()`
   now read and write them via a proper `MERGE`.
9. **`warden_runner.py` never told `warden-serve` the canonical `server_id`,
   and the one identity hint it did send never actually arrived.**
   `WARDEN_SERVER_SOURCE`/`WARDEN_SERVER_ID` are read by `warden-serve`'s own
   *host*-side process (`cmd/warden-serve/main.go`, before any confinement)
   to resolve telemetry identity — but `_serve()` was passing
   `WARDEN_SERVER_SOURCE` via `-env`, which only injects environment
   variables into the **confined guest process**, invisible to
   `warden-serve` itself. In practice this meant every server run through
   the real, production `warden_runner.py` path (as opposed to the
   interactive `warden-console`) got a telemetry identity derived from its
   bare executable name (`node`, `python3`, ...) instead of its actual
   registered identity — confirmed empirically: a session registered as
   server X reported `telemetry enabled: server_id=<some unrelated UUID>`,
   and every audit/discovery query against server X's real ID came back
   empty. Fixed by passing both as real subprocess environment variables
   (`env=` on `Popen`, not `-env`) including the new `WARDEN_SERVER_ID`, so
   telemetry now lands under the exact same `server_id` the rest of the API
   uses. **This is the fix that makes the dashboard's audit/reputation
   views show anything at all** for servers launched the real way.
10. **`warden-serve`'s HTTP `/rpc` handler never extracted the tool name
    from the request.** `handleRPC` built its `runtime.ExecRequest` with no
    `ToolName`, so every call made over HTTP (the interface a dashboard or
    any real MCP client uses — `warden-console`'s own equivalent sets
    `ToolName` itself when an operator types `call <tool>`, but nothing did
    the same for HTTP callers) recorded an audit trail entry with an empty
    tool name. Fixed with a small `rpcToolName()` that parses the JSON-RPC
    body for `tools/call` requests.
11. **`warden-serve` never posted tool discovery outside the interactive
    console.** `PostToolDiscovery` was only ever called from
    `warden-console`'s `tools` command; the long-running daemon — the
    production path — captures the exact same `tools/list` response during
    its warmup handshake (that's how it pins the manifest hash, §4.2) but
    never told the telemetry platform about it. A server run through
    `warden_runner.py` therefore never appeared in `GET /servers/{id}/tools`
    or the dashboard's tool catalog at all, no matter how many tools it
    declared. Fixed: `OnWarmupResponse` now parses the tools/list payload
    and posts it once (`sync.Once`) per session.

None of the first seven were Go-side issues; #9-11 are, and are the ones
that actually make real-time execution and discovery show up correctly on
a dashboard for a server run the production way. All confirmed by an
actual end-to-end run (see §6) — not by code review alone.

## 3. Known issues, not fixed (flagging for you)

- **`alembic.ini` has a live-looking Postgres credential hardcoded** in
  `sqlalchemy.url`. It's overridden at runtime by the `DATABASE_URL` env var
  (see `alembic/env.py`), so it's not a functional problem, but a credential
  should not be sitting in a committed file. Rotate it and scrub it from
  history when you get a chance.
- **`server-filesystem` (the official npm MCP filesystem server) fails to
  boot under gVisor** in this dev environment — reproducible
  `runsc: canary handshake ... EOF` — while `server-everything`,
  `server-memory`, and the local test fixtures all boot and run fine. This
  is in the sandbox/runtime layer (unrelated to anything touched in this
  port) and wasn't chased further; worth a look if the filesystem server
  specifically matters to you.
- **SAST (semgrep) fails in this environment** with a `mcp==1.29.0` vs
  installed `mcp 2.2.0` conflict (semgrep's own MCP integration, unrelated
  to this project's MCP client code). It fails gracefully — SAST is
  best-effort by design and doesn't block confinement or telemetry — but
  static findings won't show up until that's resolved in whatever
  environment installs `requirements.txt`.
- `docs/TESTING.md` still references `python3 -m server_management.cli
  init`, a command that no longer exists post-restructure (see bug #6
  above). Worth a doc pass once you've settled on how `hostconfig` wants to
  do first-time schema setup (the self-seeding in `_connect()` now covers
  the same need automatically, so the doc's `init` step can likely just be
  deleted rather than reimplemented).

## 4. If your Exasol instance predates this schema

If `hostconfig`'s Exasol instance has ever run an older version of
`star.sql` (columns get added/renamed there over time, and `CREATE TABLE IF
NOT EXISTS` silently keeps old columns), you'll hit the same class of error
as bugs #5/#6 above on whichever table drifted. Cheapest fix for a
non-production instance: drop and let it recreate itself —

```sql
DROP SCHEMA IF EXISTS MCP_ANALYTICS CASCADE;
```

— then let any of the services below reconnect once; `_connect()` runs
`star.sql` and seeds `DIM_DATE` automatically. For a production instance
with real telemetry you care about, diff the live schema against
`server_management/exasol/star.sql` table by table instead and write a
proper `ALTER TABLE` migration — do not drop it.

## 5. Environment variables

Required by `api.py` / `githubapp.py` (the full registration+scan backend):

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Postgres connection string (SQLAlchemy) |
| `GITHUB_WEBHOOK_SECRET` | validates GitHub push webhook signatures |
| `GITHUB_APP_ID`, `GITHUB_PRIVATE_KEY` | GitHub App installation-token exchange |
| `EXASOL_DSN`, `EXASOL_USER`, `EXASOL_PASSWORD` | Exasol connection |

`telemetry_api.py` alone (mounted into `api.py`, or run standalone) only
needs the three `EXASOL_*` variables — it has no Postgres dependency by
design (best-effort, see `CONTEXT.md`).

Used by `warden_session_manager.py` to reach the host-side runner:

| Variable | Purpose |
|---|---|
| `WARDEN_RUNNER_URL` | base URL of `warden_runner.py` (e.g. `http://127.0.0.1:9100`) |
| `WARDEN_RUNNER_TOKEN` | optional bearer token both sides check |
| `WARDEN_RUNNER_TIMEOUT` | seconds to wait for a session to come up (default 360) |

Required on the machine `warden_runner.py` itself runs on (needs git, runsc,
the built warden binaries — this is why it's a separate process/host from
the API):

| Variable | Purpose |
|---|---|
| `WARDEN_OBSERVE_BIN`, `WARDEN_SERVE_BIN`, `WARDEN_PROBE_BIN` | paths to built Go binaries |
| `WARDEN_TELEMETRY_API` | URL `warden-serve` posts runtime telemetry to (your `api.py`/`telemetry_api.py`) |
| `WARDEN_PROFILE_ROOT` | where capability profiles are cached (default `~/.warden/profiles`) |
| `WARDEN_PORT_BASE` | base port for allocating per-server gateway addresses (default 18000) |
| `WARDEN_APPROVER` | name stamped on auto-approved profiles |
| `WARDEN_RUNNER_TOKEN` | must match the API side if set |
| `WARDEN_RUNSC_BIN` | path to `runsc`, read by `warden-serve` itself |
| `WARDEN_REQUEST_TIMEOUT` | optional; overrides `warden-serve -request-timeout` (default 30s) for a legitimately slow but native-filesystem workload — see §0 |

Optional, static analysis:

| Variable | Purpose |
|---|---|
| `SEMGREP_BIN`, `SEMGREP_APP_TOKEN`, `SEMGREP_SCA_REQUIRED`, `SEMGREP_SCA_TIMEOUT_SECONDS` | semgrep wrapper config |
| `MCP_SCANNER_BIN` | path to cisco-ai mcp-scanner, if used |

## 6. Dashboard API reference

Everything below is served by `api.py` (which mounts `telemetry_api.py`'s
router, so it's one process, one base URL). This is the complete surface a
frontend needs — nothing here requires touching Exasol or Postgres directly.

### Registration & discovery (Postgres-backed, `api.py`)

| Method & path | What it's for |
|---|---|
| `POST /servers` | Register a server (repo URL, allowed destinations, launch command). Kicks off the scan pipeline and a Warden session in the background. |
| `GET /servers/{id}/manifest` | Current manifest: allowed destinations, declared tools, launch command, Warden approval state. |
| `PATCH /servers/{id}/manifest` | Operator edits (e.g. change `launch_executable`) — versioned, restarts the Warden session if the launch command changed. |
| `POST /servers/{id}/warden/approve` / `POST /servers/{id}/warden/profile` | Approve or upload a capability profile by hand, bypassing auto-approval. |
| `GET /tools?server_id=&q=` | **Global tool catalog, Postgres-backed** — every known tool across every registered server, optionally filtered by server or name substring. This is the dashboard's "browse and select a tool" view; it mirrors Exasol's `DIM_TOOL` so it's queryable without touching Exasol, per the explicit requirement that tool info live in Postgres too. |

### Per-server discovery, audit, reputation (Exasol-backed, `telemetry_api.py`)

| Method & path | What it's for |
|---|---|
| `GET /servers` | Every known server plus its latest computed trust score — the landing-page list. |
| `GET /servers/{id}/tools` | This server's known tools (declared + observed), with description and parameter schema — the per-server tool picker. |
| `GET /servers/{id}/runtime-events?limit=` | The audit trail: one row per tool call, with decision, latency, byte counts, destination match, sensitive-data flags. |
| `GET /servers/{id}/runtime-findings?limit=` | Security findings the behavioral analyzer raised (path-drift, syscall-drift, injection patterns, ...), most severe first. |
| `GET /servers/{id}/sessions?limit=` | Per-session summaries — posture, request counts, latency percentiles, findings by severity. |
| `GET /servers/{id}/trust-score` | The latest computed reputation: security score, operational score, overall score, decay-weighted violation/exfil counts. |
| `POST /compute-scores` | Force an immediate rescore (normally a scheduled job — useful right after a session ends). |
| `GET /servers/{id}/summary` | Tools + trust score + last 5 sessions + last 10 findings + last 10 events, in one call — what a server's detail page needs without fanning out. |

### Real-time execution (new, proxies to the live Warden gateway)

This is what makes "select a tool and run it" possible from a dashboard.
Under the hood, each running server has its own `warden-serve` gateway
(started by `warden_runner.py`); these endpoints look up that gateway's
address and proxy to it, starting a session on demand if none is warm yet.

| Method & path | What it's for |
|---|---|
| `GET /servers/{id}/live/status` | Is a gateway actually running for this server right now? `{"running": bool, "address": "host:port" \| null}`. Never starts one — pure status check. |
| `GET /servers/{id}/live/tools` | The server's **live** tool list, straight from its own `tools/list` — the freshest possible answer, as opposed to `GET /servers/{id}/tools`'s historical catalog. Starts a session on demand. |
| `POST /servers/{id}/call` `{"tool_name": "...", "arguments": {...}}` | **Make a real tool call.** Starts a session on demand if needed, forwards the call to the confined process, returns its result (or a 422 with the JSON-RPC error body on failure). The call is recorded to the audit trail automatically — nothing else needs to happen for `GET /servers/{id}/runtime-events` to show it. |
| `GET /servers/{id}/live/metrics` | Live pool/traffic metrics straight from `warden-serve`'s own `/stats` — request counts, container pool state, latency, findings-by-severity gauges. For a real-time monitoring widget; complements the historical `GET /servers/{id}/sessions`. |

A session started on demand this way needs a completed static-analysis pass
and a configured `launch_executable` (`PATCH /servers/{id}/manifest`) — if
neither is ready, these all return `503` with a message saying exactly that,
rather than a confusing timeout.

**Practical note on identity:** everything above only lines up (a server's
audit trail actually shows up under the same `server_id` the registration
API gave it) because of bug fix #9 in §2 — `warden_runner.py` now passes the
real `server_id` through to `warden-serve`. If you ever see a running
session whose telemetry doesn't appear anywhere, that's the first thing to
check.

## 7. How to stand it up and test it (what I actually ran)

This is the exact sequence I used to battle-test this branch. Runtimes
needed: Python 3.11+, Go 1.23+, Docker (for a scratch Postgres — swap for
your real instance), a reachable Exasol instance, Node + `runsc` (gVisor) on
PATH for the sandbox itself.

```bash
cd mcp-server-exasol

# 1. Python deps
pip3 install --user --break-system-packages -r requirements.txt
pip3 install --user --break-system-packages -r warden-runner-requirements.txt

# 2. .env for Exasol (gitignored, not committed)
cat > .env <<'EOF'
EXASOL_DSN=127.0.0.1/nocertcheck:8563
EXASOL_USER=sys
EXASOL_PASSWORD=<your password>
EOF

# 3. A scratch Postgres for api.py's registration/manifest state
docker run -d --name mcpwarden-pg -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=warden -p 15432:5432 postgres:16-alpine

# 4. Migrations
export DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:15432/warden"
python3 -m alembic upgrade head

# 5. Start the full backend (registration + telemetry, one process)
export GITHUB_WEBHOOK_SECRET=test-secret GITHUB_APP_ID=1 GITHUB_PRIVATE_KEY=test
python3 -m uvicorn server_management.api.api:app --port 8000
```

In a second terminal, exercise discovery/audit/reputation/telemetry directly:

```bash
curl -s localhost:8000/health
curl -s -X POST localhost:8000/servers -H 'Content-Type: application/json' -d \
  '{"repo_url":"owner/repo","installation_id":1,"allowed_destinations":[]}'
curl -s localhost:8000/servers                          # discovery list + latest scores
curl -s localhost:8000/servers/<id>/tools                # declared/observed tools
curl -s localhost:8000/servers/<id>/runtime-events        # audit trail
curl -s localhost:8000/servers/<id>/runtime-findings        # security findings
curl -s localhost:8000/servers/<id>/sessions                 # per-session summaries
curl -s localhost:8000/servers/<id>/trust-score                # latest reputation
curl -s localhost:8000/servers/<id>/summary                     # all of the above, one call
curl -s -X POST localhost:8000/compute-scores                    # force a rescore now
```

To actually prove tool calls work end to end against a real, arbitrary MCP
server (this is the interactive console — it's the same code path
`warden-serve` uses when run as a long-lived gateway):

```bash
cd Exasol
export EXASOL_TELEMETRY_API=http://localhost:8000   # tells the console where to report
./warden
```

At the prompt, try any of:

```
load everything                    # official reference server (tools, prompts, resources)
load memory                        # knowledge-graph server — proves genericity
load filesystem                    # sandboxed file access (may not boot in every env — see §3)
load path:testdata/evil-mcp        # deliberately malicious fixture — proves detection works

tools                              # lists whatever the loaded server actually declares
call <tool-name> {"arg":"value"}   # make an arbitrary tool call
scan                               # run every detector now
score                              # discovery + reputation + audit, read back from Exasol
stop
quit
```

What "working" looks like:
- `everything`/`memory`: tool calls return correct JSON-RPC results, posture
  ends `TRUSTED` or a well-explained `QUARANTINE` (the `memory` server
  writes its own data file outside the auto-generated profile's declared
  paths — that's the detector correctly catching real off-profile
  behavior, not a false positive to chase).
- `path:testdata/evil-mcp`: posture `QUARANTINE`, security score `0.0`,
  findings for `path-drift`, `unexpected-exec`, `response-injection-pattern`,
  every dangerous syscall/path attempt shows `ALLOWED` at the JSON-RPC level
  but denied at the kernel (this is correct — see `docs/TESTING.md` §3 for
  why "the call succeeded, the attack didn't" is the expected shape).
- `curl .../servers` afterward shows both servers with clearly separated
  scores (malicious near 30, legitimate near 90+).

### Testing the production path (`warden_runner.py` + real-time `/call`)

The `warden-console` test above proves the sandbox and telemetry work; it
does **not** exercise `warden_runner.py` (the host-side git-checkout
service) or the `/call`/`live/*` HTTP endpoints in §6 — that's the actual
path a dashboard drives. To test that too:

```bash
cd Exasol
go build -o /tmp/warden-bin/warden-observe ./cmd/warden-observe
go build -o /tmp/warden-bin/warden-serve ./cmd/warden-serve
go build -o /tmp/warden-bin/probe ./sandbox/runtime/runsc/probe

export WARDEN_OBSERVE_BIN=/tmp/warden-bin/warden-observe
export WARDEN_SERVE_BIN=/tmp/warden-bin/warden-serve
export WARDEN_PROBE_BIN=/tmp/warden-bin/probe
export WARDEN_TELEMETRY_API=http://127.0.0.1:8000   # your running api.py
export WARDEN_RUNSC_BIN=$(which runsc)
python3 -m uvicorn server_management.warden_runner:app --port 8100
```

In another terminal, start a session the way `warden_session_manager.py`
would (any public git repo with a buildless entrypoint works — no GitHub
token needed for a public HTTPS clone):

```bash
curl -s -X POST http://127.0.0.1:8100/sessions/<server_id> \
  -H 'Content-Type: application/json' -d '{
    "server_id": "<server_id>",
    "repo_url": "https://github.com/<owner>/<repo>",
    "commit_sha": "<full commit sha>",
    "executable": "node",
    "args": ["server.js"]
}'
```

This clones the repo, runs `warden-observe` in learning mode, and starts a
`warden-serve` gateway — the response's `"address"` is where it's listening.
`warden_session_manager.reconcile_server()` does exactly this automatically
once a server has a completed scan and a `launch_executable` set, caching
the address so `api.py`'s `/call`/`live/*` endpoints in §6 can find it
without hitting `warden_runner.py` again. From there:

```bash
curl -s http://localhost:8000/servers/<server_id>/live/status
curl -s http://localhost:8000/servers/<server_id>/live/tools
curl -s -X POST http://localhost:8000/servers/<server_id>/call \
  -H 'Content-Type: application/json' -d '{"tool_name":"<name>","arguments":{}}'
curl -s http://localhost:8000/servers/<server_id>/live/metrics
curl -s http://localhost:8000/servers/<server_id>/runtime-events   # the call you just made, audited
```

I validated this exact sequence end to end with a throwaway single-file
Node MCP server and a local git remote standing in for GitHub (real GitHub
App credentials aren't available in this environment — see §3) — a real
tool call went in through `POST /servers/{id}/call`, came back with the
correct result, and showed up immediately in `runtime-events` under the
right `server_id`, which is what bug fixes #9–11 in §2 were for.

Go side, independently:

```bash
cd Exasol
go build ./...
go test ./...
```

## 8. What's left — next step is frontend integration

Backend-side, this branch is feature-complete for what was asked:

- ✅ **Any MCP server can be loaded and have its tools called**, two ways:
  interactively (`warden-console`, confirmed against 3 distinct real servers
  plus a malicious fixture) and **the real production path** —
  register → `warden_runner.py` clones/observes/serves →
  `POST /servers/{id}/call` makes a live tool call and gets a real result
  back. Verified end to end with a throwaway git-hosted MCP server (§7),
  not just by code review.
- ✅ **Tool discovery lives in both Exasol and Postgres**, as required: a
  server's tools (name, description, full parameter schema) land in
  Exasol's `DIM_TOOL` *and* Postgres's new `discovered_tools` table, kept in
  sync automatically whenever tools are posted, with a global cross-server
  catalog at `GET /tools` for a dashboard's browse-and-select view.
- ✅ **Exasol holds the complete audit trail and reputation**: every tool
  call (`FACT_RUNTIME_EVENTS`, now correctly tagged with the tool name —
  bug #10), every security finding (`FACT_RUNTIME_FINDINGS`), every session
  (`FACT_SESSION`), and the computed trust score (`FACT_TRUST_SCORE`), all
  under the same `server_id` the registration API uses (bug #9) — so a
  dashboard's per-server detail page is one `GET /servers/{id}/summary`
  away.
- ✅ **Real-time execution and monitoring** are new in this pass: `POST
  /servers/{id}/call` to run a tool, `GET /servers/{id}/live/status` and
  `/live/metrics` for a live monitoring widget, `/live/tools` for the
  freshest possible tool list. All proxy to the actual running
  `warden-serve` gateway, starting one on demand if needed. Full reference
  in §6.
- ✅ Registration, manifest, and scan-run lifecycle (`api.py` + Postgres) work
  against a real database and are ready for the GitHub App webhook path once
  real GitHub App credentials are configured (not testable without them —
  everything downstream of registration was verified using synthetic
  registrations and a local git remote instead of a live webhook).

What's not done, and is genuinely next:

1. **Frontend integration.** Nothing here has a UI. §6 is the complete API
   surface a frontend should build against — discovery, audit, reputation,
   real-time execution, monitoring, and the global tool catalog are all
   there and battle-tested.
2. **Real GitHub App credentials**, to exercise the webhook → scan pipeline
   → automatic-reconciliation path for real, end to end in one continuous
   flow, instead of via synthetic `POST /servers` plus a manually-driven
   `warden_runner.py` session as was used here to prove the mechanism works.
3. **A production Exasol schema decision** per §4, if `hostconfig`'s
   instance has history predating this schema.
4. Whatever `hostconfig` needs to actually run `warden_runner.py` on its own
   host (git, runsc, built warden binaries) rather than the same machine as
   `api.py` — the two are already split into separate processes/services for
   exactly this reason.
