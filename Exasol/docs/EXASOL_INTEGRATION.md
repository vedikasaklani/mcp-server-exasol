# Wiring warden into the Exasol trust/reputation platform

This documents what changed to connect warden (this repo) to
`mcp-server-exasol` (nested checkout, branch `hostconfig`) — a tool
discovery + MCP reputation + audit platform, three pillars:

- **Discovery** — `DIM_TOOL` in Exasol: what tools a server has, sourced
  from both static analysis (`declared`) and warden's own live capture
  (`observed`).
- **Reputation** — `FACT_TRUST_SCORE`: a daily computed trust score
  blending static findings and runtime behavior (`trust_score.sql`,
  pre-existing, unmodified in logic — see the Exasol-side doc for the one
  structural fix it needed).
- **Audit trail** — `FACT_RUNTIME_EVENTS`: one row per tool call, landed
  from warden's own kernel-observed behavior.

`mcp-server-exasol/CONTEXT.md` already named the gap this closes: runtime
event ingestion was schema-only, nothing wrote to it. This also runs
without Postgres or a GitHub App — only the local Exasol instance is
required — because neither this repo's environment nor warden's own load
flow (arbitrary npm/git/path/cmd sources, not just GitHub-App-registered
repos) has either of those available.

## New packages (this repo)

- **`sandbox/sast`** — shells out to `mcp-server-exasol`'s
  `sast_cli.py`, running Semgrep SAST against exactly the source tree
  `sandbox/fetch` already pulled down. Doesn't reimplement Semgrep's
  ruleset in Go; the Python side owns that.
- **`sandbox/registry`** — a best-effort HTTP client for
  `telemetry_api.py`. A nil/disabled client makes every call a no-op, so
  storage being unreachable never affects confinement. Writes are
  fire-and-forget except `Resolve` (needs the id back synchronously,
  short-timeout).

## Changed: `sandbox/bridge.Observer`

Gained optional `Storage`, `ServerID`, `SessionID`, `Networks` fields.
`RequestFinished` now also builds one `registry.RuntimeEvent` per call,
reusing the exact `Window` data already fetched for the audit-log entry
(`sandbox/bridge/bridge.go`'s `emitRuntimeEvent`) — so this can never
disagree with what the local hash-chained audit log recorded. Field
mapping onto `FACT_RUNTIME_EVENTS`:

| Column | Source |
|---|---|
| `DESTINATION_DECLARED`/`ACTUAL`/`MATCH` | `Baseline.Network` vs. the window's actual `Dials` — a coarse mirror of `NetworkDrift`'s verdict, not itself a security decision |
| `SENSITIVE_DATA_FLAG`/`CATEGORIES` | `Window.SecretHits`/`InjectionHits` non-empty |
| `DECISION` | `BLOCKED` on a kernel denial, `FLAGGED` on a sensitive-data hit or undeclared destination, else `ALLOWED` |
| `DECISION_REASON` | the specific reason for the above |
| `LATENCY_MS`/`BYTES_SENT`/`BYTES_RECEIVED` | directly from the call outcome |
| `STATUS_CODE` | warden's own small enum (0/1/2) — **not an HTTP code** |
| `INTENT_MATCH` | always `NULL` — IBAC's job (§5.2), out of v0 scope |
| `AGENT_ID` | always `NULL` — warden doesn't yet know the calling AI client's identity |
| `RETRY_COUNT` | always `0` — warden doesn't retry within a call |

## Changed: `cmd/warden-console`

- `load()` launches a SAST scan concurrently with learning-mode profiling
  (a goroutine, not sequential), scanning the specific package/project
  directory — not an npm install's whole `node_modules` tree, which would
  make every load scan someone else's hundred-odd dependencies.
- Once the profile/baseline exist, it resolves a `server_id` from the
  telemetry service (`registry.Client.Resolve`, synchronous, short
  timeout) and wires it onto the `bridge.Observer`.
- The warmup handshake's `tools/list` capture now also posts to
  `/servers/{id}/tools` as `observed` — the live discovery half.
- New commands: `rescan` (re-run SAST on demand) and `reputation`
  (prints all three pillars, read straight from Exasol via
  `telemetry_api.py`).
- New `set` keys: `sast` (on/off), `storage` (on/off), `exasol-api`
  (base URL, default `http://localhost:8000`).
- `quit`/`stop` wait up to 20s for an in-flight SAST scan before tearing
  down the source directory it's reading, so a scan's result isn't
  silently lost to process exit.

## What gets stored, and where

| Pillar | Table | Written by | When |
|---|---|---|---|
| Discovery | `DIM_TOOL` (+ `server_manifests` in Postgres, optional) | SAST's static extraction (`declared`) and warden's live `tools/list` (`observed`) | at `load` |
| Reputation | `FACT_TRUST_SCORE` | `trust_score.sql` | batch (`warden-metrics compute-scores`) |
| Audit | `FACT_RUNTIME_EVENTS` | `bridge.Observer.RequestFinished` | per tool call |
| Audit | `FACT_RUNTIME_FINDINGS` | `bridge.Observer.OnFinding` | per new/escalated finding |
| Audit | `FACT_SESSION` | `bridge.Observer.PostSession` | at `stop` |
| SAST | `FACT_STATIC_FINDINGS` | `sandbox/sast` via the telemetry API | at `load`, async |

Two deliberate choices in there:

- **Per-call sandbox counters are NULL, not 0, when the trace hasn't
  arrived.** gVisor writes its debug log asynchronously, so a call's
  syscalls usually aren't parsed by the time the call returns. NULL says
  "unknown"; 0 would assert the call touched nothing. `FACT_SESSION`,
  written at teardown after the lag, carries the accurate totals.
- **`KERNEL_ATTESTED` is stored per finding** and the trust score halves
  the weight of anything without it. §7.2's whole argument is that a
  statistical judgement must not weigh the same as a kernel-attested fact,
  and that distinction has to survive the trip into the warehouse to mean
  anything.

Event ids are `<session>:<request>`, because request ids restart at
`req_000001` every session — without the prefix a second session's calls
collide with the first's and the upsert silently keeps the older row.

## Reputation scoring

`trust_score.sql` gained one term: a runtime-findings penalty on the same
3-day half-life as runtime events, severity-weighted, halved for
non-kernel-attested findings. Before it, a server could fail every
behavioural detector at runtime and still score 100 on security, because
only SAST findings and destination/exfil rates fed the number. Verified
against both controls: the official reference server scores security 100,
the malicious fixture scores 0.

`RUNTIME_FINDING_PENALTY` is stored alongside `STATIC_PENALTY` for the same
"why did this drop" reason the original design kept the latter.

## Local setup

1. `mcp-server-exasol` checked out at `../mcp-server-exasol` relative to
   this repo (it already is — nested inside this same directory).
2. `python3 -m uvicorn server_management.api.telemetry_api:app --port 8000`
   running, with `EXASOL_DSN`/`EXASOL_USER`/`EXASOL_PASSWORD` set (`.env`
   in that repo, gitignored).
3. `semgrep` and `python3` on `PATH`.
4. `./warden`, then `load <server>` — `reputation` shows what landed.

See `mcp-server-exasol/CONTEXT.md` for the Exasol-side half of this (schema
changes, the Postgres-free write path, the CTE/MERGE fix trust_score.sql
needed).

## Known gaps (fast-follow, not blocking)

- No background rescan-on-change loop yet (`rescan_scheduler.py`) — only
  the on-demand `rescan` console command. The schema tracks
  `LAST_SCANNED_REF` so this is a pure addition, not a rework.
- `AGENT_ID`/`INTENT_MATCH` are placeholders until there's a calling-client
  identity and an IBAC intent layer, respectively.
- Semgrep's supply-chain (SCA) scan needs `semgrep login`; without it,
  every SAST run reports that step's failure in `Report.Error` and still
  returns whatever the base SAST scan and tool-declaration extraction
  found.
