# Quickstart

```bash
cp .env.example .env      # fill in your Exasol credentials
./warden up
```

That's it. Open **http://localhost:3000**.

`./warden up` is idempotent — anything already listening is left alone. It is
also the right thing to run when something has fallen over: it starts only
what is missing. A cold start takes about 10 seconds once dependencies are
cached, a couple of minutes the very first time.

| Command | What it does |
|---|---|
| `./warden up` | Start everything not already running |
| `./warden status` | What is up, what is not, and backend health |
| `./warden logs api` | Tail a log — `api`, `runner`, `dashboard`, `fixture` |
| `./warden down` | Stop the services (leaves PostgreSQL container up) |
| `./warden reset` | Wipe both data stores — asks first |
| `./warden doctor` | Check prerequisites without starting anything |

## What it starts

| Service | Port | Why |
|---|---|---|
| PostgreSQL | 15432 | Registration, manifests, scan runs (Docker container) |
| API | 8000 | The registry and telemetry API |
| Warden runner | 8100 | Fetches sources, generates capability profiles, runs the confined gateway |
| Dashboard | 3000 | The operations console |
| Git fixture | 9500 | Serves the two demo repositories locally |

Exasol is expected to be running already and is configured through `.env`
— it holds the audit trail, findings and trust scores.

## Prerequisites

`docker`, `python3`, `node`, `npm`, `git`, and `go`. `./warden doctor` checks
them and tells you what is missing.

**gVisor (`runsc`)** is optional but is what makes confinement real. Without
it, registration, scanning, the tool catalogue and the dashboard all work;
servers just cannot be *run* confined. Install:
<https://gvisor.dev/docs/user_guide/install/>

One hard constraint: the checkout must be on a native Linux filesystem. On a
Windows drive mount (`/mnt/c/...` under WSL2) gVisor intercepts every syscall
across a slow filesystem and containers never finish starting. `./warden
doctor` refuses to continue if it detects this.

## First five minutes

1. **Discovery → Connect a server.** Try
   `npm:@modelcontextprotocol/server-memory` — a real, official MCP server.
   The version is resolved and pinned at registration, so the identity names
   an immutable artifact.
2. **Monitoring → Run scan.** Fetches the source and reports what it found.
3. **Monitoring → Start confined session.** Clones or installs, profiles the
   server by watching a learning run, then warms a gVisor container pool.
   The first start takes a minute.
4. **Discovery → Run** on any tool. That is a real MCP call executing inside
   the sandbox.
5. **Audit Trail.** Your call is there. Click the row — it expands into what
   the kernel actually observed while it ran.

To see the platform do its job, register `demo/evil` (the bundled malicious
fixture) and do the same. Its scan fails outright on committed AWS
credentials, and its `exfiltrate` tool is flagged on every call, naming the
credential files it tried to open and the shell it spawned — all of it
refused by confinement.

## Configuration

Everything has a working default; override by exporting before `./warden up`.

| Variable | Default | Purpose |
|---|---|---|
| `EXASOL_DSN` / `EXASOL_USER` / `EXASOL_PASSWORD` | — | Required, in `.env` |
| `WARDEN_API_PORT` | 8000 | API port |
| `WARDEN_UI_PORT` | 3000 | Dashboard port |
| `WARDEN_RUNNER_PORT` | 8100 | Runner port |
| `WARDEN_PG_PORT` | 15432 | PostgreSQL host port |
| `GITHUB_APP_ID` / `GITHUB_PRIVATE_KEY` | dev placeholders | Only needed for private repos and webhooks |

With placeholder GitHub credentials you will see a JWT traceback in the API
log after registering. It is expected and blocks nothing — public repos and
npm packages need no token.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Address already in use` | It is already running. `./warden status`, then leave it alone. |
| Dashboard says the API is down | `./warden logs api` |
| `/health` reports `degraded` | Read which store is `false`; Exasol usually means `.env` |
| A session will not start | `./warden logs runner` — the message names the cause |
| `warmup:initialize timed out` | The checkout is on a Windows/network mount; see above |

Deeper reference: `HOSTCONFIG_INTEGRATION.md` (every endpoint, every
environment variable, every bug found and fixed) and `DEMO_CHECKLIST.md` (a
full guided walkthrough).
