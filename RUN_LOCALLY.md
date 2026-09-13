# Run & test locally

Everything below assumes you're in the repo root (`mcp-server-exasol/`).
Prereqs: Python 3.11+, Go 1.23+, Node 20+, Docker, `runsc` (gVisor) on PATH
for live tool calls.

## 1. Install dependencies

```bash
pip3 install --user --break-system-packages -r requirements.txt
pip3 install --user --break-system-packages -r warden-runner-requirements.txt
cd dashboard && npm install && cd ..
```

## 2. Configure `.env` (repo root, gitignored)

```bash
cat > .env <<'EOF'
EXASOL_DSN=127.0.0.1/nocertcheck:8563
EXASOL_USER=sys
EXASOL_PASSWORD=<your Exasol password>
EOF
```

## 3. Start Postgres + Exasol, run migrations

```bash
docker run -d --name mcpwarden-pg -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=warden -p 15432:5432 postgres:16-alpine
# ... and make sure your Exasol instance (e.g. the local nano container) is running

export DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:15432/warden"
python3 -m alembic upgrade head
```

## 4. Start the backend

```bash
export DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:15432/warden"
export GITHUB_WEBHOOK_SECRET=test-secret GITHUB_APP_ID=1 GITHUB_PRIVATE_KEY=test
python3 -m uvicorn server_management.api.api:app --port 8000
```

Check it's up: `curl localhost:8000/health` → `{"status":"ok","exasol":true,...}`

## 5. (Optional, for live tool calls) Start the Warden runner

Needs the Go binaries built once:

```bash
cd Exasol
go build -o /tmp/warden-bin/warden-observe ./cmd/warden-observe
go build -o /tmp/warden-bin/warden-serve ./cmd/warden-serve
go build -o /tmp/warden-bin/probe ./sandbox/runtime/runsc/probe
cd ..

export WARDEN_OBSERVE_BIN=/tmp/warden-bin/warden-observe
export WARDEN_SERVE_BIN=/tmp/warden-bin/warden-serve
export WARDEN_PROBE_BIN=/tmp/warden-bin/probe
export WARDEN_TELEMETRY_API=http://127.0.0.1:8000
export WARDEN_RUNSC_BIN=$(which runsc)
python3 -m uvicorn server_management.warden_runner:app --port 8100
```

Also export `WARDEN_RUNNER_URL=http://127.0.0.1:8100` in the terminal running
`api.py` so registered servers can be automatically reconciled into live
sessions.

## 6. Start the dashboard

```bash
cd dashboard
cp .env.example .env.local   # NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
npm run dev
```

Open **http://localhost:3000**.

## 7. Test it — the fast path

1. **Discovery Hub → "+ Connect a server"** → enter `owner/repo` (any
   GitHub-shaped string works for registration; e.g. `demo/my-server`) →
   Register.
2. It'll show up **Offline** with no tools yet — that's correct, nothing's
   live until it has a launch command and a completed scan.
3. To see it fully working end to end (discovery, live status, real tool
   calls, audit trail, reputation) without needing a real GitHub App or a
   real repo, see `HOSTCONFIG_INTEGRATION.md` §7's "Testing the production
   path" section — it walks through registering a server, setting a launch
   command, starting a session, and calling a tool live, with a
   copy-pasteable example server included.
4. Whatever you do, check it landed everywhere:
   - **Audit & Activity** — the call you just made, with a status badge.
   - `curl localhost:8000/servers/<id>/trust-score` — reputation score.
   - `curl localhost:8000/tools` — the Postgres-backed global tool catalog.

## 8. Shut it down

```bash
docker stop mcpwarden-pg && docker rm mcpwarden-pg
# Ctrl+C the three python/npm processes
```

## Troubleshooting

- **Dashboard shows "Backend unreachable"** → `api.py` isn't running, or
  `NEXT_PUBLIC_API_BASE_URL` in `dashboard/.env.local` doesn't match its port.
- **CORS errors in the browser console** → make sure you're on this branch's
  `api.py` (has `CORSMiddleware`), not an older copy.
- **`warmup:initialize timed out`** when starting a session → see
  `HOSTCONFIG_INTEGRATION.md` §0 (almost always a WSL2 `/mnt/c/...` path
  issue).
- Anything else → `HOSTCONFIG_INTEGRATION.md` is the full reference: every
  endpoint (§6), every bug already found and fixed (§2), every environment
  variable (§5), and the ngrok setup for the GitHub webhook (§9).
