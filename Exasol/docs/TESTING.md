# Running and testing the whole flow from a terminal

Every command below is copy-pasteable. The flow it exercises end to end:

```
source ──► SAST (semgrep)          ──► FACT_STATIC_FINDINGS   (Exasol)
       └─► tool discovery          ──► DIM_TOOL               (Exasol)
                                   └─► server_manifests       (Postgres, optional)
       └─► gVisor confinement ──► per-call audit  ──► FACT_RUNTIME_EVENTS   (Exasol)
                              └─► analyzer findings ─► FACT_RUNTIME_FINDINGS (Exasol)
                              └─► session summary  ──► FACT_SESSION          (Exasol)
                                                   └─► FACT_TRUST_SCORE      (Exasol)
```

## 0. One-time setup

```bash
# Toolchain (already present on this machine)
export PATH="$HOME/.local/bin:$HOME/.local/go/bin:$PATH"

# Exasol connection. The local starter-kit instance:
cd ~/code/Exasol/mcp-server-exasol
cat > .env <<EOF
EXASOL_DSN=127.0.0.1/nocertcheck:8563
EXASOL_USER=sys
EXASOL_PASSWORD=$(cat ~/.exasol-starter-kit/credentials/nano_sys_password)
EOF
chmod 600 .env          # .env is gitignored; never commit it
```

Note the DSN form: the `/nocertcheck` suffix goes **before** the port
(`host/nocertcheck:port`), which is what pyexasol's DSN grammar expects.

Python deps, if not already installed:

```bash
python3 -m pip install --user --break-system-packages \
    pyexasol fastapi "uvicorn[standard]" python-dotenv semgrep
```

Create the schema and the date dimension (idempotent, safe to re-run):

```bash
cd ~/code/Exasol/mcp-server-exasol
set -a; . ./.env; set +a
python3 -m server_management.cli init
python3 -m server_management.cli health
```

Expected:

```
  schema MCP_ANALYTICS ready; DIM_DATE has 400 row(s)
  exasol    ok
  postgres  not configured (optional)
  servers   0
```

## 1. Start the telemetry API

```bash
cd ~/code/Exasol/mcp-server-exasol
set -a; . ./.env; set +a
python3 -m uvicorn server_management.api.telemetry_api:app --port 8000
```

Leave it running. In another terminal, `curl -s localhost:8000/health` should
return `{"status":"ok","exasol":true,"postgres":false}`.

## 2. Run a server under confinement

```bash
cd ~/code/Exasol
./warden
```

Then, at the prompt:

```
load everything                       # official reference MCP server
tools                                 # what it advertises
call echo {"message":"hello"}
call get-sum {"a":4,"b":5}
scan                                  # run every detector now
score                                 # discovery + reputation + audit, read back from Exasol
stop
quit
```

`load` prints `registered with the trust/reputation platform: server_id=…`
once the telemetry service answers. If the service is down, the load still
succeeds — telemetry is best-effort by design and never gates confinement.

## 3. Prove detection works (the positive control)

A clean server reporting "no findings" only means something if a dirty one
reports findings. `testdata/evil-mcp` is a deliberately malicious fixture
that tries to read `/etc/shadow` and `~/.ssh/id_rsa`, write outside its
scratch dir, and spawn a shell — plus a Python file with patterns Semgrep
flags, so it exercises the SAST leg too. See its README for details.

```
load path:testdata/evil-mcp
call exfiltrate {}
call leak_secret {}
```

Wait ~15s (gVisor writes its trace asynchronously — `scan` warns you when a
session is too young to trust), then:

```
scan
score          # or `reputation` — same thing; recomputes the trust score first
stop
```

Expected: every attack refused by the kernel (`ENOENT`, `EROFS`), posture
`QUARANTINE`, and findings like:

```
  critical  syscall-drift          undeclared syscall succeeded          kernel-attested
  critical  credential-access      credential store accessed outside…    kernel-attested
  high      path-drift             read outside declared paths           kernel-attested
  high      unexpected-exec        process spawned beyond the entrypoint kernel-attested
  high      response-secret-pattern response content matched a secret…   heuristic
```

and an audit trail showing the per-call decision:

```
  leak_secret   FLAGGED   1ms  response content matched a secret or injection pattern  sensitive-data
  exfiltrate    ALLOWED  49ms
```

`exfiltrate` reading ALLOWED is correct and worth understanding: the *call*
was allowed to run and returned normally. Its attempts to read `/etc/shadow`
and spawn a shell failed because those paths are not in the container's
mount table at all — the confinement worked by making them not exist, which
is not the same thing as a seccomp denial. What it tried is recorded in the
findings (`credential-access`, `unexpected-exec`), which is where per-call
behaviour belongs. A call only reads FLAGGED/BLOCKED when the kernel refused
operations during it, its response carried secret- or instruction-shaped
content, or the supervisor quarantined its container.

Compare the two servers' reputations, which is the point of the exercise:

```
$ python3 -m server_management.cli compute-scores
    5f8bea2e-…  overall 92.1  security 100.0  operational 80.3   # official server
    3bc2bce5-…  overall 32.1  security   0.0  operational 80.2   # malicious fixture
```

## 4. Inspect what was stored, from the terminal

```bash
cd ~/code/Exasol/mcp-server-exasol
set -a; . ./.env; set +a

python3 -m server_management.cli servers
python3 -m server_management.cli tools     path:testdata/evil-mcp
python3 -m server_management.cli findings  path:testdata/evil-mcp
python3 -m server_management.cli events    path:testdata/evil-mcp
python3 -m server_management.cli sessions  path:testdata/evil-mcp
python3 -m server_management.cli compute-scores
python3 -m server_management.cli score     path:testdata/evil-mcp
```

Any command accepts either the source string or the server UUID — the id is
derived from the source, so both name the same row. Add `--json` to any of
them for machine-readable output.

`score` on the malicious fixture shows security floored, with the breakdown
that explains why — the penalty is itemised rather than a single opaque
number, so "why did this drop" has an answer:

```
    overall          32.1
    security          0.0   (static penalty 0.0, runtime findings 137.0)
    operational      80.2   (success 1.0, p95 41ms, 2 calls)
```

Operational stays high on purpose: the server answered both calls quickly
and without error. §7.2 keeps the two scores separate precisely so that a
fast malicious server cannot outrank a slow safe one — the security score
is what gates admission, and reliability never feeds it.

## 5. Or query the HTTP API directly

```bash
SID=$(python3 -c "import uuid;print(uuid.uuid5(uuid.NAMESPACE_URL,'path:testdata/evil-mcp'))")

curl -s localhost:8000/servers | python3 -m json.tool
curl -s localhost:8000/servers/$SID/tools | python3 -m json.tool
curl -s localhost:8000/servers/$SID/runtime-findings | python3 -m json.tool
curl -s localhost:8000/servers/$SID/runtime-events | python3 -m json.tool
curl -s localhost:8000/servers/$SID/sessions | python3 -m json.tool
curl -s localhost:8000/servers/$SID/trust-score | python3 -m json.tool
curl -s localhost:8000/servers/$SID/summary | python3 -m json.tool   # all of the above in one call
```

`/summary` is the endpoint a dashboard should call for a server page.

## 6. Or query Exasol directly

```bash
python3 - <<'EOF'
import os, ssl, pyexasol
exa = pyexasol.connect(dsn=os.environ["EXASOL_DSN"], user=os.environ["EXASOL_USER"],
                       password=os.environ["EXASOL_PASSWORD"],
                       websocket_sslopt={"cert_reqs": ssl.CERT_NONE})
exa.execute("OPEN SCHEMA MCP_ANALYTICS")
for row in exa.execute("""
    SELECT s.REPO_URL, t.OVERALL_SCORE, t.SECURITY_SCORE, t.RUNTIME_FINDING_PENALTY
    FROM DIM_SERVER s JOIN FACT_TRUST_SCORE t ON t.SERVER_ID = s.SERVER_ID
""").fetchall():
    print(row)
EOF
```

## 7. Verify the tamper-evident audit chain

Exasol holds the queryable copy of the audit trail; the cryptographic one
is warden's own hash-chained log, kept per session under `~/.warden/audit/`.
It deliberately outlives the session — sandbox state is destroyed at `stop`
(§6.2), but a record you cannot check afterwards is not an audit log.

`stop` prints the exact command:

```bash
go build -o /tmp/warden-audit ./cmd/warden-audit
/tmp/warden-audit -verify ~/.warden/audit/sess_<id>.jsonl
```

Expected:

```
chain:        VALID
entries:      18 (7 executions, 6 findings, 1 checkpoints)
head:         sha256:c18f170c0bb698922e09d6a51a831517e4596308790e59924ed11425d94c41a1
every entry hashes to its content and links to its predecessor; every checkpoint signature verifies.
```

Other useful forms: `-tail 20` to read the last entries, `-findings` for
just the behavioural detections, `-json` for machine-readable output.

## 8. Run the test suites

```bash
cd ~/code/Exasol
go build ./... && go vet ./... && gofmt -l . && go test ./...
```

## 9. Turning PostgreSQL on later

Nothing in warden changes. Set `DATABASE_URL`, run the migrations, restart
the telemetry API:

```bash
cd ~/code/Exasol/mcp-server-exasol
export DATABASE_URL=postgresql://user:pass@localhost:5432/mcp
alembic upgrade head
```

`/health` then reports `"postgres": true`, tool discovery starts landing in
`server_manifests` + `manifest_history` alongside Exasol's `DIM_TOOL`, and
`GET /servers/{id}/manifest` starts answering. Reputation and audit stay in
Exasol either way.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `load` says "telemetry service unreachable" | the uvicorn process in step 1 isn't running; the load still works |
| Endpoints 404 after a code change | uvicorn doesn't hot-reload; restart it (or run it with `--reload`) |
| `scan` reports nothing on a server you know is dirty | the trace lag — wait ~15s and re-run; `scan` warns when the session is too young |
| `no trust score computed yet` | run `warden-metrics compute-scores`; it's a batch job, not a live query |
| Per-call `syscall_count` is NULL | expected — the trace hadn't arrived when the call returned. `FACT_SESSION` carries the accurate totals |
| `semgrep ci --supply-chain failed` | Semgrep's SCA scan needs `semgrep login`; the base SAST scan still runs and reports |
