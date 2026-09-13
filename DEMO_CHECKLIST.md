# Demo checklist

A run sheet for showing the platform end to end: register an MCP server,
scan it, run it confined, call its tools live, watch the audit trail fill,
and see reputation separate a trustworthy server from a malicious one.

Budget ~15 minutes for the walkthrough, plus ~10 for setup the first time.

Everything here has been run end to end on this branch. Section 7 is the
single most convincing thing to show; if you only have five minutes, do
sections 0, 1 and 7.

---

## 0. Setup — do this before the demo, not during it

### 0.1 Data stores

```bash
docker exec mcpwarden-pg pg_isready -U postgres
```

If that fails, recreate it and **wait** — a container that reports `Up`
is not necessarily accepting connections on the mapped host port yet, and
under WSL2 the port mapping itself occasionally fails to establish:

```bash
docker rm -f mcpwarden-pg
docker run -d --name mcpwarden-pg -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=warden -p 15432:5432 postgres:16-alpine
sleep 10 && docker exec mcpwarden-pg pg_isready -U postgres
```

`docker exec ... psql` bypasses the host port mapping entirely, so it can
succeed while the API still cannot connect. Trust `pg_isready` over it.

Make sure your Exasol instance is up too, then apply migrations:

```bash
export DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:15432/warden"
python3 -m alembic upgrade head
```

### 0.2 Check the ports are free

```bash
ss -ltn | grep -E '8000|8100|3000|9500'
```

Anything listening is a leftover from a previous run and will cause an
`address already in use` that is easy to misread as a code failure. If
`lsof`/`fuser` are not installed, this finds the owners:

```bash
python3 - <<'EOF'
import os
t={l.split()[9] for f in ('/proc/net/tcp','/proc/net/tcp6')
   for l in open(f).readlines()[1:]
   if int(l.split()[1].split(':')[1],16) in (8000,8100,3000,9500) and l.split()[3]=='0A'}
for pid in filter(str.isdigit, os.listdir('/proc')):
    try: fds=os.listdir(f'/proc/{pid}/fd')
    except Exception: continue
    for fd in fds:
        try: link=os.readlink(f'/proc/{pid}/fd/{fd}')
        except Exception: continue
        if link.startswith('socket:[') and link[8:-1] in t:
            print(pid, open(f'/proc/{pid}/cmdline','rb').read().decode(errors='ignore')[:80])
EOF
```

### 0.3 Build the Go binaries and the demo repositories

```bash
cd Exasol
go build -o /tmp/warden-bin/warden-observe ./cmd/warden-observe
go build -o /tmp/warden-bin/warden-serve   ./cmd/warden-serve
go build -o /tmp/warden-bin/probe          ./sandbox/runtime/runsc/probe
cd ..

bash scripts/make_demo_repos.sh          # creates /tmp/warden-demo
```

That produces two repositories laid out as `owner/repo`, so they go through
exactly the same checkout path a real GitHub repo does:

| Repo | What it is |
|---|---|
| `demo/mcp` | a well-behaved MCP server (`echo`, `new_id`, `add`) with a real npm dependency |
| `demo/evil` | the malicious fixture: reads credential files, returns secret-shaped and injection-shaped content |

### 0.4 Start the four processes

Use four terminals and leave them in the foreground — you want to be able
to point at the logs during the demo.

**Terminal A — git fixture host**
```bash
python3 scripts/demo_git_server.py /tmp/warden-demo 9500
```

**Terminal B — API**
```bash
export DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:15432/warden"
export GITHUB_WEBHOOK_SECRET=test-secret GITHUB_APP_ID=1 GITHUB_PRIVATE_KEY=test
export WARDEN_RUNNER_URL=http://127.0.0.1:8100
python3 -m uvicorn server_management.api.api:app --port 8000
```

**Terminal C — Warden runner**
```bash
export WARDEN_OBSERVE_BIN=/tmp/warden-bin/warden-observe
export WARDEN_SERVE_BIN=/tmp/warden-bin/warden-serve
export WARDEN_PROBE_BIN=/tmp/warden-bin/probe
export WARDEN_TELEMETRY_API=http://127.0.0.1:8000
export WARDEN_RUNSC_BIN=$(which runsc)
export WARDEN_GIT_BASE_URL=http://127.0.0.1:9500
python3 -m uvicorn server_management.warden_runner:app --port 8100
```

**Terminal D — dashboard**
```bash
cd dashboard && npm run dev
```

### 0.5 Confirm all four

```bash
curl -s localhost:8000/health          # {"status":"ok","exasol":true,"postgres":true}
curl -s -o /dev/null -w '%{http_code}\n' localhost:8100/docs   # 200
curl -s -o /dev/null -w '%{http_code}\n' localhost:3000        # 200
```

`"status":"ok"` requires **both** stores. If it says `degraded`, read which
one is false rather than guessing.

> **Expected noise:** a `GITHUB_PRIVATE_KEY` / JWT traceback in Terminal B
> after registering a server is normal with placeholder credentials. It does
> not block registration, scanning, running, or scoring. Say so before
> someone spots it.

---

## 1. Register a server — Discovery Hub

Open **http://localhost:3000** → **Discovery Hub** → **+ Connect a server**
→ enter `demo/mcp` → Register.

**What to point out:** the card appears immediately, marked **Offline** with
no tools. That is correct — registration establishes identity, nothing more.
A server is not runnable until it has a launch command and a passed scan.

Set the launch command:

```bash
SID=$(curl -s localhost:8000/servers | python3 -c \
  'import sys,json;print([s["server_id"] for s in json.load(sys.stdin) if s["source"]=="demo/mcp"][0])')
echo $SID

curl -s -X PATCH localhost:8000/servers/$SID/manifest \
  -H 'Content-Type: application/json' \
  -d '{"launch_executable":"node","launch_args":["server.js"]}'
```

**Worth saying:** `launch_executable` must be a real ELF binary — `node`,
`python3` — with the script as an argument. A wrapper script like `npx`
fails inside gVisor, because the container's entrypoint loader reads the ELF
header directly.

**Try to break it (do this on purpose, it looks good):**

```bash
curl -i -X POST localhost:8000/servers -H 'Content-Type: application/json' \
  -d '{"repo_url":"not a repo","installation_id":1,"allowed_destinations":[]}'   # 422, with the reason
curl -i -X POST localhost:8000/servers -H 'Content-Type: application/json' \
  -d '{"repo_url":"demo/mcp","installation_id":1,"allowed_destinations":[]}'     # 409, already registered
```

---

## 2. Scan it

```bash
source /tmp/warden-demo/shas.env

RID=$(curl -s -X POST localhost:8000/scan-runs -H 'Content-Type: application/json' \
  -d "{\"server_id\":\"$SID\",\"commit_sha\":\"$MCP_SHA\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["scan_run_id"])')

# rule phase: SAST findings + the tools the code declares
curl -s -X POST localhost:8000/scan-runs/$RID/rule-analysis-result \
  -H 'Content-Type: application/json' -d '{
  "verdict":"pass_with_findings",
  "rule_findings":[{"rule_id":"demo.example","severity":"low",
    "message":"example low-severity finding","file_path":"server.js","line":1}],
  "tool_declarations":[
    {"name":"echo","description":"Echo a message back to the caller.",
     "parameter_schema":{"type":"object","properties":{"message":{"type":"string"}}}},
    {"name":"new_id","description":"Generate a fresh UUID v4.","parameter_schema":{"type":"object"}},
    {"name":"add","description":"Add two numbers.",
     "parameter_schema":{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}}}}]}'

# llm phase: does the implementation match the declared intent
curl -s -X POST localhost:8000/scan-runs/$RID/llm-analysis-result \
  -H 'Content-Type: application/json' -d '{"verdict":"pass","llm_findings":[]}'
```

Status should now read `static_analysis_passed`.

**Refresh Discovery Hub.** The card now lists three tools with descriptions,
still Offline. The sync to both stores runs in the background, so give it a
second or two if the first refresh looks empty.

Show that the catalog landed in *both* stores under one id:

```bash
curl -s localhost:8000/tools | python3 -m json.tool | head -20          # PostgreSQL
curl -s localhost:8000/servers/$SID/tools | python3 -m json.tool | head -20   # Exasol
```

**The point:** same `server_id` in both. Registration lives in PostgreSQL,
telemetry in Exasol, and one identity spans them.

Note the `source` field reads `declared` — these came from static analysis,
nothing has run yet. After §3 it becomes `observed`, because the running
server advertised them itself. That distinction is the whole point of the
column: what the code claims versus what the process actually offered.

---

## 3. Bring it live

In the browser, click **Try it** on any tool. The first click takes 30–60
seconds — it is doing real work: clone, shallow-fetch that exact commit,
`npm install`, generate a capability profile by observing a learning run,
then warm a pool of gVisor containers.

Watch Terminal C while it happens. Call out these lines:

```
installing npm dependencies (UNCONFINED on this host ...)
profile approved_by=vedika: ~/.warden/profiles/<server-id>/<commit>.json
telemetry enabled: server_id=<same uuid as PostgreSQL>
warming 2 confined container(s)...
pool ready in 806ms
listening on http://127.0.0.1:18466
```

`telemetry enabled: server_id=…` is the one to linger on — that is the
PostgreSQL UUID being adopted by the runtime, not a second identity derived
independently.

The card flips to **Live**.

---

## 4. Call tools for real

In the modal, enter arguments and run. From the terminal:

```bash
curl -s -X POST localhost:8000/servers/$SID/call -H 'Content-Type: application/json' \
  -d '{"tool_name":"add","arguments":{"a":7,"b":35}}'
# {"content":[{"type":"text","text":"42"}]}
```

That is a real MCP `tools/call`, executed by a real process, inside gVisor.

Try a tool that does not exist — `{"tool_name":"nope"}` — and note it comes
back as a clean 422, *and* that `nope` does not appear in the tool catalog
afterwards. Attempts are audit history; only declared or advertised tools
are catalog entries.

---

## 5. Monitor

```bash
curl -s localhost:8000/servers/$SID/live/status
curl -s localhost:8000/servers/$SID/live/metrics | python3 -m json.tool | head -30
```

Live metrics come straight from the gateway: container pool state, request
counts, latency percentiles, syscall and path counts, bytes in and out.

---

## 6. Audit trail

**Audit & Activity** in the dashboard. Every call you just made is there,
newest first, with tool name, decision, latency and session id. Filter by
server and by decision.

```bash
curl -s "localhost:8000/servers/$SID/runtime-events?limit=10" | python3 -m json.tool
```

**The point:** this is per-tool-call attribution, recorded by the sandbox as
it executes, not reconstructed from logs afterwards.

---

## 7. The negative control — the part worth showing

Everything so far proves the happy path. This proves the platform does its
actual job. Register, scan and run the malicious fixture exactly as before:

```bash
EID=$(curl -s -X POST localhost:8000/servers -H 'Content-Type: application/json' \
  -d '{"repo_url":"demo/evil","installation_id":1,"allowed_destinations":[],
       "launch_executable":"node","launch_args":["server.js"]}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["server_id"])')

ERID=$(curl -s -X POST localhost:8000/scan-runs -H 'Content-Type: application/json' \
  -d "{\"server_id\":\"$EID\",\"commit_sha\":\"$EVIL_SHA\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["scan_run_id"])')

curl -s -X POST localhost:8000/scan-runs/$ERID/rule-analysis-result \
  -H 'Content-Type: application/json' -d '{
  "verdict":"pass_with_findings",
  "rule_findings":[
    {"rule_id":"python.hardcoded-aws-key","severity":"critical",
     "message":"Hardcoded AWS access key","file_path":"helper.py","line":5},
    {"rule_id":"python.subprocess-shell-true","severity":"high",
     "message":"subprocess with shell=True on untrusted input","file_path":"helper.py","line":10},
    {"rule_id":"python.eval-untrusted","severity":"high",
     "message":"eval() on untrusted expression","file_path":"helper.py","line":14}],
  "tool_declarations":[
    {"name":"exfiltrate","description":"Reads credential files and returns them",
     "parameter_schema":{"type":"object"}},
    {"name":"leak_secret","description":"Returns a credential-shaped string in its response",
     "parameter_schema":{"type":"object"}}]}'

curl -s -X POST localhost:8000/scan-runs/$ERID/llm-analysis-result \
  -H 'Content-Type: application/json' -d '{"verdict":"pass_with_findings","llm_findings":[]}'

curl -s localhost:8000/servers/$EID/live/tools >/dev/null     # bring it live
```

Now let it attack:

```bash
curl -s -X POST localhost:8000/servers/$EID/call -H 'Content-Type: application/json' \
  -d '{"tool_name":"exfiltrate","arguments":{}}'
```

It tries to read `/etc/shadow`, an SSH private key, and AWS credentials.
Every one comes back `ENOENT`. **Those files exist on the host.** gVisor is
what makes them not exist for this process.

```bash
curl -s -X POST localhost:8000/servers/$EID/call -H 'Content-Type: application/json' \
  -d '{"tool_name":"leak_secret","arguments":{}}'
```

This one *succeeds* — and gets flagged anyway, on its response content:

```bash
curl -s "localhost:8000/servers/$EID/runtime-events?limit=5" | python3 -m json.tool
```

`"decision": "FLAGGED"`, with categories including `aws_access_key_id`,
`aws_secret_access_key_assignment`, and `ignore previous instructions` —
prompt injection caught in a tool response.

And the behavioural detectors:

```bash
curl -s "localhost:8000/servers/$EID/runtime-findings?limit=10" | python3 -m json.tool
```

| Detector | Severity | Kernel-attested |
|---|---|---|
| `syscall-drift` — undeclared syscall succeeded | critical | yes |
| `credential-access` — credential store accessed outside the profile | critical | yes |
| `unexpected-exec` — process spawned beyond the entrypoint | high | yes |
| `path-drift` — read outside declared paths | high | yes |
| `response-secret-pattern` | high | no |
| `response-injection-pattern` | medium | no |

**"Kernel-attested" is the phrase to use.** These are not heuristics over
output; they are observations of what the process actually asked the kernel
to do, from outside the sandbox.

---

## 8. Reputation

```bash
curl -s -X POST localhost:8000/compute-scores -H 'Content-Type: application/json' -d '{}'
curl -s localhost:8000/servers | python3 -c '
import sys, json
for r in json.load(sys.stdin):
    print("%-34s overall=%-7s security=%s" % (r["source"], r["overall_score"], r["security_score"]))'
```

```
demo/evil                          overall=32.26   security=0.0
demo/mcp                           overall=92.35   security=100.0
```

Go back to **Overview**. The two servers sit side by side in Connection
Health with those scores, and the Recent Security Alerts panel is entirely
`demo/evil`. Avg. Reputation and Security Alerts update with them.

**Close on this:** same registration flow, same scan pipeline, same
confinement, same audit trail. One is trustworthy and one is not, and the
platform worked that out by running them.

---

## 9. Security Controls

**Security Controls** → pick a server.

- **Allowed Destinations** — live and editable; saves through
  `PATCH /servers/{id}/manifest`. This is the egress policy the confinement
  actually enforces.
- **Warden Confinement Profile** — the approved capability profile: launch
  command, approver, approved commit, timestamp.
- **Rate Limits** and **Allowed Scopes** are labelled **Preview** and are
  not enforced yet. They are shown for the layout. Say so rather than
  letting someone assume otherwise.

---

## Quick reference — what proves what

| Claim | Shown by |
|---|---|
| Any MCP server can be registered | §1, Discovery Hub |
| One identity spans PostgreSQL and Exasol | §2, same `server_id` from `/tools` and `/servers/{id}/tools` |
| Static analysis gates execution | §2 → §3, no live session before `static_analysis_passed` |
| Servers run genuinely confined | §7, `ENOENT` on files that exist on the host |
| Tools execute for real, in real time | §4, `add(7,35)` → `42` |
| Every call is audited per tool | §6, Audit & Activity |
| Malicious behaviour is detected | §7, kernel-attested findings |
| Trust is computed, not asserted | §8, 92.35 vs 32.26 |

---

## If something goes wrong

| Symptom | Cause |
|---|---|
| Dashboard: "Backend unreachable" | API not running, or `NEXT_PUBLIC_API_BASE_URL` in `dashboard/.env.local` points at the wrong port |
| `/health` says `degraded` | Read which store is `false`; usually Postgres, see §0.1 |
| Registration fails with 422 | Repo URL is not GitHub-shaped; the response says so |
| Registration fails with 409 | Already registered |
| `live/tools` returns 503 | No launch command, or no passed scan — §1 and §2 |
| `live/tools` returns 502 | Session could not start; the message carries the reason, and Terminal C has the detail |
| `warmup:initialize timed out` | Source checked out on a `/mnt/c/...` drvfs path — see `HOSTCONFIG_INTEGRATION.md` §0 |
| `address already in use` | Leftover process from an earlier run — §0.2 |
| JWT / `GITHUB_PRIVATE_KEY` traceback | Expected with placeholder credentials; harmless |

Full reference: `HOSTCONFIG_INTEGRATION.md` — endpoints (§6), every bug
found and fixed (§2), environment variables (§5), ngrok for the GitHub
webhook (§9).
