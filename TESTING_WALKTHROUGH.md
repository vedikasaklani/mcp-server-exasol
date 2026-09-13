# Full testing flow: connect → exercise → monitor → scan → audit → reputation

One continuous walkthrough exercising every piece of the system, in order.
Follow `RUN_LOCALLY.md` first — this assumes Postgres, Exasol, `api.py`
(port 8000), `warden_runner.py` (port 8100), and the dashboard
(`localhost:3000`) are all already running.

Every step below shows the **dashboard** action and the **equivalent curl**,
so you can do this either through the UI or a terminal. `$SID` is the
server's ID from the register step — export it once you have it and every
later command just works.

---

## 1. Connect an MCP server

You need something real to register and run. The guaranteed-working example
(no build step, uses a real npm dependency) — save these two files anywhere,
push them to a throwaway GitHub repo you own:

**`server.js`**
```js
#!/usr/bin/env node
const { v4: uuidv4 } = require('uuid');
let buf = '';
process.stdin.on('data', (chunk) => {
  buf += chunk;
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    let msg; try { msg = JSON.parse(line); } catch { continue; }
    if (msg.method === 'initialize') {
      respond(msg.id, { protocolVersion: '2025-06-18', capabilities: { tools: {} },
        serverInfo: { name: 'demo-mcp-server', version: '1.0.0' } });
    } else if (msg.method === 'tools/list') {
      respond(msg.id, { tools: [
        { name: 'new_id', description: 'Generate a UUID',
          inputSchema: { type: 'object', properties: {} } },
        { name: 'add', description: 'Add two numbers',
          inputSchema: { type: 'object', properties: { a: { type: 'number' }, b: { type: 'number' } }, required: ['a','b'] } },
      ]});
    } else if (msg.method === 'tools/call') {
      const { name, arguments: args } = msg.params;
      if (name === 'new_id') respond(msg.id, { content: [{ type: 'text', text: uuidv4() }] });
      else if (name === 'add') respond(msg.id, { content: [{ type: 'text', text: String(Number(args.a) + Number(args.b)) }] });
      else respond(msg.id, { error: { code: -32601, message: 'unknown tool: ' + name } });
    } else if (msg.id !== undefined) {
      respond(msg.id, {});
    }
  }
});
function respond(id, result) {
  const key = result.error ? 'error' : 'result';
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, [key]: result[key] || result }) + '\n');
}
```

**`package.json`**
```json
{ "name": "demo-mcp-server", "version": "1.0.0", "dependencies": { "uuid": "^9.0.0" } }
```

**Dashboard:** Discovery Hub → **+ Connect a server** → enter `owner/repo` →
Register.

**curl:**
```bash
SID=$(curl -s -X POST http://localhost:8000/servers -H 'Content-Type: application/json' -d '{
  "repo_url": "owner/repo",
  "installation_id": 1,
  "allowed_destinations": []
}' | python3 -c "import json,sys; print(json.load(sys.stdin)['server_id'])")
echo $SID
```

It now exists in Postgres (`servers`, `server_manifests`) but is **Offline**
— nothing runs until it has a launch command and a completed scan.

---

## 2. Set its launch command

**Dashboard:** Security Controls → pick the server → the launch command
lives on the manifest (set via the API for now; a manifest-edit UI panel is
a natural next add).

**curl:**
```bash
curl -s -X PATCH http://localhost:8000/servers/$SID/manifest -H 'Content-Type: application/json' -d '{
  "allowed_destinations": [],
  "launch_executable": "node",
  "launch_args": ["server.js"]
}'
```

---

## 3. Run a scan (static analysis)

This is the "scan" step — populates declared tools and static findings in
both Postgres and (via background sync) Exasol. In production this runs
automatically off a GitHub push webhook (`githubapp.py`); without real
GitHub App credentials, drive the same three endpoints it calls directly:

```bash
COMMIT=$(git ls-remote https://github.com/owner/repo HEAD | cut -f1)

RUN_ID=$(curl -s -X POST http://localhost:8000/scan-runs -H 'Content-Type: application/json' \
  -d "{\"server_id\":\"$SID\",\"commit_sha\":\"$COMMIT\"}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['scan_run_id'])")

# Phase 1: rule-based static analysis + declared tools
curl -s -X POST "http://localhost:8000/scan-runs/$RUN_ID/rule-analysis-result" -H 'Content-Type: application/json' -d '{
  "verdict": "pass",
  "rule_findings": [],
  "tool_declarations": [
    {"name": "new_id", "description": "Generate a UUID", "parameter_schema": {"type": "object"}},
    {"name": "add", "description": "Add two numbers", "parameter_schema": {"type": "object"}}
  ]
}'

# Phase 2: behavioral/LLM analysis
curl -s -X POST "http://localhost:8000/scan-runs/$RUN_ID/llm-analysis-result" -H 'Content-Type: application/json' -d '{
  "verdict": "pass",
  "llm_findings": []
}'
```

Status is now `static_analysis_passed` — ready to run live. Check:
```bash
curl -s http://localhost:8000/servers/$SID/manifest   # tool_declarations now populated
docker exec mcpwarden-pg psql -U postgres -d warden -c "SELECT name FROM tool_declarations WHERE server_id='$SID';"
```

---

## 4. Bring it live

Normally automatic (`PATCH .../manifest` above already queued a background
reconcile). If `WARDEN_RUNNER_URL` is set on `api.py`'s process and a
GitHub App is configured, it just works. Without real GitHub credentials,
drive the runner directly (see `HOSTCONFIG_INTEGRATION.md` §7 for the full
recipe, including standing up a local git remote if you're not using a real
GitHub repo):

```bash
curl -s -X POST "http://127.0.0.1:8100/sessions/$SID" -H 'Content-Type: application/json' -d "{
  \"server_id\": \"$SID\",
  \"repo_url\": \"https://github.com/owner/repo\",
  \"commit_sha\": \"$COMMIT\",
  \"executable\": \"node\",
  \"args\": [\"server.js\"]
}"
```

**Dashboard:** refresh Discovery Hub — the server card now shows **Live**.

```bash
curl -s http://localhost:8000/servers/$SID/live/status   # {"running": true, "address": "..."}
```

---

## 5. Exercise its functionality — call tools across the board

**Dashboard:** Discovery Hub → the server's card → **Try it** next to each
tool → enter arguments → Call tool → see the real result.

**curl**, exercising every tool it declares:
```bash
curl -s -X POST http://localhost:8000/servers/$SID/call -H 'Content-Type: application/json' \
  -d '{"tool_name":"new_id","arguments":{}}'

curl -s -X POST http://localhost:8000/servers/$SID/call -H 'Content-Type: application/json' \
  -d '{"tool_name":"add","arguments":{"a":12,"b":30}}'

# an unknown tool, to see error handling
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8000/servers/$SID/call \
  -H 'Content-Type: application/json' -d '{"tool_name":"nope","arguments":{}}'   # 422

# the live, freshest tool list straight from the running process
curl -s http://localhost:8000/servers/$SID/live/tools
```

Every one of these calls is recorded to the audit trail automatically —
nothing else to do for step 7.

---

## 6. Monitor it in real time

**Dashboard:** Overview page — "Live Sessions" count, per-server status in
"Connection Health".

**curl:**
```bash
curl -s http://localhost:8000/servers/$SID/live/status    # is it up right now
curl -s http://localhost:8000/servers/$SID/live/metrics    # pool size, request counts, finding gauges
```

`live/metrics` is the real-time one — pool state, `warden_requests_total`,
uptime, live finding counters straight from the running `warden-serve`
gateway. `GET /servers/$SID/sessions` (below) is the historical counterpart
once a session ends.

---

## 7. Review audit outputs

**Dashboard:** Audit & Activity Logs — filter by server, by status
(Allowed/Flagged/Blocked), or search by tool name.

**curl:**
```bash
curl -s "http://localhost:8000/servers/$SID/runtime-events?limit=50" | python3 -m json.tool
curl -s "http://localhost:8000/servers/$SID/runtime-findings?limit=20" | python3 -m json.tool
curl -s "http://localhost:8000/servers/$SID/sessions?limit=10" | python3 -m json.tool
```

You should see one `runtime-events` row per call from step 5, each with
`tool_name`, `decision`, `latency_ms`. `runtime-findings` will be empty for
this benign example — see step 9 for what a real finding looks like.

**In Exasol directly**, if you want to see the raw fact tables:
```sql
SELECT TOOL_NAME, DECISION, LATENCY_MS, EVENT_TS
FROM MCP_ANALYTICS.FACT_RUNTIME_EVENTS e
JOIN MCP_ANALYTICS.DIM_TOOL t ON t.TOOL_KEY = e.TOOL_KEY
WHERE e.SERVER_ID = '<SID>' ORDER BY EVENT_TS DESC;
```

---

## 8. Check reputation

```bash
curl -s -X POST http://localhost:8000/compute-scores   # force a rescore now (normally scheduled)
curl -s http://localhost:8000/servers/$SID/trust-score | python3 -m json.tool
curl -s http://localhost:8000/servers | python3 -m json.tool   # every server's latest score, side by side
```

**Dashboard:** Overview → "Avg. Reputation" card; Discovery Hub → each
card's Reputation/Security numbers.

A clean server with no findings should land around `security_score: 100,
overall_score: ~90+`.

---

## 9. Prove detection actually works (negative control)

Everything above uses a well-behaved server. To see the security/reputation
machinery actually catch something, run the deliberately malicious test
fixture through the interactive console (separate from the dashboard/API
path, but the same underlying sandbox and telemetry):

```bash
cd Exasol
export EXASOL_TELEMETRY_API=http://localhost:8000
./warden
```

At the prompt:
```
load path:testdata/evil-mcp
call exfiltrate {}
call leak_secret {}
scan
score
stop
quit
```

Expected: posture `QUARANTINE`, `security_score: 0.0`, findings like
`path-drift`, `unexpected-exec`, `response-injection-pattern` — every
dangerous operation attempted but blocked at the kernel level. Refresh the
dashboard afterward: this server now appears in Discovery Hub with a red/low
reputation, and its findings show up in Audit & Activity and on Overview's
"Recent Security Alerts". This is the clearest side-by-side proof the whole
pipeline works: two servers, one trusted (~90+), one quarantined (~30 or
lower), both computed the same way.

---

## 10. Security Controls

**Dashboard:** Security Controls → pick a server → add/remove an allowed
destination → **Save policy**.

```bash
curl -s -X PATCH http://localhost:8000/servers/$SID/manifest -H 'Content-Type: application/json' \
  -d '{"allowed_destinations": ["api.example.com"]}'
```

Rate limits and allowed-scopes panels are intentionally marked "Preview" —
real UI, no backend enforcement behind them yet.

---

## Quick reference: what proves what

| You want to see... | Look at |
|---|---|
| A server exists and its tools | Discovery Hub, or `GET /tools` / `GET /servers/{id}/tools` |
| It's actually running right now | `GET /servers/{id}/live/status` |
| A tool call actually worked | `POST /servers/{id}/call` response body |
| That call was recorded | Audit & Activity, or `GET /servers/{id}/runtime-events` |
| Security findings from running it | `GET /servers/{id}/runtime-findings` |
| Live resource/traffic stats | `GET /servers/{id}/live/metrics` |
| Overall trust | `GET /servers/{id}/trust-score`, Overview page |
| Everything about one server at once | `GET /servers/{id}/summary` |
