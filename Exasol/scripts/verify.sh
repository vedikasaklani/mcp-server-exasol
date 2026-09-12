#!/usr/bin/env bash
# End-to-end verification for the mcp-warden sandbox.
#
# Runs the full pipeline against a real MCP server under real gVisor
# confinement: unit tests, race detector, kernel-level integration tests,
# observe -> profile -> approve -> enforce, and a live load test against
# the always-on daemon.
#
# Usage:  sudo ./scripts/verify.sh [path-to-mcp-server-entrypoint]
#
# Requires: go, runsc, and root (this host's runsc needs real root; see
# the notes in sandbox/runtime/runsc/runtime_integration_test.go).

set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

SERVER_JS="${1:-/home/neal/mcp-test-servers/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js}"
SERVED_DIR="${SERVED_DIR:-/tmp/mcp-served-dir}"
WORK="$(mktemp -d /tmp/warden-verify-XXXXXX)"
BIN="$WORK/bin"
mkdir -p "$BIN"

PASS=0; FAIL=0
declare -a FAILURES=()

ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); FAILURES+=("$1"); }
head_() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
note() { printf '        %s\n' "$1"; }

cleanup() {
  if [[ -n "${SERVE_PID:-}" ]]; then
    kill "$SERVE_PID" 2>/dev/null
    wait "$SERVE_PID" 2>/dev/null
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---------------------------------------------------------------- build
head_ "build"
if go build ./... 2>"$WORK/build.err"; then ok "go build ./..."; else bad "go build ./..."; cat "$WORK/build.err"; fi
if go vet ./... 2>"$WORK/vet.err"; then ok "go vet ./..."; else bad "go vet ./..."; cat "$WORK/vet.err"; fi
if [[ -z "$(gofmt -l . 2>/dev/null)" ]]; then ok "gofmt clean"; else bad "gofmt clean ($(gofmt -l . | tr '\n' ' '))"; fi

go build -o "$BIN/warden-observe" ./cmd/warden-observe || bad "build warden-observe"
go build -o "$BIN/warden-run"     ./cmd/warden-run     || bad "build warden-run"
go build -o "$BIN/warden-serve"   ./cmd/warden-serve   || bad "build warden-serve"
go build -o "$BIN/warden-audit"   ./cmd/warden-audit   || bad "build warden-audit"
CGO_ENABLED=0 go build -o "$BIN/probe" ./sandbox/runtime/runsc/probe || bad "build probe (static)"
[[ -x "$BIN/probe" ]] && ok "binaries built"

# ------------------------------------------------------------ unit tests
head_ "unit tests"
if go test ./... >"$WORK/test.log" 2>&1; then ok "go test ./..."; else bad "go test ./..."; tail -30 "$WORK/test.log"; fi
if go test -race ./sandbox/... >"$WORK/race.log" 2>&1; then ok "go test -race ./sandbox/... (no data races)"; else bad "race detector"; tail -30 "$WORK/race.log"; fi

# ----------------------------------------------------- kernel integration
head_ "kernel integration (real gVisor)"
if ! command -v runsc >/dev/null; then
  bad "runsc not found on PATH"
else
  if go test ./sandbox/runtime/runsc/... -run Integration -v >"$WORK/integ.log" 2>&1; then
    ok "seccomp/mount/landlock integration tests"
    grep -E "FLAG #[23]" "$WORK/integ.log" | sed 's/^ *//' | while read -r l; do note "$l"; done
  else
    bad "integration tests"; tail -40 "$WORK/integ.log"
  fi
fi

# --------------------------------------------------------------- fixtures
mkdir -p "$SERVED_DIR"
echo "hello from a served file" > "$SERVED_DIR/hello.txt"
mkdir -p /tmp/mcp-secret-dir && echo "top secret" > /tmp/mcp-secret-dir/secret.txt

cat > "$WORK/requests.jsonl" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warden-verify","version":"0.1"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"/tmp/mcp-served-dir/hello.txt"}}}
EOF

# A coherent single session for latency measurement: initialize once, then
# repeat an idempotent call. Replaying `initialize` against an already
# initialized server is a protocol error, so it must not be the thing we
# time.
{
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"warden-verify","version":"0.1"}}}'
  for i in $(seq 2 40); do
    echo "{\"jsonrpc\":\"2.0\",\"id\":$i,\"method\":\"tools/list\",\"params\":{}}"
  done
} > "$WORK/requests-load.jsonl"

# -------------------------------------------------------- observe/profile
head_ "observe -> candidate profile"
if [[ ! -f "$SERVER_JS" ]]; then
  bad "MCP server not found at $SERVER_JS"
else
  if "$BIN/warden-observe" -requests "$WORK/requests.jsonl" -rollup-depth 5 \
      -write-path "$SERVED_DIR" -tool-name filesystem_server \
      -emit-profile "$WORK/profile.json" -top 3 \
      -- node "$SERVER_JS" "$SERVED_DIR" >"$WORK/observe.log" 2>&1; then
    ok "observed a real MCP server under gVisor"
    note "$(grep -E 'syscalls granted|read paths|write paths' "$WORK/observe.log" | tr -s ' ' | tr '\n' ' ')"
  else
    bad "observe run"; tail -20 "$WORK/observe.log"
  fi

  if [[ -f "$WORK/profile.json" ]]; then
    # The generated profile must be UNAPPROVED and therefore unusable.
    if "$BIN/warden-run" -profile "$WORK/profile.json" -probe "$BIN/probe" \
         -- node "$SERVER_JS" "$SERVED_DIR" >"$WORK/unapproved.log" 2>&1; then
      bad "an UNAPPROVED profile was accepted (human review gate broken)"
    else
      grep -q "approved_by" "$WORK/unapproved.log" && ok "unapproved profile refused (§3.2 review gate holds)" \
        || bad "unapproved profile refused for the wrong reason: $(tail -1 "$WORK/unapproved.log")"
    fi

    # No whole-system-tree grants may survive generation.
    if python3 - "$WORK/profile.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1])); t=p['tools'][0]['filesystem']
broad={'/','/home','/root','/etc','/usr','/var','/tmp'}
bad=[x for x in t['read']+t['write'] if x in broad]
sys.exit(1 if bad else 0)
PY
    then ok "no broad system-root grants in generated profile"
    else bad "generated profile grants a whole system tree"; fi

    # The ELF interpreter must be present or nothing can exec.
    grep -q "ld-linux" "$WORK/profile.json" && ok "ELF interpreter included in profile" \
      || bad "ELF interpreter missing from profile"

    # The generated profile must pin what it observed, interpreter
    # included — the interpreter appears in no trace, so nothing else
    # covers it.
    if python3 - "$WORK/profile.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1])); e=p.get('entrypoint') or {}
print(f"        entrypoint  {e.get('path','?')}")
print(f"          binary      {e.get('sha256','MISSING')}")
print(f"          interpreter {e.get('interpreter','-')} {e.get('interpreter_sha256','')}")
sys.exit(0 if e.get('sha256') and e.get('interpreter_sha256') else 1)
PY
    then ok "entrypoint and ELF interpreter pinned by digest in the profile"
    else bad "profile does not pin the entrypoint digest"; fi

    python3 - "$WORK/profile.json" "$WORK/approved.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1])); p['approved_by']='operator:verify'
json.dump(p,open(sys.argv[2],'w'),indent=2)
PY
    ok "operator approved the profile"
  fi
fi

# --------------------------------------------------------- enforced run
head_ "enforced run (kernel confinement)"
if [[ -f "$WORK/approved.json" ]]; then
  if "$BIN/warden-run" -profile "$WORK/approved.json" -probe "$BIN/probe" \
      -requests "$WORK/requests-load.jsonl" -iterations 1 -json \
      -- node "$SERVER_JS" "$SERVED_DIR" >"$WORK/run.json" 2>"$WORK/run.err"; then
    ok "real MCP server ran under full confinement"
    python3 - "$WORK/run.json" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]))
def ms(ns): return f"{ns/1e6:.2f}ms"
print(f"        canary denied: {m['canary_denied']} (errno {m['canary_errno']})")
print(f"        syscalls allowed: {m['syscalls_allowed']}, mounts: {m['read_mounts']} ro / {m['write_mounts']} rw")
print(f"        container create: {ms(m['create_latency_ns'])}, destroy: {ms(m['destroy_latency_ns'])}")
lat=sorted(m['request_latencies_ns'])
warm=sorted(m['request_latencies_ns'][1:]) or lat
q=lambda s,p: s[int((len(s)-1)*p)]
print(f"        requests: {m['requests']} ({m['failures']} failed)")
print(f"        cold first request: {ms(lat[-1] if len(lat)==1 else m['request_latencies_ns'][0])}")
print(f"        warm p50/p95/p99: {ms(q(warm,.5))} / {ms(q(warm,.95))} / {ms(q(warm,.99))}")
PY
  else
    bad "enforced run"; tail -20 "$WORK/run.err"; tail -5 "$WORK/run.json" 2>/dev/null
  fi
else
  bad "no approved profile to enforce"
fi

# ------------------------------------------------------------ live daemon
head_ "always-on daemon + live metrics"
if [[ -f "$WORK/approved.json" ]]; then
  PORT=18173
  AUDIT="$WORK/audit.jsonl"
  "$BIN/warden-serve" -profile "$WORK/approved.json" -probe "$BIN/probe" \
      -addr "127.0.0.1:$PORT" -pool 1 \
      -analyze detect -audit "$AUDIT" -evaluate-every 1s \
      -- node "$SERVER_JS" "$SERVED_DIR" \
      >"$WORK/serve.log" 2>&1 &
  SERVE_PID=$!

  for _ in $(seq 1 60); do
    curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
    sleep 0.5
  done

  if curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
    ok "daemon came up with a warm confined pool"

    # The daemon runs the MCP handshake against every container at
    # creation, so a client's first call can be a real tool call.
    curl -sf -X POST "http://127.0.0.1:$PORT/rpc" -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
      >"$WORK/init.json" 2>/dev/null
    grep -q '"result"' "$WORK/init.json" && ok "handshake ran at container creation; tools/list served" \
      || { bad "tools/list through daemon"; cat "$WORK/init.json"; }

    START=$(date +%s.%N)
    N=100
    for i in $(seq 1 $N); do
      curl -sf -X POST "http://127.0.0.1:$PORT/rpc" -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":$((i+10)),\"method\":\"tools/list\",\"params\":{}}" >/dev/null 2>&1
    done
    END=$(date +%s.%N)
    ELAPSED=$(python3 -c "print(f'{$END-$START:.2f}')")
    note "$N sustained requests in ${ELAPSED}s ($(python3 -c "print(f'{$N/($END-$START):.0f}')") req/s incl. curl overhead)"

    curl -sf "http://127.0.0.1:$PORT/stats" >"$WORK/stats.json" 2>/dev/null
    if python3 - "$WORK/stats.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1])); c=s['metrics']['counters']; g=s['metrics']['gauges']; h=s['metrics']['histograms']
ms=lambda ns: f"{ns/1e6:.2f}ms"
req=c.get('warden_requests_total',0); fail=c.get('warden_request_failures_total',0)
print(f"        requests={req} failures={fail} denials={c.get('warden_kernel_denials_total',0)}")
print(f"        containers created={c.get('warden_containers_created_total',0)} quarantined={c.get('warden_containers_quarantined_total',0)}")
rs=h.get('warden_request_seconds')
if rs: print(f"        live p50/p95/p99: {ms(rs['p50_ns'])} / {ms(rs['p95_ns'])} / {ms(rs['p99_ns'])}")
cc=h.get('warden_container_create_seconds')
if cc: print(f"        container create p50: {ms(cc['p50_ns'])}")
print(f"        pool idle={g.get('warden_pool_idle',0)}/{g.get('warden_pool_size',0)} degraded={g.get('warden_pool_degraded',0)}")
sys.exit(0 if req>=100 and fail==0 else 1)
PY
    then ok "sustained load served with zero failures; live metrics accurate"
    else bad "sustained load had failures (see above)"; fi

    curl -sf "http://127.0.0.1:$PORT/metrics" | grep -q '^warden_requests_total ' \
      && ok "Prometheus /metrics scrapeable" || bad "Prometheus /metrics"

    curl -sf "http://127.0.0.1:$PORT/" | grep -q '<title>warden</title>' \
      && ok "live dashboard served at /" || bad "dashboard"

    # Container reuse is the whole point of the pool.
    python3 - "$WORK/stats.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]))
created=s['metrics']['counters'].get('warden_containers_created_total',0)
req=s['metrics']['counters'].get('warden_requests_total',0)
sys.exit(0 if created <= 2 and req >= 100 else 1)
PY
    [[ $? -eq 0 ]] && ok "pool reused containers (no per-request 220ms create)" \
                   || bad "pool churned containers under steady load"

    # ---------------------------------------------- behavioural analysis
    curl -sf "http://127.0.0.1:$PORT/behavior" >"$WORK/behavior.json" 2>/dev/null
    curl -sf "http://127.0.0.1:$PORT/score"    >"$WORK/score.json"    2>/dev/null
    curl -sf "http://127.0.0.1:$PORT/findings" >"$WORK/findings.json" 2>/dev/null

    if python3 - "$WORK/behavior.json" <<'PY'
import json,sys
b=json.load(open(sys.argv[1])); t=b['totals']; p=b['pipeline']; i=b['idle']
print(f"        syscalls observed={t['syscalls']:,} failed={t['errors']:,} distinct paths={t['distinct_paths']:,}")
print(f"        bytes: file read={t['file_read_bytes']:,} file write={t['file_write_bytes']:,} net out={t['net_write_bytes']:,}")
print(f"        process spawns={t['process_spawns']} network destinations={len(t.get('dials') or {})}")
print(f"        idle: syscalls={i['syscalls']:,} bursts={i['bursts']} egress={i['net_write_bytes']}")
print(f"        pipeline: ingested={p['events_ingested']:,} dropped={p['events_dropped']:,} read={p['bytes_read']:,}B")
top=", ".join(f"{k['name']}={k['count']}" for k in t['top_syscalls'][:6])
print(f"        top syscalls: {top}")
# The analyzer must actually be seeing the server.
sys.exit(0 if p['events_ingested'] > 0 and t['distinct_paths'] > 0 else 1)
PY
    then ok "behavioural telemetry flowing from the confined container"
    else bad "analyzer saw nothing — confinement works but nothing is being observed"; fi

    python3 - "$WORK/behavior.json" <<'PY'
import json,sys
b=json.load(open(sys.argv[1]))
sys.exit(0 if b['pipeline']['events_dropped']==0 else 1)
PY
    [[ $? -eq 0 ]] && ok "no trace events dropped under sustained load" \
                   || bad "analysis fell behind ingestion (findings would be incomplete)"

    if python3 - "$WORK/score.json" "$WORK/findings.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1])); f=json.load(open(sys.argv[2]))
print(f"        posture: {s['posture'].upper()} — {s['posture_reason']}")
print(f"        findings: {s['critical']} critical, {s['high']} high, {s['medium']} medium, {s['low']} low "
      f"({s['deterministic_findings']} kernel-attested)")
print(f"        reliability: {s['reliability']['requests']} requests, "
      f"{s['reliability']['error_rate']*100:.1f}% errors, "
      f"p50 {s['reliability']['p50_ns']/1e6:.1f}ms p99 {s['reliability']['p99_ns']/1e6:.1f}ms")
for x in f['findings'][:10]:
    print(f"          [{x['severity']:8s}/{x['confidence']:13s}] {x['detector']}: {x['title']} (x{x['count']})")
# An approved profile driven by exactly the traffic it was generated from
# must not produce a kernel-attested deviation. If it does, either the
# profile is wrong or a detector is.
sys.exit(0 if s['analysis_healthy'] and s['critical']==0 else 1)
PY
    then ok "server conforms to its approved profile under load (no critical findings)"
    else bad "critical findings against a profile generated from this same server"; fi

    curl -sf "http://127.0.0.1:$PORT/containers" | grep -q '"container_id"' \
      && ok "per-container drill-down served at /containers" || bad "/containers"

    curl -sf "http://127.0.0.1:$PORT/metrics" | grep -q '^warden_posture_tier ' \
      && ok "behavioural metrics exported to Prometheus" || bad "posture not in /metrics"

    kill -INT "$SERVE_PID" 2>/dev/null
    for _ in $(seq 1 40); do kill -0 "$SERVE_PID" 2>/dev/null || break; sleep 0.5; done
    grep -q "all containers destroyed" "$WORK/serve.log" \
      && ok "graceful shutdown destroyed every container" \
      || bad "graceful shutdown"
    SERVE_PID=""

    # ------------------------------------------------------- audit chain
    if [[ -f "$AUDIT" ]]; then
      if "$BIN/warden-audit" -verify "$AUDIT" >"$WORK/audit.txt" 2>&1; then
        sed 's/^/        /' "$WORK/audit.txt"
        ok "audit chain verifies (every hash, every link, every checkpoint signature)"
      else
        bad "audit chain did not verify"; sed 's/^/        /' "$WORK/audit.txt"
      fi

      # Tamper with one entry and confirm the verifier catches it. An
      # audit log that has never been shown to detect an edit is an
      # assumption, not a control.
      python3 - "$AUDIT" "$WORK/tampered.jsonl" <<'PY'
import json,sys
src,dst=sys.argv[1],sys.argv[2]
lines=[l for l in open(src) if l.strip()]
for i,l in enumerate(lines):
    e=json.loads(l)
    if e.get('kind')=='execution':
        e['execution']['status']='SUCCESS_TAMPERED'
        lines[i]=json.dumps(e)+"\n"
        break
open(dst,'w').writelines(lines)
PY
      if "$BIN/warden-audit" -verify "$WORK/tampered.jsonl" >"$WORK/tamper.txt" 2>&1; then
        bad "a modified audit entry still verified — tamper-evidence is not working"
      else
        ok "a modified audit entry is detected and named"
        grep -m1 '!' "$WORK/tamper.txt" | sed 's/^/        /'
      fi

      note "audit findings recorded:"
      "$BIN/warden-audit" -findings "$AUDIT" 2>/dev/null | head -8 | sed 's/^/        /'
    else
      bad "no audit chain was written"
    fi
  else
    bad "daemon failed to become ready"; tail -25 "$WORK/serve.log"
  fi
fi

# ----------------------------------------------------------------- result
head_ "result"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
if (( FAIL > 0 )); then
  printf '\n  failures:\n'
  for f in "${FAILURES[@]}"; do printf '    - %s\n' "$f"; done
  exit 1
fi
printf '\n  \033[32mAll checks passed.\033[0m\n'
