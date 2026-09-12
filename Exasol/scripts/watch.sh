#!/usr/bin/env bash
# Plug in any MCP server, confine it, and watch it live.
#
#   sudo ./scripts/watch.sh -- npx -y @modelcontextprotocol/server-filesystem /tmp/data
#   sudo ./scripts/watch.sh -- node /path/to/server.js /tmp/data
#   sudo ./scripts/watch.sh -- python -m my_mcp_server
#
# Runs, in order:
#   1. LEARNING MODE — the server runs unconfined but traced, under gVisor,
#      to record what it actually needs. §6.4: a learning-mode execution is
#      an unconfined execution, and it is labelled as one below.
#   2. A candidate CapabilityProfile is generated from that recording.
#   3. YOU approve it. Never automatic (§3.2 step 5): a server that
#      exfiltrates during profiling would otherwise have the exfiltration
#      baked into its own allowlist.
#   4. The server is restarted under full kernel confinement and a live
#      terminal dashboard runs until you press Ctrl-C.
#
# Flags (before --):
#   -w DIR     grant write access to DIR (repeatable)
#   -r FILE    drive this JSON-RPC request file instead of the default
#   -n RATE    requests per second (default 2)
#   -p N       warm container pool size (default 2)
#   -o DIR     keep artifacts here instead of a temp dir
#   -y         approve the generated profile without prompting
#   -f FILE    skip learning entirely and use this already-approved profile

set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

WRITE_PATHS=(); REQ_FILE=""; RATE=2; POOL=2; OUT=""; AUTO_YES=0; PROFILE_IN=""
while getopts "w:r:n:p:o:f:yh" opt; do
  case "$opt" in
    w) WRITE_PATHS+=("$OPTARG") ;;
    r) REQ_FILE="$OPTARG" ;;
    n) RATE="$OPTARG" ;;
    p) POOL="$OPTARG" ;;
    o) OUT="$OPTARG" ;;
    f) PROFILE_IN="$OPTARG" ;;
    y) AUTO_YES=1 ;;
    h) sed -n '2,28p' "$0"; exit 0 ;;
    *) exit 2 ;;
  esac
done
shift $((OPTIND-1))
[[ "${1:-}" == "--" ]] && shift

if [[ $# -eq 0 ]]; then
  echo "usage: sudo $0 [flags] -- <mcp server command> [args...]" >&2
  echo "       $0 -h  for flags" >&2
  exit 2
fi
SERVER_CMD=("$@")

if [[ $EUID -ne 0 ]]; then
  echo "This needs root: runsc creates sandboxes and cgroups." >&2
  echo "Re-run as:  sudo $0 ${*@Q}" >&2
  exit 1
fi

command -v runsc >/dev/null || { echo "runsc not found on PATH" >&2; exit 1; }
command -v go    >/dev/null || { echo "go not found on PATH" >&2; exit 1; }

if [[ -n "$OUT" ]]; then mkdir -p "$OUT"; WORK="$OUT"; KEEP=1
else WORK="$(mktemp -d /tmp/warden-watch-XXXXXX)"; KEEP=0; fi
BIN="$WORK/bin"; mkdir -p "$BIN"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
dim()  { printf '\033[2m%s\033[0m\n' "$1"; }
warn() { printf '\033[33m%s\033[0m\n' "$1"; }
die()  { printf '\033[31m%s\033[0m\n' "$1" >&2; exit 1; }

cleanup() { [[ $KEEP -eq 0 ]] && rm -rf "$WORK"; }
trap cleanup EXIT

# ---------------------------------------------------------------- build
bold "building warden"
go build -o "$BIN/warden-observe" ./cmd/warden-observe || die "build warden-observe"
go build -o "$BIN/warden-serve"   ./cmd/warden-serve   || die "build warden-serve"
go build -o "$BIN/warden-audit"   ./cmd/warden-audit   || die "build warden-audit"
CGO_ENABLED=0 go build -o "$BIN/probe" ./sandbox/runtime/runsc/probe || die "build probe"
dim "  ok"

# The default drive traffic. tools/list is the one call every MCP server
# answers, so it works against a server this script has never seen.
# Supply your own with -r to exercise real tools.
if [[ -z "$REQ_FILE" ]]; then
  REQ_FILE="$WORK/requests.jsonl"
  cat > "$REQ_FILE" <<'JSON'
{"jsonrpc":"2.0","method":"tools/list","params":{}}
JSON
fi

# The observe run needs its own handshake, since nothing has initialized
# the server at that point.
OBS_REQ="$WORK/observe-requests.jsonl"
{
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-warden-watch","version":"0.1"}}}'
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
  grep -v '^\s*#' "$REQ_FILE" | grep -v '^\s*$' | head -20
} > "$OBS_REQ"

APPROVED="$WORK/approved.json"

if [[ -n "$PROFILE_IN" ]]; then
  cp "$PROFILE_IN" "$APPROVED" || die "cannot read $PROFILE_IN"
  bold "using approved profile $PROFILE_IN"
else
  # ------------------------------------------------------------ learning
  echo
  warn "LEARNING MODE — the next step runs this server UNCONFINED (traced, inside gVisor)."
  warn "Nothing it does here is prevented. That is the point: we are recording what it needs."
  dim  "  ${SERVER_CMD[*]}"
  echo

  OBS_ARGS=(-requests "$OBS_REQ" -rollup-depth 5 -tool-name mcp_server
            -emit-profile "$WORK/profile.json" -top 5)
  for w in "${WRITE_PATHS[@]:-}"; do [[ -n "$w" ]] && OBS_ARGS+=(-write-path "$w"); done

  if ! "$BIN/warden-observe" "${OBS_ARGS[@]}" -- "${SERVER_CMD[@]}" > "$WORK/observe.log" 2>&1; then
    sed 's/^/  /' "$WORK/observe.log" | tail -25
    die "learning run failed — the server did not start or did not speak MCP"
  fi
  grep -E 'syscalls granted|read paths|write paths|findings|events' "$WORK/observe.log" | sed 's/^/  /'

  [[ -f "$WORK/profile.json" ]] || die "no candidate profile was produced"

  # ------------------------------------------------------- human review
  echo
  bold "REVIEW — this is the allowlist the kernel will enforce (§3.2 step 5)"
  python3 - "$WORK/profile.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1])); t=p['tools'][0]; fsx=t['filesystem']
e=p.get('entrypoint') or {}
print(f"  entrypoint   {e.get('path','?')}")
print(f"               {e.get('sha256','UNPINNED')}")
if e.get('interpreter'):
    print(f"  interpreter  {e['interpreter']}")
    print(f"               {e.get('interpreter_sha256','UNPINNED')}")
print(f"  syscalls     {len(t['syscalls'])} allowed; everything else returns EPERM")
print(f"  network      {len(t.get('network') or [])} declared destinations "
      f"({'no interfaces in the container' if not t.get('network') else 'CHECK THESE'})")
print(f"  read  ({len(fsx['read'])})")
for x in fsx['read'][:14]: print(f"                 {x}")
if len(fsx['read'])>14: print(f"                 … and {len(fsx['read'])-14} more")
print(f"  write ({len(fsx['write'])})")
for x in fsx['write']: print(f"                 {x}")
broad={'/','/home','/root','/etc','/usr','/var','/tmp','/opt','/srv'}
flag=[x for x in fsx['read']+fsx['write'] if x in broad]
if flag:
    print(f"\n  \033[31m!! GRANTS A WHOLE SYSTEM TREE: {', '.join(flag)}\033[0m")
    print("     Do not approve this without narrowing it by hand.")
PY
  echo
  if [[ $AUTO_YES -eq 1 ]]; then
    dim "  -y given; approving without prompting"
    REPLY=y
  else
    read -r -p "  Approve this profile and run confined? [y/N] " REPLY
  fi
  case "$REPLY" in
    y|Y|yes|YES) ;;
    *) echo "  not approved; nothing will run confined."; exit 0 ;;
  esac

  python3 - "$WORK/profile.json" "$APPROVED" <<'PY'
import json,sys,os,getpass
p=json.load(open(sys.argv[1]))
p['approved_by']=f"operator:{os.environ.get('SUDO_USER') or getpass.getuser()}"
json.dump(p,open(sys.argv[2],'w'),indent=2)
PY
  cp "$WORK/profile.json" "$WORK/candidate.json" 2>/dev/null
  dim "  approved as $(python3 -c "import json;print(json.load(open('$APPROVED'))['approved_by'])")"
fi

# ------------------------------------------------------------- monitor
AUDIT="$WORK/audit.jsonl"
echo
bold "starting confined session — Ctrl-C to stop"
[[ $KEEP -eq 1 ]] && dim "  artifacts in $WORK"
sleep 1

"$BIN/warden-serve" \
  -profile "$APPROVED" -probe "$BIN/probe" \
  -pool "$POOL" -analyze detect -audit "$AUDIT" \
  -live -drive "$REQ_FILE" -rate "$RATE" \
  -- "${SERVER_CMD[@]}"
STATUS=$?

# ---------------------------------------------------------- audit check
if [[ -f "$AUDIT" ]]; then
  echo
  bold "audit chain"
  "$BIN/warden-audit" -verify "$AUDIT" 2>&1 | sed 's/^/  /'
  if [[ $KEEP -eq 1 ]]; then
    dim "  chain kept at $AUDIT"
    dim "  re-verify any time:  $BIN/warden-audit -verify $AUDIT"
    dim "  findings only:       $BIN/warden-audit -findings $AUDIT"
  fi
fi

exit $STATUS
