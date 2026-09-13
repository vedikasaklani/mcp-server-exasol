#!/usr/bin/env bash
# Build the two demo repositories the walkthrough uses, as bare repos laid
# out as owner/repo so they exercise the same code path a real GitHub
# server does:
#
#   demo/mcp    a well-behaved MCP server with a real npm dependency
#   demo/evil   the malicious fixture from Exasol/testdata/evil-mcp
#
# Usage: scripts/make_demo_repos.sh [target-dir]   (default /tmp/warden-demo)
set -euo pipefail

TARGET="${1:-/tmp/warden-demo}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

rm -rf "$TARGET"
mkdir -p "$TARGET/demo" "$TARGET/src"

# ---------------------------------------------------------------- demo/mcp
cat > "$TARGET/src/package.json" <<'JSON'
{
  "name": "demo-mcp-server",
  "version": "1.0.0",
  "type": "commonjs",
  "dependencies": { "uuid": "^9.0.1" }
}
JSON

cat > "$TARGET/src/server.js" <<'JS'
// A minimal, well-behaved stdio MCP server. It has a real npm dependency so
// the runner's install step is genuinely exercised, and node is a real ELF
// binary, which gVisor requires of a launch executable.
const { v4: uuidv4 } = require("uuid");

const TOOLS = [
  { name: "echo", description: "Echo a message back to the caller.",
    inputSchema: { type: "object", properties: { message: { type: "string" } }, required: ["message"] } },
  { name: "new_id", description: "Generate a fresh UUID v4.",
    inputSchema: { type: "object", properties: {} } },
  { name: "add", description: "Add two numbers.",
    inputSchema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" } }, required: ["a", "b"] } },
];

function handle(req) {
  const { id, method, params } = req;
  if (method === "initialize") {
    return { jsonrpc: "2.0", id, result: {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "demo-mcp-server", version: "1.0.0" } } };
  }
  if (method === "tools/list") return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
  if (method === "tools/call") {
    const { name, arguments: args = {} } = params || {};
    let text;
    if (name === "echo") text = String(args.message ?? "");
    else if (name === "new_id") text = uuidv4();
    else if (name === "add") text = String(Number(args.a) + Number(args.b));
    else return { jsonrpc: "2.0", id, error: { code: -32602, message: `unknown tool: ${name}` } };
    return { jsonrpc: "2.0", id, result: { content: [{ type: "text", text }] } };
  }
  if (method && method.startsWith("notifications/")) return null;
  return { jsonrpc: "2.0", id, error: { code: -32601, message: `unknown method: ${method}` } };
}

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (!line) continue;
    let res;
    try { res = handle(JSON.parse(line)); }
    catch (e) { res = { jsonrpc: "2.0", id: null, error: { code: -32700, message: String(e) } }; }
    if (res) process.stdout.write(JSON.stringify(res) + "\n");
  }
});
JS

git -C "$TARGET/src" init -q -b main
git -C "$TARGET/src" add -A
git -C "$TARGET/src" -c user.email=demo@example.com -c user.name=demo commit -qm "demo mcp server"
MCP_SHA=$(git -C "$TARGET/src" rev-parse HEAD)
git clone -q --bare "$TARGET/src" "$TARGET/demo/mcp.git"
git -C "$TARGET/demo/mcp.git" update-server-info

# --------------------------------------------------------------- demo/evil
cp -r "$REPO_ROOT/Exasol/testdata/evil-mcp" "$TARGET/evilsrc"
git -C "$TARGET/evilsrc" init -q -b main
git -C "$TARGET/evilsrc" add -A
git -C "$TARGET/evilsrc" -c user.email=demo@example.com -c user.name=demo commit -qm "evil mcp fixture"
EVIL_SHA=$(git -C "$TARGET/evilsrc" rev-parse HEAD)
git clone -q --bare "$TARGET/evilsrc" "$TARGET/demo/evil.git"
git -C "$TARGET/demo/evil.git" update-server-info

cat > "$TARGET/shas.env" <<EOF
MCP_SHA=$MCP_SHA
EVIL_SHA=$EVIL_SHA
EOF

echo "repositories ready under $TARGET"
echo "  demo/mcp   $MCP_SHA"
echo "  demo/evil  $EVIL_SHA"
echo
echo "serve them with:"
echo "  python3 scripts/demo_git_server.py $TARGET 9500"
echo "and start the Warden runner with WARDEN_GIT_BASE_URL=http://127.0.0.1:9500"
