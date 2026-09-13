# Runs scripts/warden_healthcheck.py inside the API container.
#
# Verifies, from a clean state and without triggering any scan:
#   1. the Warden runner is reachable and the runner token matches
#   2. a fresh Warden session (checkout -> observe -> serve) starts for every
#      eligible registered server
#   3. Exasol is resynced for each server's latest scan run (idempotent)
#
# Safe to run repeatedly: stale sessions are cleared first, and Exasol sync
# uses the MERGE-based sync helpers, never the rule/llm result endpoints.
#
# Examples:
#   .\scripts\warden_healthcheck.ps1
#   .\scripts\warden_healthcheck.ps1 -Server 38056b5f-6756-44b1-8d67-3606de250d0a
#   .\scripts\warden_healthcheck.ps1 -NoSession          # Exasol resync only
#   .\scripts\warden_healthcheck.ps1 -NoSync            # warden session test only

[CmdletBinding()]
param(
    [string]$Server,
    [switch]$NoSession,
    [switch]$NoSync,
    [string]$RunnerToken = $env:WARDEN_RUNNER_TOKEN,
    [string]$Container = "mcp-server-exasol",
    [string]$Script = ""
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "docker is not on PATH"
    exit 1
}

if (-not $Script) {
    $ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
    $Script = Join-Path $ScriptDir "warden_healthcheck.py"
}

$running = docker ps -q -f "name=$Container" 2>$null
if (-not $running) {
    Write-Error "container '$Container' is not running. Start it first (docker run ... mcp-server-exasol:latest)"
    exit 1
}
if (-not (Test-Path -LiteralPath $Script)) {
    Write-Error "python driver not found at $Script"
    exit 1
}

$tmp = "/tmp/warden_healthcheck.py"
try {
    docker cp $Script "${Container}:${tmp}"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $innerArgs = @("/tmp/warden_healthcheck.py")
    if ($Server) { $innerArgs += "--server"; $innerArgs += $Server }
    if ($NoSession) { $innerArgs += "--no-session" }
    if ($NoSync) { $innerArgs += "--no-sync" }
    if ($RunnerToken) {
        $innerArgs += "--runner-token"
        $innerArgs += $RunnerToken
    }

    Write-Host "running warden health check in container '$Container'..."
    docker exec -w /app -e PYTHONPATH=/app $Container python @innerArgs
    exit $LASTEXITCODE
}
finally {
    docker exec $Container rm -f $tmp 2>$null | Out-Null
}