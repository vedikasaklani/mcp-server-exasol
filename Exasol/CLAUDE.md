# mcp-warden

Zero-trust security proxy for MCP servers.
Full architecture: @docs/ARCHITECTURE.md — read it before any design decision.

## Current scope
v0 §6 (the sandboxed execution layer) is built.

Extended, at explicit direction, into part of §3 (SAST via
`sandbox/sast` + `mcp-server-exasol`) and part of §7 (telemetry storage:
`sandbox/registry` writes discovery/reputation/audit data into Exasol —
see docs/EXASOL_INTEGRATION.md). This is a hackathon-driven scope
expansion, not a reversal of the v0 boundary: IBAC, OpenFGA, and
attestation (cosign/in-toto, §3.3) are still out of scope. The telemetry
path is additive and best-effort — it never gates or blocks confinement.

## Non-negotiables
- Enforcement at the kernel, not observation in userspace.
- Default deny. Unlisted syscalls return EPERM, not SIGSYS.
- Sandbox unavailable means calls are rejected, never run unconfined.
- Learning mode is an unconfined execution and must be flagged as such.
