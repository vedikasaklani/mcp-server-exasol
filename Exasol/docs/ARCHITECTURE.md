# MCP Security & Auditing Engine — Architecture

Version 2. Supersedes the initial architecture definition.

A zero-trust intermediary between AI clients and MCP servers. It admits only
attested servers, authorizes every tool call deterministically, narrows that
authorization using parsed user intent, executes the server under kernel-enforced
confinement, inspects everything on the way back, and writes a tamper-evident
audit trail.

---

## 1. Design principles

These are load-bearing. Violating one is a design bug, not a tradeoff.

1. **No LLM is a security boundary.** Model output can narrow or escalate an
   authorization decision. It can never widen one. Any component fed
   attacker-influenceable text is advisory by construction.
2. **Prevent at the kernel, detect in userspace.** Anything expressible as a
   seccomp filter, a Landlock rule, or a network namespace is enforced there.
   eBPF covers only what those cannot express. Observe-then-react has a
   TOCTOU window; the exfiltration completes before userspace sees it.
3. **Every stage has a written fail mode.** Fail-open and fail-closed are both
   valid; undefined is not.
4. **Untrusted content is labelled, not sanitized.** Tool results entering the
   model context are structurally marked as data.
5. **Instance quarantine and artifact revocation are separate.** One bad
   container does not kill an artifact fleet-wide.
6. **Latency budget is a requirement.** Proxy overhead target: p50 under 15 ms,
   p99 under 60 ms, excluding tool execution and human approval.

---

## 2. Component overview

| Layer | Responsibility | Stack |
|---|---|---|
| Ingestion & attestation | Static analysis, capability profiling, artifact signing | Semgrep, cosign / Sigstore, in-toto |
| Proxy gateway | Transport interception, admission, authorization, response guard | Go |
| IBAC engine | Deterministic policy + intent constraint + escalation | OpenFGA, local classifier model |
| Sandbox | Confined ephemeral execution | runsc / Firecracker, seccomp-bpf, Landlock, netns, Tetragon |
| Telemetry | Hash-chained audit log, metrics, posture and reliability scoring | SQLite → Postgres → ClickHouse (staged) |

---

## 3. Ingestion & attestation

Runs once per artifact version, offline. Output is a signed attestation bound to
an image digest.

### 3.1 Static analysis
Semgrep rulesets over the server source or image: hardcoded secrets, dangerous
imports (`os.system`, `eval`, `subprocess` with shell), network calls not
declared in the manifest, filesystem access outside declared paths.

### 3.2 Capability profiling
The critical stage, and the one most systems skip. Nobody hand-writes syscall
allowlists.

1. Run the server in the sandbox in **learning mode**.
2. Drive it with generated invocations for every declared tool, plus fuzzed
   arguments, plus the server's own test suite if present.
3. Record: syscall set, file paths touched (read vs write), network destinations
   (host, port, protocol), process spawns, environment reads.
4. Emit a candidate `CapabilityProfile` (schema in §8.2).
5. **Human review gate.** An operator approves or edits the profile. Never
   auto-promote — a server that exfiltrates during profiling would have the
   exfiltration baked into its allowlist.
6. Approved profile is embedded in the attestation.

### 3.3 Attestation
Sign the image digest with cosign. Attach an in-toto attestation containing the
SAST result, the approved capability profile, the tool manifest hash, and the
assigned security tier.

Admission is then a lookup: does a valid attestation exist for this exact digest,
meeting policy? No CRL, no expiry plumbing, no OCSP responder.

**Revocation** is a deny-list keyed by digest. Entry requires either an operator
decision or N confirmed violations across M distinct instances. A single instance
violation quarantines that instance only.

---

## 4. Proxy gateway

### 4.1 Transport modes

**stdio.** The proxy is not a network proxy here. It registers itself as the MCP
server in the client config and spawns the real server as a child, owning both
pipes. This is the primary mode for desktop clients.

**HTTP / SSE.** A genuine reverse proxy. The MCP server is an OAuth resource
server; the proxy is the token broker (§4.5).

Both modes present an identical internal interface to the rest of the pipeline.

### 4.2 Admission

On session initialize:

1. Resolve the server image digest. Verify the cosign signature and in-toto
   attestation. Check the digest deny-list.
2. Fetch the tool manifest from the server. Hash every tool's name, description,
   and input schema. Compare against the manifest hash in the attestation.
3. Pin those hashes for the session lifetime.

**Fail mode: closed.** No attestation, no session.

### 4.3 Rug-pull and shadowing defence

Cheap, and it covers the most exploited weakness in the ecosystem.

- **Rug-pull.** If any tool description or schema changes mid-session, or between
  sessions without a new attestation, block the call and alert. Servers mutating
  descriptions after approval is the standard attack.
- **Shadowing.** Namespace every tool as `{server_id}::{tool_name}` before it
  reaches the client, so a malicious server cannot redefine a trusted server's
  `send_email`.

**Fail mode: closed.**

### 4.4 Response guard

The original design authorized outbound calls and ignored the return path. The
return path is where MCP is actually attacked.

Applied to every tool result before it reaches the client:

- **Injection scan.** Pattern and classifier detection for instruction-shaped
  content in what should be data.
- **Structural wrapping.** Results are wrapped in an explicit untrusted-data
  envelope so the client can distinguish data from instruction.
- **Egress DLP.** Secrets, credentials, PII flowing server → client.
- **Taint tagging.** Result is labelled with the sensitivity of the resource it
  came from; the label attaches to the session (§5.3).

**Fail mode:** closed on detection, open on scanner error, with a loud log.

### 4.5 Credential isolation

The sandboxed server never holds long-lived credentials. The proxy brokers
short-lived, narrowly-scoped tokens per request, minted against the resource the
authorized call actually targets. This single control neutralises a large class
of compromised-server scenarios independent of whether detection works.

---

## 5. IBAC — Intent-Based Access Control

Intent is part of authorization, but it is not the authorizer. The engine runs
three components; the final decision is the strictest of them.

```
decision = intersect(deterministic_grant, intent_constraint)
tier     = max(base_tier, risk_escalation)
```

### 5.1 Deterministic grant (authoritative)

Built only from inputs the proxy controls:

- authenticated client and user identity
- namespaced tool name
- structurally validated arguments
- target resource, extracted from arguments by a typed extractor declared in the
  capability profile — never by a model

These form an OpenFGA tuple, e.g. `user:alice # invoke @ tool:db_query` plus
`user:alice # can_read @ resource:financial_db`. Evaluated against the store.
Deny here is final; no downstream component can overturn it.

Decisions are cached by tuple hash. This is the latency-critical path.

**Fail mode: closed.**

### 5.2 Intent constraint (narrowing only)

A local classifier reads the user's turn — not the accumulated context, which
contains untrusted tool output — and produces a structured intent:

```json
{
  "declared_goal": "read_analytics",
  "expected_resources": ["resource:metrics_db"],
  "expected_effects": ["read"],
  "confidence": 0.86
}
```

This is intersected with the deterministic grant. If the user asked to read
analytics and the tool call targets `resource:payroll`, the call falls outside
declared intent and is blocked or escalated — even though OpenFGA allowed it.

The asymmetry is the whole point. Intent can **remove** permissions the policy
granted. It can never **add** one the policy withheld. A prompt-injected
classifier can therefore only cause a false denial, never a false approval.

**Fail mode:** on timeout or low confidence, skip the constraint and fall through
to the deterministic decision at an escalated tier. Never fail closed — that
makes the classifier a denial-of-service surface.

### 5.3 Session taint and sequence policy

Per-call authorization structurally cannot catch the dominant real threat: every
call is individually fine, the sequence is an exfiltration.

The session carries a taint set. Reading `resource:financial_db` adds
`taint:financial`. Any subsequent call with an egress-capable effect — network
write, file write outside scratch, message send — is evaluated against the taint
set and is denied or escalated. Taint is monotonic within a session; it clears
only on session end.

This is deterministic, cheap, and the highest-value control in the system.

### 5.4 Risk escalation (advisory)

A parallel classifier scores the call and can only raise the approval tier:

| Tier | Behaviour |
|---|---|
| `auto` | Execute |
| `confirm` | Block pending explicit human approval, surfaced through the client |
| `deny` | Reject |

Escalate-only means the classifier's compromise, timeout, or absence is never an
authorization bypass.

**Fail mode:** proceed at the tier already determined.

---

## 6. Sandbox — first build target

Ephemeral, kernel-confined execution. Everything here is enforcement, not
observation, except where noted.

### 6.1 Isolation stack

Layered, outermost first:

1. **Container runtime.** gVisor (`runsc`) for v0 — user-space kernel, strong
   syscall interception, ~50 ms start. Firecracker microVM for v2 where hardware
   isolation is required (~125 ms boot).
2. **seccomp-bpf.** Generated from the capability profile. Default deny.
   Unlisted syscalls return `EPERM`, not `SIGSYS` — a killed process loses the
   error context that makes violations diagnosable.
3. **Landlock LSM.** Filesystem access confined to declared paths. Read and write
   sets are separate. Scratch space is a per-request tmpfs, discarded after.
4. **Network namespace.** No interfaces by default. Declared destinations get an
   explicit allowlist via a userspace resolver the sandbox must call; raw DNS is
   blocked so a server cannot exfiltrate over DNS queries.
5. **cgroup v2 limits.** CPU, memory, PID count, and IO. Prevents resource
   exhaustion as a denial-of-service against the host.
6. **Tetragon (v2).** In-kernel enforcement for what the above cannot express:
   `connect()` destination policy correlated with the active tool, file access
   patterns, process lineage. Uses in-kernel `SIGKILL`, not userspace reaction.

### 6.2 Lifecycle

```
session start → container created, profile loaded, seccomp + landlock applied
per request  → request_id stamped, cgroup tagged, tool invoked
violation    → kernel denies (EPERM) or Tetragon kills; proxy returns hard error;
               instance quarantined; violation recorded against artifact
session end  → container destroyed, tmpfs discarded, no state persists
```

### 6.3 Attribution

MCP permits concurrent requests on one connection. Without attribution you cannot
say which tool call produced a given syscall, which breaks violation accounting.

**v0 decision: serialize requests within a session.** One in-flight tool call per
container. Attribution is then trivially exact. Concurrency is recovered by
running multiple containers per session for servers marked parallel-safe in
their profile.

Kernel events are correlated back to the request via cgroup ID, which the proxy
stamps with `request_id` at invocation.

Document the guarantee explicitly: *within a session, syscall attribution is
exact; across parallel containers, attribution is by container, not by request.*

### 6.4 Learning mode

The same sandbox, running with seccomp in log-only mode and Landlock disabled,
recording rather than denying. Feeds §3.2. Must be flagged unmistakably in the
audit log — a learning-mode execution is an unconfined execution.

**Fail mode for the whole layer: closed.** Sandbox unavailable means calls are
rejected, never executed unconfined.

---

## 7. Telemetry, audit, and scoring

### 7.1 Audit log

Hash-chained: each entry contains the hash of the previous entry. A signed
checkpoint every N entries or T seconds. Same tamper-evidence as per-entry
signing at a fraction of the cost.

Written asynchronously. **Audit never blocks the response path.** Buffer locally;
alert on backlog depth.

### 7.2 Two scores, not one

Collapsing security and reliability into one number means a fast malicious server
outranks a slow safe one.

**Security posture** — gates admission. Discrete tiers, not a continuous score,
because "why did this drop from 71 to 68" has no useful answer. Inputs:
attestation validity, SAST findings by severity, confirmed violation history.

**Operational reliability** — an SLO. Error rate, timeout frequency, latency,
uptime. Drives routing and alerting. **Never an input to authorization.**

Violation penalties decay on a defined half-life and have an explicit remediation
path — a new attestation on a fixed artifact restores tier. Without this, one
violation is a permanent death sentence with no route back.

---

## 8. Schemas

### 8.1 Audit entry

```json
{
  "entry_id": "ae_8f92a1b9",
  "prev_hash": "sha256:...",
  "timestamp": "2026-09-09T17:58:00Z",
  "session_id": "sess_4a1c",
  "request_id": "req_0117",
  "mcp_server_id": "srv_postgres_readonly_v1",
  "image_digest": "sha256:...",
  "attestation_id": "att_xyz123",
  "ai_client_id": "client_claude_desktop",
  "learning_mode": false,
  "authorization": {
    "deterministic_tuples": ["user:alice#invoke@tool:db_query"],
    "openfga_decision": "ALLOW",
    "intent_constraint": {
      "declared_goal": "read_analytics",
      "within_intent": true,
      "confidence": 0.86
    },
    "taint_labels_at_call": ["taint:financial"],
    "approval_tier": "confirm",
    "decision": "ALLOW",
    "decision_reason": "policy_allow_intent_match_taint_escalated",
    "latency_ms": 11
  },
  "execution": {
    "tool_name": "srv_postgres_readonly_v1::query_metrics",
    "rpc_payload_hash": "sha256:...",
    "status": "SUCCESS",
    "latency_ms": 310
  },
  "sandbox": {
    "runtime": "runsc",
    "seccomp_denials": 0,
    "landlock_denials": 0,
    "network_connections": 1,
    "anomalies": []
  },
  "response_guard": {
    "injection_flags": 0,
    "dlp_flags": 0,
    "taint_added": ["taint:financial"]
  }
}
```

### 8.2 Capability profile

```json
{
  "profile_version": "1.0",
  "image_digest": "sha256:...",
  "generated_by": "learning_mode",
  "approved_by": "operator:neal",
  "parallel_safe": false,
  "tools": [{
    "name": "query_metrics",
    "resource_extractor": { "arg": "database", "type": "resource_id" },
    "effects": ["read"],
    "syscalls": ["read", "write", "openat", "connect", "socket"],
    "filesystem": { "read": ["/app", "/etc/ssl"], "write": ["/tmp/scratch"] },
    "network": [{ "host": "db.internal", "port": 5432, "proto": "tcp" }],
    "max_duration_ms": 5000
  }]
}
```

---

## 9. Fail modes

| Stage | On failure | On timeout |
|---|---|---|
| Admission | closed | closed |
| Tool-hash pin | closed | n/a |
| Deterministic grant | closed | closed |
| Intent constraint | skip, escalate tier | skip, escalate tier |
| Risk escalation | proceed at current tier | proceed at current tier |
| Sandbox | closed, quarantine instance | closed |
| Response guard | closed on detection, open on scanner error | open |
| Audit commit | never blocks response; buffer and alert | n/a |

---

## 10. Build order

**v0 — sandbox and core proxy.** gVisor runtime, seccomp + Landlock + netns from
a hand-written profile, learning mode, request serialization, stdio proxy, tool
hash pinning, flat-file deterministic policy, hash-chained SQLite audit log. No
OpenFGA, no classifier, no Tetragon, no CA.

**v1 — full IBAC.** OpenFGA replaces the flat policy. Session taint tracking.
Intent constraint classifier. Cosign attestation and automated profiling.
Response guard. HTTP/SSE transport.

**v2 — hardening and scale.** Firecracker option, Tetragon enforcement, risk
escalation classifier, credential brokering, ClickHouse telemetry. Kafka only
when a single writer demonstrably cannot keep up.

Starting point is §6, the sandbox layer. It is the only component with no
dependency on the others, and everything above it is worthless without it.
