# Behavioural analysis — design note

Phase 7. Extends §6 (sandbox) and implements the sandbox half of §7
(telemetry, audit, scoring). IBAC, OpenFGA, cosign attestation and the
response guard remain out of scope.

---

## 1. The premise

**Malicious intent is not observable. Deviation is.**

Nothing in this layer claims to detect intent, and any component that did
would be a security boundary made of guesses. What is observable is
divergence — from the capability profile a human approved (§3.2), from
the behaviour recorded when that profile was generated, and from the
shape of a well-behaved MCP server.

Every detector measures one kind of divergence and declares how much it
trusts its own measurement:

| Confidence | Means | May gate? |
|---|---|---|
| `deterministic` | Restates a kernel-attested fact. The syscall happened, the bytes moved, the path was outside the allowlist. No threshold, no model. | Yes |
| `statistical` | Compares a measurement against a baseline or threshold. True but tunable, and wrong at the edges. | Advisory |
| `heuristic` | Matches a pattern believed to correlate with risk. | Triage only |

This split is load-bearing, not decoration. §1.1 says a component fed
attacker-influenceable input may narrow trust and never widen it; the
corollary implemented here is that such a component must not be able to
take a server *down* either, or it becomes a denial-of-service surface. A
statistical critical therefore caps at `watch`. Only a deterministic
critical quarantines.

## 2. What made this possible

The enforced path previously produced exactly one behavioural signal:
`Denial.Occurred`. Three changes opened the rest:

1. **Live tracing on enforced containers.** `runsc.Runtime.Trace` turns
   on gVisor's own strace, written as JSON per container and consumed by
   `observe.Tailer` while the server runs. This is observation layered on
   enforcement, never instead of it — seccomp, the mount topology and the
   network namespace are applied identically either way.
2. **A descriptor table.** Built from the return values of `socket(2)`
   and `openat(2)`, keyed by `(tgid, fd)`. It is what makes "620 bytes
   were read from `~/.aws/credentials` and 620 bytes left over a socket"
   expressible at all. Keying on the descriptor number alone would
   conflate fd 5 in the server with fd 5 in anything it spawned — which
   is exactly the case the supply-chain detectors exist to catch.
3. **Exact request attribution.** §6.3 serializes tool calls per
   container, so the interval between send and response belongs to
   exactly one request. Attribution is by *timestamp*, not arrival order,
   because the sentry writes its log asynchronously: a request's events
   routinely arrive after that request has returned.

## 3. The detectors

### A. Conformance — deviation from the approved profile

| Detector | Measures | Confidence |
|---|---|---|
| `syscall-drift` | Syscalls outside the profile union, **split by whether they succeeded**. Refused → high (confinement working). Succeeded → critical (the enforced filter does not match the profile). | deterministic |
| `path-drift` | Undeclared reads, writes, and failed probes, reported separately. | deterministic |
| `network-drift` | Dials to destinations the profile does not declare. Under §6.1.4 a container has no interfaces, so any dial means the namespace is not what the design says. | deterministic |
| `write-then-exec` | A path that is both writable and executed. Neither permission is dangerous alone, so neither a read-set nor a write-set review catches it. | deterministic |
| `kernel-denial` | Denials the supervisor already quarantined on. | deterministic |

### B. Data flow — the sequence no single call violates

| Detector | Measures | Confidence |
|---|---|---|
| `read-then-egress` | Credential-shaped read **ordered before** socket write, within one request. This is §5.3's case: every call is individually fine, the order is the attack. | deterministic |
| `egress-volume` | Network egress against the size of the response the client received. Idle egress is critical — no caller explains it. | statistical |
| `path-fanout` | Distinct paths per request vs. the session's own median, scored by **median-absolute-deviation**. MAD rather than standard deviation because a single exfiltration burst would inflate an SD enough to hide inside it. | statistical |
| `enumeration` | ENOENT *rate* on path lookups. A rate, not a count: every runtime misses paths during module resolution. | statistical |
| `credential-access` | Successful opens of credential stores; deterministic when the path is also outside the profile, heuristic when the profile permits it. | both |

### C. Supply chain — the integrity of the code that is running

| Detector | Measures | Confidence |
|---|---|---|
| `entrypoint-drift` | The running binary and **its ELF interpreter** against digests pinned in the profile. The interpreter is unobservable everywhere else — the sentry maps it inside `execve`, so it appears in no trace. An attacker who replaces `ld.so` controls every dynamically linked process while leaving traced behaviour unchanged. | deterministic |
| `module-drift` | Files inside a package directory (`node_modules`, `site-packages`, …) loaded that the approved profile does not cover. The profile *is* the reviewed dependency set, so this is a dependency tree that changed after review — the practical shape of a supply-chain compromise. | deterministic |
| `native-code-load` | `.so`/`.node` loaded from an undeclared path, or worse, from a writable one. Native code bypasses every source-level audit. | deterministic |
| `unexpected-exec` | Any execution beyond the entrypoint. An MCP stdio server's base rate is ~zero. | deterministic |
| `process-spawn` | Fork/clone volume while serving. | heuristic |

### D. Temporal — when things happen

| Detector | Measures | Confidence |
|---|---|---|
| `idle-activity` | Non-housekeeping syscalls with no request in flight. Only well-defined because §6.3 serializes. Escalates to critical if idle work reaches the network. | statistical |
| `beaconing` | Coefficient of variation of the gaps between idle bursts. C2 polls on an interval; event-driven work does not. A cron-like task looks the same, hence statistical. | statistical |
| `duration-budget` | Calls exceeding the profile's own `max_duration_ms`. | deterministic |

### E. Protocol — the MCP layer

| Detector | Measures | Confidence |
|---|---|---|
| `manifest-drift` | §4.3 rug-pull: the tool manifest is hashed (name + description + schema, order-independent) and pinned at session start. | deterministic |
| `argument-access-mismatch` | Files read or written that bear no relation to the paths the call named. §5.1's typed extractor, applied after the fact against the kernel's record. Runtime internals — module loads, library mapping — are excluded, or every call would look like a mismatch. | statistical, escalating to deterministic when the unrelated path is a credential store |
| `unsolicited-traffic` | Notifications per request. All of it reaches the model as content nobody requested. | heuristic |
| `response-anomaly` | Responses far above the session norm — how injected instructions arrive at scale, measurable without reading the content that must not be trusted. | statistical |

### F. Reliability — SLO only

`error-rate`, `latency-budget`, and **`pipeline-health`**. Excluded from
the security tier by construction (§7.2: collapsing the two means a fast
malicious server outranks a slow safe one).

`pipeline-health` is the most important detector here and the easiest to
omit. Every other finding is an assertion about what the server did; all
of them are silently wrong if the engine stopped receiving events. A
monitoring system whose silence is ambiguous provides no assurance, so
degradation — tracing off, events dropped, zero events despite served
traffic — is reported as loudly as a detection, and forces the posture to
`degraded`.

## 4. False positives are the failure mode

A detector that fires on healthy traffic gets switched off, and a
switched-off detector catches nothing. This project has already learned
it once: a `/home` prefix in the sensitive-path list produced 543
findings on one reference run, none meaningful.

The defences, all tested:

- **The benign-session test.** A simulated healthy server — module
  resolution with its ENOENT probes, declared reads, responses — must
  produce zero findings at low severity or above. It is the single most
  important test in `sandbox/analyze`.
- **Startup is a separate window.** A Node runtime makes thousands of
  syscalls resolving modules before answering anything. Attributed to
  idle, that alone would flag every server. Handshake windows are marked
  `Synthetic`: excluded from request statistics and from the idle budget,
  **but still analysed** — module loading is where supply-chain drift
  actually shows up.
- **Rates, not counts**, wherever a runtime does the thing legitimately.
- **Robust estimators**, so the outlier cannot move the threshold it is
  measured against.
- **Deduplication by key.** Ten thousand undeclared reads are one finding
  with a count of ten thousand.

## 5. Two scores, never one

```
posture ∈ {trusted, watch, degraded, quarantine}   ← gates admission
reliability = {error rate, p50, p99, uptime}        ← SLO, never authorization
```

Tier rules:

| Condition | Tier |
|---|---|
| deterministic critical | `quarantine` |
| deterministic high | `degraded` |
| analysis pipeline degraded | `degraded` |
| statistical critical | `watch` |
| any high or medium | `watch` |
| otherwise | `trusted` |

Discrete tiers because "why did this drop from 71 to 68" has no useful
answer, and because a number invites averaging — which is how a critical
confinement gap gets diluted by a hundred clean requests.

## 6. Audit (§7.1 / §8.1)

Append-only JSONL, hash-chained, with an ed25519-signed checkpoint every
N entries. Three properties, each rejecting an easier design:

- **Chained, not per-entry signed** — same tamper-evidence, a fraction of
  the cost, and this is on every request's path.
- **Never blocks the response path** — buffered queue, writer goroutine.
- **Records its own gaps** — if the buffer fills, a gap marker enters the
  chain. A verified chain with missing requests is distinguishable from a
  verified chain that is complete. An audit log that can lose entries
  invisibly is not an audit log.

`warden-audit -verify` recomputes every hash, checks every link, and
verifies every checkpoint signature from the file alone — deliberately a
separate binary, because a log whose only verifier is the process that
wrote it proves very little.

Entries follow §8.1 exactly. `authorization` and `response_guard` are
typed and emitted as explicit `null`: IBAC and the response guard are v1,
and an explicit null is an honest statement that no authorization
decision was made, which a missing field is not. The `sandbox` block is
extended additively with the byte-flow and fan-out measurements.

## 7. Cost

Tracing every syscall is expensive — the sentry formats and writes a line
per call. `-analyze detect` (the default) traces only
`runsc.DetectionSyscalls`, the set the detectors actually read, derived
from what `Engine.applyLocked` switches on. A server's hot loop is
`futex`, `epoll_wait` and `clock_gettime`, none of which any detector
reads.

Bounds for a process expected to run for weeks: the event channel drops
(counted) rather than growing; trace files are truncated behind the read
offset past `-trace-max-bytes`; distinct paths and dials are capped with
counted overflow; retained windows are a fixed ring while session
aggregates are fixed-size.

**Adding a detector that needs a new syscall means adding it to
`DetectionSyscalls` too, or the detector silently sees nothing.**

## 8. Known limits

- **`connect` address decoding is format-dependent.** `SockAddr` parses
  gVisor's rendering field-by-field and degrades to "socket, address
  unknown" rather than guessing. Byte-flow accounting stays correct even
  when the destination does not.
- **Cross-container percentiles are approximate.** Exact quantiles need
  the raw samples; the session view summarises from per-container
  summaries and says so. Per-container percentiles are exact.
- **Landlock is unavailable inside gVisor** (ABI 0, proven empirically).
  Filesystem confinement is mount topology; `path-drift` measures against
  the profile regardless.
- **No in-kernel enforcement of behavioural findings.** Findings are
  advisory by design; killing on them is Tetragon, v2.
