"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  ApiError,
  api,
  type LiveMetrics,
  type RuntimeFinding,
  type ScanHistoryEntry,
  type ScanResult,
  type ServerSummary,
  type SessionSummary,
  type Tool,
} from "@/lib/api";
import {
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  KeyValue,
  LiveBadge,
  Mono,
  PageHeader,
  ScoreRing,
  SeverityBadge,
  SeverityBar,
  Sparkline,
  Spinner,
  StatCard,
  bytes,
  num,
  relativeTime,
} from "@/components/ui";
import { Modal } from "@/components/Modal";

const POLL_MS = 3000;
const HISTORY = 40;

export function ServerDetail({ serverId }: { serverId: string }) {
  const [servers, setServers] = useState<ServerSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const id = window.setTimeout(async () => {
      try {
        setServers(await api.listServers());
      } catch (e) {
        setError(e instanceof Error ? e.message : "Could not reach the backend");
      }
    }, 0);
    return () => window.clearTimeout(id);
  }, []);

  if (error) return <ErrorState message={error} />;
  if (!servers) return <Spinner label="Loading server…" />;

  const server = servers.find((s) => s.server_id === serverId);
  if (!server) {
    return (
      <>
        <PageHeader
          title="Server not found"
          subtitle="It may have been removed."
          right={
            <Link href="/discovery" className="text-[12px] text-primary hover:underline">
              ← Discovery
            </Link>
          }
        />
      </>
    );
  }

  return <ServerBody server={server} />;
}

function ServerBody({ server }: { server: ServerSummary }) {
  const serverId = server.server_id;
  const [metrics, setMetrics] = useState<LiveMetrics | null>(null);
  const [live, setLive] = useState<boolean | null>(null);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [tools, setTools] = useState<Tool[] | null>(null);
  const [findings, setFindings] = useState<RuntimeFinding[] | null>(null);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const [callTarget, setCallTarget] = useState<Tool | null>(null);
  const rps = useRef<number[]>([]);
  const latency = useRef<number[]>([]);
  const lastRequests = useRef<number | null>(null);

  const poll = useCallback(async () => {
    try {
      const status = await api.getLiveStatus(serverId);
      setLive(status.running);
      if (!status.running) {
        setMetrics(null);
        return;
      }
      const m = await api.getLiveMetrics(serverId);
      setMetrics(m);
      if (m) {
        const total = m.metrics.counters.warden_requests_total ?? 0;
        if (lastRequests.current !== null) {
          const delta = Math.max(0, total - lastRequests.current);
          rps.current = [...rps.current, delta / (POLL_MS / 1000)].slice(-HISTORY);
        }
        lastRequests.current = total;
        const syscalls = m.metrics.gauges.warden_syscalls_observed;
        if (typeof syscalls === "number") latency.current = [...latency.current, syscalls].slice(-HISTORY);
      }
    } catch {
      setLive(false);
    }
  }, [serverId]);

  useEffect(() => {
    const first = window.setTimeout(() => void poll(), 0);
    const id = setInterval(poll, POLL_MS);
    return () => {
      window.clearTimeout(first);
      clearInterval(id);
    };
  }, [poll]);

  useEffect(() => {
    const id = window.setTimeout(async () => {
      try {
        setSessions(await api.getSessions(serverId, 10));
      } catch {
        setSessions([]);
      }
      try {
        setTools(await api.getTools(serverId));
      } catch {
        setTools([]);
      }
      try {
        setFindings(await api.getRuntimeFindings(serverId, 100));
      } catch {
        setFindings([]);
      }
    }, 0);
    return () => window.clearTimeout(id);
  }, [serverId]);

  const start = async () => {
    setStarting(true);
    setStartError(null);
    try {
      await api.getLiveTools(serverId);
      await poll();
    } catch (e) {
      setStartError(e instanceof ApiError ? e.message : "Could not start a session");
    } finally {
      setStarting(false);
    }
  };

  const g = metrics?.metrics.gauges ?? {};
  const c = metrics?.metrics.counters ?? {};

  return (
    <>
      <PageHeader
        title={server.source}
        subtitle="Score, exposed tools, live confinement and static analysis for this server."
        right={
          <div className="flex items-center gap-3">
            <LiveBadge live={!!live} />
            <Link href="/discovery" className="text-[12px] text-text-faint transition-colors hover:text-primary">
              ← Discovery
            </Link>
          </div>
        }
      />

      <div className="space-y-5">
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="Gateway"
            value={live === null ? "…" : live ? "Serving" : "Offline"}
            tone={live ? "good" : "default"}
            hint={metrics ? `pool of ${metrics.pool_size} confined containers` : "no confined process running"}
          />
          <StatCard
            label="Requests served"
            value={num(c.warden_requests_total ?? null)}
            chart={<Sparkline values={rps.current} />}
            hint={`${(rps.current.at(-1) ?? 0).toFixed(2)}/s now`}
          />
          <StatCard
            label="Uptime"
            value={metrics ? formatUptime(metrics.metrics.uptime_seconds) : "—"}
            chart={<Sparkline values={latency.current} stroke="var(--sev-low)" />}
            hint={metrics ? `${num(g.warden_syscalls_observed ?? null)} syscalls observed` : "—"}
          />
          <StatCard
            label="Reputation"
            value={server.overall_score !== null ? server.overall_score.toFixed(1) : "—"}
            tone={(server.overall_score ?? 0) >= 80 ? "good" : (server.overall_score ?? 0) >= 50 ? "warn" : "bad"}
            chart={<ScoreRing score={server.overall_score} size={44} />}
            hint={server.security_score !== null ? `security ${server.security_score}` : "not yet scored"}
          />
        </div>

        <Card padded={false}>
          <CardHeader
            title="Tools"
            subtitle="Everything this server exposes, declared or observed"
            right={tools && <span className="text-[12px] text-text-faint">{num(tools.length)} total</span>}
          />
          {tools === null ? (
            <div className="px-5 py-6">
              <Spinner label="Loading tools…" />
            </div>
          ) : tools.length === 0 ? (
            <EmptyState
              title="Nothing discovered yet"
              hint="Scan it or start a confined session to populate the catalogue."
            />
          ) : (
            <ul className="max-h-[420px] divide-y divide-border overflow-y-auto px-5">
              {tools.map((t) => (
                <li key={t.name} className="flex items-start justify-between gap-3 py-3">
                  <div className="min-w-0">
                    <Mono className="text-text">{t.name}</Mono>
                    {t.description && (
                      <p className="mt-0.5 max-w-xl truncate text-[11.5px] text-text-faint">{t.description}</p>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wide ${
                        t.source === "observed" ? "bg-primary/12 text-primary" : "bg-surface-2 text-text-faint"
                      }`}
                      title={
                        t.source === "observed"
                          ? "Advertised by the running server"
                          : "Extracted from source by static analysis"
                      }
                    >
                      {t.source || "—"}
                    </span>
                    <Button size="sm" onClick={() => setCallTarget(t)}>
                      Run
                    </Button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card padded={false} id="security-findings">
          <CardHeader
            title="Security findings"
            subtitle="Behavioural findings from confined sessions, newest first"
            right={findings && <span className="text-[12px] text-text-faint">{findings.length} total</span>}
          />
          {findings === null ? (
            <div className="px-5 py-6">
              <Spinner label="Loading findings…" />
            </div>
          ) : findings.length === 0 ? (
            <EmptyState
              title="Nothing detected"
              hint="Findings appear here when this server does something outside its approved profile."
            />
          ) : (
            <div className="max-h-[420px] divide-y divide-border overflow-y-auto">
              {findings
                .slice()
                .sort((a, b) => (a.event_ts < b.event_ts ? 1 : -1))
                .map((f, i) => (
                  <div key={i} className="px-5 py-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={f.severity} />
                        <span className="text-[12.5px] text-text">{f.title}</span>
                      </div>
                      <span className="shrink-0 text-[11px] text-text-faint">{relativeTime(f.event_ts)}</span>
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-[11.5px] text-text-faint">
                      <Mono>{f.detector}</Mono>
                      {f.kernel_attested && (
                        <>
                          <span>·</span>
                          <span className="text-primary">kernel-attested</span>
                        </>
                      )}
                    </div>
                    {f.detail && <p className="mt-1 text-[11.5px] leading-snug text-text-muted">{f.detail}</p>}
                    {f.evidence?.length > 0 && (
                      <ul className="mt-1.5 space-y-0.5">
                        {f.evidence.slice(0, 4).map((e, j) => (
                          <li key={j} className="font-mono text-[11px] text-text-faint">
                            {e}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                ))}
            </div>
          )}
        </Card>

        {!live && (
          <Card>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-[13px] text-text">This server has no confined process running.</p>
                <p className="mt-0.5 text-[12px] text-text-faint">
                  Starting one clones or installs the source, generates a capability profile from a
                  learning run, then warms a gVisor container pool. First start takes a minute.
                </p>
              </div>
              <Button variant="primary" onClick={start} disabled={starting}>
                {starting ? "Starting…" : "Start confined session"}
              </Button>
            </div>
            {startError && <p className="mt-3 text-[12.5px] text-danger">{startError}</p>}
          </Card>
        )}

        {live && metrics && (
          <div className="grid gap-5 xl:grid-cols-3">
            <Card padded={false} className="xl:col-span-2">
              <CardHeader
                title="Confinement telemetry"
                subtitle="Straight from the gateway, refreshed every 3 seconds"
                right={<LiveBadge live />}
              />
              <div className="grid gap-x-8 gap-y-1 px-5 py-4 sm:grid-cols-2">
                <KeyValue k="Syscalls observed" v={num(g.warden_syscalls_observed ?? null)} />
                <KeyValue k="Distinct paths" v={num(g.warden_distinct_paths ?? null)} />
                <KeyValue k="File read" v={bytes(g.warden_file_read_bytes ?? null)} />
                <KeyValue k="File written" v={bytes(g.warden_file_write_bytes ?? null)} />
                <KeyValue k="Network out" v={bytes(g.warden_net_write_bytes ?? null)} />
                <KeyValue k="Network in" v={bytes(g.warden_net_read_bytes ?? null)} />
                <KeyValue k="Network destinations" v={num(g.warden_network_destinations ?? null)} />
                <KeyValue k="Process spawns" v={num(g.warden_process_spawns ?? null)} />
                <KeyValue k="Idle syscalls" v={num(g.warden_idle_syscalls ?? null)} />
                <KeyValue k="Containers created" v={num(c.warden_containers_created_total ?? null)} />
                <KeyValue k="Containers quarantined" v={num(c.warden_containers_quarantined_total ?? null)} />
                <KeyValue k="Requests failed" v={num(c.warden_request_failures_total ?? null)} />
                <KeyValue k="Pool idle / in use" v={`${num(g.warden_pool_idle ?? null)} / ${num(g.warden_pool_in_use ?? null)}`} />
                {/* A dropped trace event is a gap in the evidence, so it is
                    reported rather than quietly averaged away. */}
                <KeyValue k="Trace events" v={`${num(g.warden_trace_events_ingested ?? null)} in, ${num(g.warden_trace_events_dropped ?? null)} dropped`} />
              </div>
              <div className="border-t border-border px-5 py-4">
                <div className="eyebrow mb-2">Findings in this session</div>
                <div className="flex flex-wrap items-center gap-2">
                  {(["critical", "high", "medium", "low"] as const).map((s) => (
                    <span key={s} className="flex items-center gap-1.5">
                      <SeverityBadge severity={s} />
                      <span className="tabular text-[13px] text-text">
                        {num(g[`warden_findings_${s}`] ?? 0)}
                      </span>
                    </span>
                  ))}
                  <span className="ml-2 text-[11.5px] text-text-faint">
                    {num(g.warden_findings_deterministic ?? 0)} kernel-attested
                  </span>
                </div>
                <div className="mt-3">
                  <SeverityBar
                    counts={{
                      critical: g.warden_findings_critical ?? 0,
                      high: g.warden_findings_high ?? 0,
                      medium: g.warden_findings_medium ?? 0,
                      low: g.warden_findings_low ?? 0,
                    }}
                  />
                </div>
              </div>
            </Card>

            <Card padded={false}>
              <CardHeader title="Target" subtitle="What is actually running inside the sandbox" />
              <div className="space-y-1 px-5 py-4">
                <KeyValue k="Command" v={<Mono>{metrics.target}</Mono>} />
                <KeyValue k="Pool size" v={num(metrics.pool_size)} />
                <KeyValue k="Ready" v={metrics.ready ? "yes" : "warming"} />
                <KeyValue k="Profile" v={<Mono>{metrics.profile_digest.slice(7, 27)}…</Mono>} />
              </div>
            </Card>
          </div>
        )}

        <ScanPanel serverId={serverId} label={server.source} />

        <Card padded={false}>
          <CardHeader title="Session history" subtitle="Completed confined sessions, newest first" />
          {sessions.length === 0 ? (
            <EmptyState title="No completed sessions yet" hint="A session is recorded when its gateway shuts down." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-[12.5px]">
                <thead>
                  <tr className="border-b border-border text-left">
                    {["Started", "Posture", "Requests", "Critical", "High", "Denials", "Confinement"].map((h) => (
                      <th key={h} className="eyebrow px-4 py-2.5">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((s) => (
                    <tr key={s.session_id} className="border-b border-border/60">
                      <td className="px-4 py-2 text-text-muted">{relativeTime(s.started_at)}</td>
                      <td className="px-4 py-2">
                        <SeverityBadge
                          severity={s.posture === "TRUSTED" ? "none" : s.posture === "QUARANTINE" ? "critical" : "medium"}
                          label={s.posture}
                        />
                      </td>
                      <td className="tabular px-4 py-2 text-text-muted">{num(s.requests)}</td>
                      <td className="tabular px-4 py-2 text-sev-critical">{num(s.critical)}</td>
                      <td className="tabular px-4 py-2 text-sev-high">{num(s.high)}</td>
                      <td className="tabular px-4 py-2 text-text-muted">{num(s.denials)}</td>
                      <td className="px-4 py-2 text-text-faint">{s.confinement}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      {callTarget && (
        <CallModal
          serverId={serverId}
          label={server.source}
          tool={callTarget}
          onClose={() => setCallTarget(null)}
        />
      )}
    </>
  );
}

function ScanPanel({ serverId, label }: { serverId: string; label: string }) {
  const [history, setHistory] = useState<ScanHistoryEntry[] | null>(null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadHistory = useCallback(async () => {
    try {
      setHistory(await api.getScans(serverId));
    } catch {
      setHistory([]);
    }
  }, [serverId]);

  useEffect(() => {
    const id = window.setTimeout(() => void loadHistory(), 0);
    return () => window.clearTimeout(id);
  }, [loadHistory]);

  const runScan = async () => {
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      const r = await api.runScan(serverId);
      setResult(r);
      await loadHistory();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scan failed");
    } finally {
      setRunning(false);
    }
  };

  const latest = result
    ? { verdict: result.verdict, counts: result.severity_counts, findings: result.findings }
    : history?.[0]
      ? { verdict: history[0].verdict ?? "—", counts: history[0].severity_counts, findings: history[0].findings }
      : null;

  return (
    <Card padded={false}>
      <CardHeader
        title="Static analysis"
        subtitle={`Fetch ${label}'s source and scan it for the findings that disqualify a server`}
        right={
          <Button variant="primary" onClick={runScan} disabled={running}>
            {running ? "Scanning…" : "Run scan"}
          </Button>
        }
      />

      {running && (
        <div className="px-5 py-6">
          <Spinner label="Fetching source and applying rules…" />
        </div>
      )}
      {error && <div className="px-5 py-4"><ErrorState message={error} onRetry={runScan} /></div>}

      {!running && !error && !latest && (
        <EmptyState title="Not scanned yet" hint="Run a scan to see what the source contains before it runs." />
      )}

      {!running && latest && (
        <div className="px-5 py-4">
          <div className="flex flex-wrap items-center gap-3">
            <span
              className={`rounded-md border px-2.5 py-1 text-[12px] font-semibold uppercase tracking-wide ${
                latest.verdict === "fail"
                  ? "border-danger/35 bg-danger/10 text-danger"
                  : latest.verdict === "pass"
                    ? "border-success/30 bg-success/10 text-success"
                    : "border-sev-medium/30 bg-sev-medium/10 text-sev-medium"
              }`}
            >
              {latest.verdict.replace(/_/g, " ")}
            </span>
            {(["critical", "high", "medium", "low"] as const).map((s) =>
              latest.counts[s] ? (
                <span key={s} className="flex items-center gap-1.5">
                  <SeverityBadge severity={s} />
                  <span className="tabular text-[13px]">{latest.counts[s]}</span>
                </span>
              ) : null
            )}
            {result?.package?.name && (
              <Mono className="ml-auto text-text-faint">
                {result.package.name}@{result.package.version} · {result.package.dependencies} deps
              </Mono>
            )}
          </div>

          <div className="mt-3">
            <SeverityBar counts={latest.counts} />
          </div>

          {latest.findings.length === 0 ? (
            <p className="mt-4 text-[12.5px] text-text-muted">
              No rule matched. The scan covers committed credentials, arbitrary execution,
              credential-path reads and instruction-shaped tool metadata.
            </p>
          ) : (
            <div className="mt-4 overflow-hidden rounded-lg border border-border">
              <table className="w-full text-[12.5px]">
                <thead>
                  <tr className="border-b border-border bg-surface-2 text-left">
                    {["Severity", "Rule", "Finding", "Location"].map((h) => (
                      <th key={h} className="eyebrow px-3 py-2">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {latest.findings.map((f, i) => (
                    <tr key={i} className="border-b border-border/60 last:border-0">
                      <td className="px-3 py-2"><SeverityBadge severity={f.severity} /></td>
                      <td className="px-3 py-2"><Mono className="text-text-muted">{f.rule_id}</Mono></td>
                      <td className="px-3 py-2 text-text">{f.message}</td>
                      <td className="px-3 py-2">
                        <Mono className="text-text-faint">
                          {(f.file_path ?? f.file ?? "?")}:{f.line ?? "?"}
                        </Mono>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {history && history.length > 1 && (
            <div className="mt-4">
              <div className="eyebrow mb-2">Previous scans</div>
              <div className="space-y-1">
                {history.slice(1, 6).map((h) => (
                  <div key={h.scan_run_id} className="flex items-center gap-3 text-[12px] text-text-muted">
                    <span className="text-text-faint">{relativeTime(h.started_at ?? "")}</span>
                    <Mono className="text-text-faint">{h.commit_sha.slice(0, 10)}</Mono>
                    <span>{h.verdict ?? h.status}</span>
                    <span className="tabular text-text-faint">
                      {Object.values(h.severity_counts).reduce((a, b) => a + b, 0)} findings
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

// A JSON value shaped to match a schema property's declared type, so the
// textarea starts as a fillable template instead of an empty "{}" a
// non-developer has no way to guess the shape of.
function placeholderFor(prop: Record<string, unknown>): unknown {
  switch (prop.type) {
    case "integer":
    case "number":
      return 0;
    case "boolean":
      return false;
    case "array":
      return [];
    case "object":
      return {};
    default:
      return "";
  }
}

function starterArgs(schema: Record<string, unknown> | null | undefined): Record<string, unknown> {
  const properties = (schema?.properties ?? {}) as Record<string, Record<string, unknown>>;
  const required = new Set((schema?.required as string[] | undefined) ?? []);
  const args: Record<string, unknown> = {};
  for (const [name, prop] of Object.entries(properties)) {
    if (required.has(name) || Object.keys(properties).length <= 6) {
      args[name] = placeholderFor(prop);
    }
  }
  return args;
}

// "product_id (integer, required)" per field, for a one-line hint under the
// arguments box - the collapsible full schema is there too, but most people
// won't open it before asking what to type.
function fieldHints(schema: Record<string, unknown> | null | undefined): string[] {
  const properties = (schema?.properties ?? {}) as Record<string, Record<string, unknown>>;
  const required = new Set((schema?.required as string[] | undefined) ?? []);
  return Object.entries(properties).map(([name, prop]) => {
    const type = typeof prop.type === "string" ? prop.type : "any";
    return `${name} (${type}${required.has(name) ? ", required" : ""})`;
  });
}

function CallModal({
  serverId,
  label,
  tool,
  onClose,
}: {
  serverId: string;
  label: string;
  tool: Tool;
  onClose: () => void;
}) {
  const [args, setArgs] = useState(() => JSON.stringify(starterArgs(tool.parameter_schema), null, 2));
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const parsed = JSON.parse(args || "{}");
      const res = await api.callTool(serverId, tool.name, parsed);
      setResult(JSON.stringify(res, null, 2));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : e instanceof Error ? e.message : "Call failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title={`Run ${tool.name}`} onClose={onClose} wide>
      <p className="text-[12.5px] text-text-muted">
        {label}
        {tool.description ? ` · ${tool.description}` : ""}
      </p>

      {Object.keys(tool.parameter_schema ?? {}).length > 0 && (
        <details className="mt-3">
          <summary className="cursor-pointer text-[12px] text-text-faint hover:text-text-muted">
            Parameter schema
          </summary>
          <pre className="mt-2 overflow-x-auto rounded-lg border border-border bg-surface p-3 font-mono text-[11px] text-text-muted">
            {JSON.stringify(tool.parameter_schema, null, 2)}
          </pre>
        </details>
      )}

      <div className="eyebrow mb-1.5 mt-4">Arguments (JSON)</div>
      {fieldHints(tool.parameter_schema).length > 0 && (
        <p className="mb-1.5 text-[11.5px] text-text-faint">{fieldHints(tool.parameter_schema).join(" · ")}</p>
      )}
      <textarea
        value={args}
        onChange={(e) => setArgs(e.target.value)}
        rows={5}
        className="w-full rounded-lg border border-border bg-surface px-3 py-2 font-mono text-[12px] text-text transition-colors focus:border-primary focus:outline-none focus:ring-[3px] focus:ring-primary/15"
      />

      <div className="mt-3 flex items-center justify-between gap-3">
        <p className="text-[11.5px] text-text-faint">
          Executes inside gVisor. The call is audited in real time — check the Audit Trail after.
        </p>
        <Button variant="primary" onClick={run} disabled={busy}>
          {busy ? "Running…" : "Run tool"}
        </Button>
      </div>

      {error && (
        <pre className="mt-3 overflow-x-auto whitespace-pre-wrap rounded-lg border border-danger/30 bg-danger/5 p-3 font-mono text-[11.5px] text-danger">
          {error}
        </pre>
      )}
      {result && (
        <pre className="mt-3 max-h-72 overflow-auto rounded-lg border border-border bg-surface p-3 font-mono text-[11.5px] text-text-muted">
          {result}
        </pre>
      )}
    </Modal>
  );
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}
