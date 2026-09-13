"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  ApiError,
  api,
  type LiveMetrics,
  type ScanHistoryEntry,
  type ScanResult,
  type ServerSummary,
  type SessionSummary,
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

const POLL_MS = 3000;
const HISTORY = 40;

export default function MonitoringPage() {
  const [servers, setServers] = useState<ServerSummary[] | null>(null);
  const [selected, setSelected] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const id = window.setTimeout(async () => {
      try {
        const list = await api.listServers();
        setServers(list);
        setSelected((cur) => cur || list[0]?.server_id || "");
      } catch (e) {
        setError(e instanceof Error ? e.message : "Could not reach the backend");
      }
    }, 0);
    return () => window.clearTimeout(id);
  }, []);

  if (error) return <ErrorState message={error} />;
  if (!servers) return <Spinner label="Loading servers…" />;
  if (servers.length === 0) {
    return (
      <>
        <PageHeader title="Monitoring" subtitle="Live confinement metrics and static analysis." />
        <Card>
          <EmptyState title="No servers registered yet" hint="Register one from Discovery to begin monitoring it." />
        </Card>
      </>
    );
  }

  const server = servers.find((s) => s.server_id === selected);

  return (
    <>
      <PageHeader
        title="Monitoring"
        subtitle="Live confinement metrics, session history and static analysis, per server."
        right={
          <select
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
            className="rounded-lg border border-border bg-surface-2 px-3 py-2 text-[13px] text-text focus:border-accent focus:outline-none"
          >
            {servers.map((s) => (
              <option key={s.server_id} value={s.server_id}>
                {s.source}
              </option>
            ))}
          </select>
        }
      />
      {selected && <ServerMonitor key={selected} serverId={selected} label={server?.source ?? ""} score={server ?? null} />}
    </>
  );
}

function ServerMonitor({
  serverId,
  label,
  score,
}: {
  serverId: string;
  label: string;
  score: ServerSummary | null;
}) {
  const [metrics, setMetrics] = useState<LiveMetrics | null>(null);
  const [live, setLive] = useState<boolean | null>(null);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
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
        const p95 = m.metrics.gauges.warden_latency_p95_ms;
        if (typeof p95 === "number") latency.current = [...latency.current, p95].slice(-HISTORY);
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
          hint={metrics ? <Mono>{metrics.profile_digest.slice(0, 19)}…</Mono> : "—"}
        />
        <StatCard
          label="Reputation"
          value={score?.overall_score !== null && score?.overall_score !== undefined ? score.overall_score.toFixed(1) : "—"}
          tone={(score?.overall_score ?? 0) >= 80 ? "good" : (score?.overall_score ?? 0) >= 50 ? "warn" : "bad"}
          chart={<ScoreRing score={score?.overall_score ?? null} size={44} />}
          hint={score?.security_score !== null && score?.security_score !== undefined ? `security ${score.security_score}` : "not yet scored"}
        />
      </div>

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
              <KeyValue k="Syscalls observed" v={num(g.warden_syscalls_total ?? null)} />
              <KeyValue k="Distinct paths" v={num(g.warden_distinct_paths ?? null)} />
              <KeyValue k="File read" v={bytes(g.warden_file_read_bytes ?? null)} />
              <KeyValue k="File written" v={bytes(g.warden_file_write_bytes ?? null)} />
              <KeyValue k="Network out" v={bytes(g.warden_net_write_bytes ?? null)} />
              <KeyValue k="Network in" v={bytes(g.warden_net_read_bytes ?? null)} />
              <KeyValue k="Process spawns" v={num(g.warden_process_spawns ?? null)} />
              <KeyValue k="Containers created" v={num(c.warden_containers_created_total ?? null)} />
              <KeyValue k="Idle syscalls" v={num(g.warden_idle_syscalls ?? null)} />
              <KeyValue k="Analysis healthy" v={g.warden_analysis_healthy ? "yes" : "no"} />
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

      <ScanPanel serverId={serverId} label={label} />

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

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}
