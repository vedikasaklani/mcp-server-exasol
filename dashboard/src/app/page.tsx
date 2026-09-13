"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  type RuntimeEvent,
  type RuntimeFinding,
  type ServerSummary,
} from "@/lib/api";
import {
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  LiveBadge,
  Mono,
  PageHeader,
  ScoreRing,
  SeverityBadge,
  SeverityBar,
  Sparkline,
  Spinner,
  StatCard,
  num,
  relativeTime,
} from "@/components/ui";

interface Row {
  server: ServerSummary;
  live: boolean;
  findings: RuntimeFinding[];
  events: RuntimeEvent[];
}

export default function OverviewPage() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scoring, setScoring] = useState(false);

  const load = useCallback(async () => {
    try {
      const servers = await api.listServers();
      const built = await Promise.all(
        servers.map(async (server) => {
          const [live, findings, events] = await Promise.all([
            api.getLiveStatus(server.server_id).then((s) => s.running).catch(() => false),
            api.getRuntimeFindings(server.server_id, 50).catch(() => []),
            api.getRuntimeEvents(server.server_id, 200).catch(() => []),
          ]);
          return { server, live, findings, events };
        })
      );
      setRows(built);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach the backend");
    }
  }, []);

  useEffect(() => {
    const first = window.setTimeout(() => void load(), 0);
    const id = setInterval(load, 15000);
    return () => {
      window.clearTimeout(first);
      clearInterval(id);
    };
  }, [load]);

  const agg = useMemo(() => {
    const out = {
      servers: rows?.length ?? 0,
      live: 0,
      calls: 0,
      flagged: 0,
      blocked: 0,
      severity: { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>,
      scored: [] as number[],
      volume: [] as number[],
      alerts: [] as Array<RuntimeFinding & { source: string }>,
    };
    if (!rows) return out;
    const buckets = new Array(24).fill(0);
    const now = Date.now();
    rows.forEach(({ server, live, findings, events }) => {
      if (live) out.live += 1;
      if (server.overall_score !== null) out.scored.push(server.overall_score);
      findings.forEach((f) => {
        const s = f.severity?.toLowerCase();
        if (s in out.severity) out.severity[s] += 1;
        out.alerts.push({ ...f, source: server.source });
      });
      events.forEach((e) => {
        out.calls += 1;
        if (e.decision === "FLAGGED") out.flagged += 1;
        if (e.decision === "BLOCKED") out.blocked += 1;
        const t = new Date(e.event_ts.includes("T") ? e.event_ts : e.event_ts.replace(" ", "T") + "Z").getTime();
        const age = (now - t) / 60000; // minutes
        if (age >= 0 && age < 120) buckets[23 - Math.floor(age / 5)] += 1;
      });
    });
    out.volume = buckets;
    out.alerts.sort((a, b) => (a.event_ts < b.event_ts ? 1 : -1));
    return out;
  }, [rows]);

  const avgScore = agg.scored.length
    ? agg.scored.reduce((a, b) => a + b, 0) / agg.scored.length
    : null;
  const criticalHigh = agg.severity.critical + agg.severity.high;
  const totalFindings = Object.values(agg.severity).reduce((a, b) => a + b, 0);

  const recompute = async () => {
    setScoring(true);
    try {
      await api.computeScores();
      await load();
    } finally {
      setScoring(false);
    }
  };

  if (error) return <ErrorState message={error} onRetry={load} />;
  if (!rows) return <Spinner label="Loading fleet…" />;

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="Posture across every MCP server this gateway admits."
        right={
          <div className="flex items-center gap-2">
            <Button onClick={recompute} disabled={scoring}>
              {scoring ? "Recomputing…" : "Recompute reputation"}
            </Button>
            <Link href="/discovery">
              <Button variant="primary">Connect a server</Button>
            </Link>
          </div>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Registered servers"
          value={agg.servers}
          hint={`${agg.live} confined and serving now`}
        />
        <StatCard
          label="Calls observed"
          value={num(agg.calls)}
          chart={<Sparkline values={agg.volume} />}
          hint="last 2 hours"
        />
        <StatCard
          label="Security findings"
          value={totalFindings}
          tone={criticalHigh > 0 ? "bad" : totalFindings > 0 ? "warn" : "good"}
          hint={`${criticalHigh} critical or high`}
        />
        <StatCard
          label="Mean reputation"
          value={avgScore === null ? "—" : avgScore.toFixed(1)}
          tone={avgScore === null ? "default" : avgScore >= 80 ? "good" : avgScore >= 50 ? "warn" : "bad"}
          chart={<ScoreRing score={avgScore} size={44} />}
          hint={`${agg.scored.length} of ${agg.servers} scored`}
        />
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-[1.35fr_1fr]">
        <Card padded={false}>
          <CardHeader
            title="Fleet"
            subtitle="Reputation, confinement state and call volume per server"
            right={<Link href="/discovery" className="text-[12px] text-accent hover:underline">Discovery →</Link>}
          />
          {rows.length === 0 ? (
            <EmptyState title="No servers registered" hint="Connect one to begin." />
          ) : (
            <div className="divide-y divide-border">
              {rows
                .slice()
                .sort((a, b) => (a.server.overall_score ?? 101) - (b.server.overall_score ?? 101))
                .map(({ server, live, findings, events }) => {
                  const counts = findings.reduce<Record<string, number>>((acc, f) => {
                    const s = f.severity?.toLowerCase() ?? "none";
                    acc[s] = (acc[s] || 0) + 1;
                    return acc;
                  }, {});
                  return (
                    <div key={server.server_id} className="flex items-center gap-4 px-5 py-3.5">
                      <ScoreRing score={server.overall_score} size={46} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="truncate text-[13px] font-medium text-text">{server.source}</span>
                          <LiveBadge live={live} />
                        </div>
                        <div className="mt-1.5">
                          <SeverityBar counts={counts} />
                        </div>
                        <div className="mt-1.5 flex flex-wrap items-center gap-x-3 text-[11.5px] text-text-faint">
                          <span className="tabular">{events.length} calls</span>
                          <span className="tabular">{findings.length} findings</span>
                          {server.security_score !== null && (
                            <span className="tabular">security {server.security_score}</span>
                          )}
                          {server.overall_score === null && <span>not yet scored</span>}
                        </div>
                      </div>
                      <Link
                        href="/monitoring"
                        className="shrink-0 text-[12px] text-text-faint transition-colors hover:text-accent"
                      >
                        Monitor →
                      </Link>
                    </div>
                  );
                })}
            </div>
          )}
        </Card>

        <Card padded={false}>
          <CardHeader
            title="Security alerts"
            subtitle="Behavioural findings from confined sessions, newest first"
            right={<Link href="/audit" className="text-[12px] text-accent hover:underline">Audit →</Link>}
          />
          {agg.alerts.length === 0 ? (
            <EmptyState
              title="Nothing detected"
              hint="Findings appear here when a confined server does something outside its approved profile."
            />
          ) : (
            <div className="max-h-[520px] divide-y divide-border overflow-y-auto">
              {agg.alerts.slice(0, 25).map((f, i) => (
                <div key={i} className="px-5 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={f.severity} />
                      <span className="text-[12.5px] font-medium text-text">{f.title}</span>
                    </div>
                    <span className="shrink-0 text-[11px] text-text-faint">{relativeTime(f.event_ts)}</span>
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-2 text-[11.5px] text-text-faint">
                    <span>{f.source}</span>
                    <span>·</span>
                    <Mono>{f.detector}</Mono>
                    {f.kernel_attested && (
                      <>
                        <span>·</span>
                        <span className="text-accent">kernel-attested</span>
                      </>
                    )}
                  </div>
                  {f.detail && <p className="mt-1 text-[11.5px] leading-snug text-text-muted">{f.detail}</p>}
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
