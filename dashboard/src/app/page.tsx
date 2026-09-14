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
  PageHeader,
  ScoreRing,
  SeverityBadge,
  SeverityRing,
  Sparkline,
  Spinner,
  StatCard,
  StatusBadge,
  type ServerStatus,
  num,
} from "@/components/ui";

interface Row {
  server: ServerSummary;
  live: boolean;
  posture: string | null;
  findings: RuntimeFinding[];
  events: RuntimeEvent[];
}

const WORST_ORDER = ["critical", "high", "medium"] as const;

// The gateway only tells us "running or not"; whether that running process
// is settled and trusted, actively being punished for misbehaving, or still
// too new to have a verdict comes from its most recent session's posture.
function deriveStatus(live: boolean, posture: string | null): ServerStatus {
  if (!live) return "offline";
  if (posture === "QUARANTINE") return "quarantine";
  if (posture === "TRUSTED") return "confined";
  return "running";
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
          const [live, findings, events, sessions] = await Promise.all([
            api.getLiveStatus(server.server_id).then((s) => s.running).catch(() => false),
            api.getRuntimeFindings(server.server_id, 50).catch(() => []),
            api.getRuntimeEvents(server.server_id, 200).catch(() => []),
            api.getSessions(server.server_id, 1).catch(() => []),
          ]);
          return { server, live, posture: sessions[0]?.posture ?? null, findings, events };
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
      alerts: [] as Array<RuntimeFinding & { source: string; serverId: string }>,
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
        out.alerts.push({ ...f, source: server.source, serverId: server.server_id });
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

  // Never run and never scored - just a registration with nothing to show
  // yet. Listing those is noise; they reappear here the moment either
  // happens.
  const liveRows = rows.filter((r) => r.live || r.server.overall_score !== null);

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

      <div className="mt-8 grid gap-4 xl:grid-cols-4">
        <Card padded={false} className="xl:col-span-2">
          <CardHeader
            title="Fleet"
            subtitle="Reputation, confinement state and call volume per server"
            right={<Link href="/discovery" className="text-[12px] text-primary hover:underline">Discovery →</Link>}
          />
          {rows.length === 0 ? (
            <EmptyState title="No servers registered" hint="Connect one to begin." />
          ) : liveRows.length === 0 ? (
            <EmptyState
              title="Nothing live or scored yet"
              hint="Registered servers show up here once they've run at least once or been scored."
            />
          ) : (
            <div className="divide-y divide-border">
              {liveRows
                .slice()
                .sort((a, b) => (a.server.overall_score ?? 101) - (b.server.overall_score ?? 101))
                .map(({ server, live, posture, findings, events }) => {
                  const counts = findings.reduce<Record<string, number>>((acc, f) => {
                    const s = f.severity?.toLowerCase() ?? "none";
                    acc[s] = (acc[s] || 0) + 1;
                    return acc;
                  }, {});
                  const worst = WORST_ORDER.find((s) => counts[s]);
                  return (
                    <Link
                      key={server.server_id}
                      href={`/servers/${server.server_id}`}
                      className="flex items-center gap-4 px-5 py-3.5 transition-colors hover:bg-surface-hover"
                    >
                      {server.overall_score !== null ? (
                        <SeverityRing score={server.overall_score} counts={counts} size={46} />
                      ) : (
                        <ScoreRing score={null} size={46} />
                      )}
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="truncate text-[13px] font-medium text-text">{server.source}</span>
                          <StatusBadge status={deriveStatus(live, posture)} />
                          {worst && <SeverityBadge severity={worst} />}
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
                    </Link>
                  );
                })}
            </div>
          )}
        </Card>

        <Card padded={false} className="xl:col-span-2">
          <CardHeader
            title="Security alerts"
            subtitle="Behavioural findings from confined sessions, newest first"
            right={<Link href="/audit" className="text-[12px] text-primary hover:underline">Audit →</Link>}
          />
          {agg.alerts.length === 0 ? (
            <EmptyState
              title="Nothing detected"
              hint="Findings appear here when a confined server does something outside its approved profile."
            />
          ) : (
            <div className="max-h-[520px] divide-y divide-border overflow-y-auto">
              {agg.alerts.slice(0, 25).map((f, i) => (
                <Link
                  key={i}
                  href={`/servers/${f.serverId}#security-findings`}
                  className="flex items-start gap-2.5 px-5 py-3 transition-colors hover:bg-surface-hover"
                >
                  <SeverityBadge severity={f.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[12.5px] text-text">{f.title}</div>
                    <div className="mt-0.5 truncate text-[11px] text-text-faint">{f.source}</div>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
