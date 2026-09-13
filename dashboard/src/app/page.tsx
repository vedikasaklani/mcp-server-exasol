"use client";

import { useEffect, useState } from "react";
import {
  api,
  ApiError,
  LiveStatus,
  RuntimeFinding,
  ServerSummary,
} from "@/lib/api";
import { Badge, Card, CardHeader, EmptyState, ErrorState, SeverityBadge, Spinner, StatCard } from "@/components/ui";
import Link from "next/link";

interface AlertRow extends RuntimeFinding {
  server_id: string;
  server_source: string;
}

export default function OverviewPage() {
  const [servers, setServers] = useState<ServerSummary[] | null>(null);
  const [liveStatus, setLiveStatus] = useState<Record<string, LiveStatus>>({});
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const list = await api.listServers();
        if (cancelled) return;
        setServers(list);
        setError(null);

        const [statuses, findingsPerServer] = await Promise.all([
          Promise.all(
            list.map(async (s) => {
              try {
                return [s.server_id, await api.getLiveStatus(s.server_id)] as const;
              } catch {
                return [s.server_id, { running: false, address: null }] as const;
              }
            })
          ),
          Promise.all(
            list.map(async (s) => {
              try {
                const findings = await api.getRuntimeFindings(s.server_id, 10);
                return findings.map((f) => ({ ...f, server_id: s.server_id, server_source: s.source }));
              } catch {
                return [] as AlertRow[];
              }
            })
          ),
        ]);
        if (cancelled) return;
        setLiveStatus(Object.fromEntries(statuses));
        setAlerts(
          findingsPerServer
            .flat()
            .sort((a, b) => (a.event_ts < b.event_ts ? 1 : -1))
            .slice(0, 8)
        );
      } catch (e) {
        if (!cancelled) setError(e instanceof ApiError ? e.message : "Could not reach the backend API.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    const id = setInterval(load, 20000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  if (error && !servers) {
    return (
      <div>
        <PageHeader />
        <Card className="mt-6">
          <ErrorState message={`${error} — is server_management.api.api running on NEXT_PUBLIC_API_BASE_URL?`} />
        </Card>
      </div>
    );
  }

  const liveCount = Object.values(liveStatus).filter((s) => s.running).length;
  const criticalOrHigh = alerts.filter((a) => ["CRITICAL", "HIGH"].includes(a.severity?.toUpperCase())).length;
  const avgReputation =
    servers && servers.length
      ? Math.round(
          (servers.reduce((sum, s) => sum + (s.overall_score ?? 0), 0) /
            servers.filter((s) => s.overall_score !== null).length || 0) * 10
        ) / 10
      : null;

  return (
    <div>
      <PageHeader />

      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Active MCP Servers"
          value={loading ? <Spinner /> : (servers?.length ?? 0)}
          hint="registered &amp; discoverable"
        />
        <StatCard
          label="Live Sessions"
          value={loading ? <Spinner /> : liveCount}
          hint="confined &amp; serving traffic now"
          tone={liveCount > 0 ? "success" : "neutral"}
        />
        <StatCard
          label="Security Alerts"
          value={loading ? <Spinner /> : alerts.length}
          hint={`${criticalOrHigh} critical/high`}
          tone={criticalOrHigh > 0 ? "danger" : alerts.length > 0 ? "warning" : "neutral"}
        />
        <StatCard
          label="Avg. Reputation"
          value={loading ? <Spinner /> : avgReputation !== null ? avgReputation : "—"}
          hint="overall trust score / 100"
          tone={avgReputation !== null && avgReputation < 60 ? "warning" : "neutral"}
        />
      </div>

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          <CardHeader
            title="Recent Security Alerts"
            subtitle="Latest behavioral findings across every server, most recent first"
          />
          {loading ? (
            <div className="flex justify-center py-12">
              <Spinner />
            </div>
          ) : alerts.length === 0 ? (
            <EmptyState title="No findings recorded" hint="Findings from confined sessions will appear here as servers run." />
          ) : (
            <ul className="divide-y divide-border">
              {alerts.map((a, i) => (
                <li key={i} className="flex items-start justify-between gap-4 px-5 py-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={a.severity} />
                      <span className="truncate text-sm text-text">{a.title}</span>
                    </div>
                    <p className="mt-1 truncate text-xs text-text-faint">
                      {a.server_source} · {a.detector}
                      {a.kernel_attested && " · kernel-attested"}
                    </p>
                  </div>
                  <span className="shrink-0 text-xs text-text-faint">{relativeTime(a.event_ts)}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader title="Connection Health" subtitle="Live gateway status per server" />
          {loading ? (
            <div className="flex justify-center py-12">
              <Spinner />
            </div>
          ) : !servers || servers.length === 0 ? (
            <EmptyState title="No servers registered yet" hint="Register one from the Discovery Hub to see it here." />
          ) : (
            <ul className="divide-y divide-border">
              {servers.map((s) => {
                const status = liveStatus[s.server_id];
                return (
                  <li key={s.server_id} className="flex items-center justify-between gap-3 px-5 py-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm text-text">{s.source}</p>
                      <p className="text-xs text-text-faint">
                        {s.overall_score !== null ? `reputation ${s.overall_score}` : "not yet scored"}
                      </p>
                    </div>
                    <Badge tone={status?.running ? "success" : "neutral"}>
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${status?.running ? "bg-emerald-400" : "bg-text-faint"}`}
                      />
                      {status?.running ? "Live" : "Offline"}
                    </Badge>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}

function PageHeader() {
  return (
    <div className="flex items-center justify-between">
      <div>
        <h1 className="text-xl font-semibold text-text">Overview</h1>
        <p className="mt-1 text-sm text-text-muted">
          Fleet health across every registered MCP server.
        </p>
      </div>
      <Link
        href="/discovery"
        className="rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-soft"
      >
        + Connect a server
      </Link>
    </div>
  );
}

function relativeTime(iso: string): string {
  if (!iso) return "";
  const then = new Date(iso.replace(" ", "T") + (iso.includes("Z") ? "" : "Z")).getTime();
  const diffMs = Date.now() - then;
  if (Number.isNaN(diffMs)) return iso;
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
