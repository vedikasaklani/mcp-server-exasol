"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, ApiError, RuntimeEvent, ServerSummary } from "@/lib/api";
import { Badge, Card, DecisionBadge, EmptyState, ErrorState, Spinner } from "@/components/ui";

interface Row extends RuntimeEvent {
  server_source: string;
}

const DECISIONS = ["All", "ALLOWED", "FLAGGED", "BLOCKED"] as const;

export default function AuditPage() {
  const [servers, setServers] = useState<ServerSummary[] | null>(null);
  const [selectedServer, setSelectedServer] = useState<string>("__all__");
  const [rows, setRows] = useState<Row[] | null>(null);
  const [decisionFilter, setDecisionFilter] = useState<(typeof DECISIONS)[number]>("All");
  const [search, setSearch] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listServers().then(setServers).catch(() => setServers([]));
  }, []);

  const load = useCallback(async () => {
    if (!servers) return;
    setLoading(true);
    try {
      const targets = selectedServer === "__all__" ? servers : servers.filter((s) => s.server_id === selectedServer);
      const perServer = await Promise.all(
        targets.map(async (s) => {
          const events = await api.getRuntimeEvents(s.server_id, 200).catch(() => []);
          return events.map((e): Row => ({ ...e, server_source: s.source }));
        })
      );
      setRows(perServer.flat().sort((a, b) => (a.event_ts < b.event_ts ? 1 : -1)));
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the backend API.");
    } finally {
      setLoading(false);
    }
  }, [servers, selectedServer]);

  useEffect(() => {
    load();
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, [load]);

  const filtered = useMemo(() => {
    if (!rows) return null;
    return rows.filter((r) => {
      if (decisionFilter !== "All" && r.decision.toUpperCase() !== decisionFilter) return false;
      if (search.trim() && !`${r.tool_name} ${r.server_source}`.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [rows, decisionFilter, search]);

  return (
    <div>
      <h1 className="text-xl font-semibold text-text">Audit &amp; Activity Logs</h1>
      <p className="mt-1 text-sm text-text-muted">
        Every agent-to-tool interaction, permission decision, and security event, most recent first.
      </p>

      <Card className="mt-6">
        <div className="flex flex-wrap items-center gap-3 border-b border-border px-5 py-3">
          <select
            value={selectedServer}
            onChange={(e) => setSelectedServer(e.target.value)}
            className="rounded-lg border border-border bg-surface px-3 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
          >
            <option value="__all__">All servers</option>
            {servers?.map((s) => (
              <option key={s.server_id} value={s.server_id}>
                {s.source}
              </option>
            ))}
          </select>

          <div className="flex gap-1">
            {DECISIONS.map((d) => (
              <button
                key={d}
                onClick={() => setDecisionFilter(d)}
                className={`rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors ${
                  decisionFilter === d
                    ? "bg-accent-bg text-blue-300"
                    : "text-text-muted hover:bg-surface-hover hover:text-text"
                }`}
              >
                {d === "All" ? "All" : d.charAt(0) + d.slice(1).toLowerCase()}
              </button>
            ))}
          </div>

          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by tool or server…"
            className="ml-auto w-56 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs text-text placeholder:text-text-faint focus:border-accent focus:outline-none"
          />

          {loading && <Spinner />}
        </div>

        {error && !rows ? (
          <ErrorState message={error} />
        ) : !filtered ? (
          <div className="flex justify-center py-14">
            <Spinner />
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState title="No activity recorded" hint="Calls made through the Discovery Hub will show up here in real time." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-border text-xs uppercase tracking-wide text-text-faint">
                  <Th>Time</Th>
                  <Th>Server</Th>
                  <Th>Tool</Th>
                  <Th>Status</Th>
                  <Th>Latency</Th>
                  <Th>Data</Th>
                  <Th>Session</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filtered.map((r) => (
                  <tr key={r.event_id} className="hover:bg-surface-hover">
                    <Td className="whitespace-nowrap text-text-faint">{formatTs(r.event_ts)}</Td>
                    <Td className="max-w-[180px] truncate" title={r.server_source}>
                      {r.server_source}
                    </Td>
                    <Td className="font-mono text-xs">{r.tool_name || <span className="text-text-faint">handshake</span>}</Td>
                    <Td>
                      <DecisionBadge decision={r.decision} />
                    </Td>
                    <Td className="tabular-nums text-text-muted">{r.latency_ms !== null ? `${r.latency_ms}ms` : "—"}</Td>
                    <Td>
                      {r.sensitive_data_flag ? (
                        <Badge tone="warning">Sensitive</Badge>
                      ) : (
                        <span className="text-text-faint">—</span>
                      )}
                    </Td>
                    <Td className="max-w-[160px] truncate font-mono text-[11px] text-text-faint" title={r.session_id}>
                      {r.session_id}
                    </Td>
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

function Th({ children }: { children: React.ReactNode }) {
  return <th className="px-5 py-2.5 font-medium">{children}</th>;
}
function Td({ children, className = "", title }: { children: React.ReactNode; className?: string; title?: string }) {
  return (
    <td className={`px-5 py-2.5 ${className}`} title={title}>
      {children}
    </td>
  );
}

function formatTs(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso.replace(" ", "T") + (iso.includes("Z") ? "" : "Z"));
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}
