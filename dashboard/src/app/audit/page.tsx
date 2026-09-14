"use client";

import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  type RuntimeEvent,
  type ServerSummary,
} from "@/lib/api";
import {
  Button,
  Card,
  DecisionBadge,
  EmptyState,
  ErrorState,
  KeyValue,
  Mono,
  PageHeader,
  SeverityBadge,
  Spinner,
  bytes,
  formatTime,
  num,
  relativeTime,
  severityStyle,
} from "@/components/ui";

type Row = RuntimeEvent & { serverLabel: string; serverId: string };

const DECISIONS = ["All", "Allowed", "Flagged", "Blocked"] as const;
const SEVERITIES = ["All", "critical", "high", "medium", "low"] as const;

export default function AuditPage() {
  const [servers, setServers] = useState<ServerSummary[] | null>(null);
  const [rows, setRows] = useState<Row[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [serverFilter, setServerFilter] = useState("all");
  const [decision, setDecision] = useState<(typeof DECISIONS)[number]>("All");
  const [severity, setSeverity] = useState<(typeof SEVERITIES)[number]>("All");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const list = await api.listServers();
      setServers(list);
      const chunks = await Promise.all(
        list.map(async (s) => {
          try {
            const events = await api.getRuntimeEvents(s.server_id, 200);
            return events.map((e) => ({ ...e, serverLabel: s.source, serverId: s.server_id }));
          } catch {
            return [] as Row[];
          }
        })
      );
      setRows(
        chunks
          .flat()
          .sort((a, b) => (a.event_ts < b.event_ts ? 1 : -1))
      );
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach the backend");
    }
  }, []);

  useEffect(() => {
    const initial = window.setTimeout(() => void load(), 0);
    const id = setInterval(load, 15000);
    return () => {
      window.clearTimeout(initial);
      clearInterval(id);
    };
  }, [load]);

  const filtered = useMemo(() => {
    if (!rows) return null;
    return rows.filter((r) => {
      if (serverFilter !== "all" && r.serverId !== serverFilter) return false;
      if (decision !== "All" && r.decision !== decision.toUpperCase()) return false;
      if (severity !== "All" && (r.severity || "none").toLowerCase() !== severity) return false;
      if (query) {
        const hay = `${r.tool_name} ${r.serverLabel} ${r.decision_reason} ${r.evidence?.join(" ")}`.toLowerCase();
        if (!hay.includes(query.toLowerCase())) return false;
      }
      return true;
    });
  }, [rows, serverFilter, decision, severity, query]);

  const stats = useMemo(() => {
    const base = { total: 0, flagged: 0, blocked: 0, sensitive: 0 };
    (filtered ?? []).forEach((r) => {
      base.total += 1;
      if (r.decision === "FLAGGED") base.flagged += 1;
      if (r.decision === "BLOCKED") base.blocked += 1;
      if (r.sensitive_data_flag) base.sensitive += 1;
    });
    return base;
  }, [filtered]);

  return (
    <>
      <PageHeader
        title="Audit Trail"
        subtitle="Every tool call the gateway executed, with what the kernel observed while it ran."
        right={
          <div className="flex items-center gap-4 text-[12px] text-text-muted">
            <span className="tabular">{stats.total} calls</span>
            <span className="tabular text-sev-medium">{stats.flagged} flagged</span>
            {stats.blocked > 0 && <span className="tabular text-danger">{stats.blocked} blocked</span>}
            <span className="tabular">{stats.sensitive} sensitive</span>
          </div>
        }
      />

      <Card padded={false}>
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-3">
          <select
            value={serverFilter}
            onChange={(e) => setServerFilter(e.target.value)}
            className="rounded-lg border border-border bg-surface-2 px-2.5 py-1.5 text-[12.5px] text-text transition-colors focus:border-primary focus:outline-none focus:ring-[3px] focus:ring-primary/15"
          >
            <option value="all">All servers</option>
            {servers?.map((s) => (
              <option key={s.server_id} value={s.server_id}>
                {s.source}
              </option>
            ))}
          </select>

          <Segmented options={DECISIONS} value={decision} onChange={setDecision} />
          <Segmented options={SEVERITIES} value={severity} onChange={setSeverity} labelize />

          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by tool, reason or evidence…"
            className="ml-auto w-64 rounded-lg border border-border bg-surface-2 px-3 py-1.5 text-[12.5px] text-text placeholder:text-text-faint transition-colors focus:border-primary focus:outline-none focus:ring-[3px] focus:ring-primary/15"
          />
        </div>

        {error && <ErrorState message={error} onRetry={load} />}
        {!error && !filtered && (
          <div className="px-5 py-10">
            <Spinner label="Loading audit trail…" />
          </div>
        )}
        {!error && filtered?.length === 0 && (
          <EmptyState
            title="No calls match these filters"
            hint="Calls appear here the moment a confined server serves one."
          />
        )}

        {!error && filtered && filtered.length > 0 && (
          <div className="w-full overflow-hidden">
            <table className="w-full table-fixed border-collapse text-[12.5px]">
              <colgroup>
                <col className="w-[28px]" />
                <col className="w-[9%]" />
                <col className="w-[20%]" />
                <col className="w-[20%]" />
                <col className="w-[11%]" />
                <col className="w-[11%]" />
                <col className="w-[9%]" />
                <col className="w-[10%]" />
              </colgroup>
              <thead>
                <tr className="border-b border-border text-left">
                  {["", "Time", "Server", "Tool", "Decision", "Severity", "Latency", "Data"].map((h) => (
                    <th key={h} className="eyebrow truncate px-2.5 py-2.5 font-semibold">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((r) => {
                  const expanded = open === r.event_id;
                  const sev = (r.severity || "none").toLowerCase();
                  const interesting = sev !== "none" || r.sensitive_data_flag;
                  return (
                    <Fragment key={r.event_id}>
                      <tr
                        onClick={() => setOpen(expanded ? null : r.event_id)}
                        className={`cursor-pointer border-b border-border/60 transition-colors hover:bg-surface-hover ${
                          expanded ? "bg-surface-hover" : ""
                        }`}
                      >
                        <td className="px-2.5 py-2 text-text-faint">
                          <svg
                            viewBox="0 0 24 24"
                            className={`h-3.5 w-3.5 transition-transform ${expanded ? "rotate-90" : ""}`}
                            fill="none"
                            stroke="currentColor"
                            strokeWidth={2}
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          >
                            <path d="m9 6 6 6-6 6" />
                          </svg>
                        </td>
                        <td
                          className="tabular truncate px-2.5 py-2 text-text-muted"
                          title={r.event_ts}
                        >
                          {formatTime(r.event_ts)}
                        </td>
                        <td className="truncate px-2.5 py-2 text-text-muted" title={r.serverLabel}>
                          {r.serverLabel}
                        </td>
                        <td className="truncate px-2.5 py-2">
                          <Mono className={r.tool_name ? "text-text" : "text-text-faint"}>
                            {r.tool_name || "handshake"}
                          </Mono>
                        </td>
                        <td className="truncate px-2.5 py-2">
                          <DecisionBadge decision={r.decision} />
                        </td>
                        <td className="truncate px-2.5 py-2">
                          {interesting ? <SeverityBadge severity={sev} /> : <span className="text-text-faint">—</span>}
                        </td>
                        <td className="tabular truncate px-2.5 py-2 text-text-muted">{r.latency_ms ?? "—"}ms</td>
                        <td className="truncate px-2.5 py-2">
                          {r.sensitive_data_flag ? (
                            <span className="rounded border border-sev-high/30 bg-sev-high/10 px-1.5 py-0.5 text-[10.5px] font-medium text-sev-high">
                              Sensitive
                            </span>
                          ) : (
                            <span className="text-text-faint">—</span>
                          )}
                        </td>
                      </tr>
                      {expanded && (
                        <tr className="row-in border-b border-border bg-bg-elevated">
                          <td colSpan={8} className="px-3 py-4">
                            <EventDetail row={r} />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}

function Segmented<T extends string>({
  options,
  value,
  onChange,
  labelize,
}: {
  options: readonly T[];
  value: T;
  onChange: (v: T) => void;
  labelize?: boolean;
}) {
  return (
    <div className="flex rounded-lg border border-border bg-surface-2 p-0.5">
      {options.map((o) => (
        <button
          key={o}
          onClick={() => onChange(o)}
          className={`rounded-[6px] px-2.5 py-1 text-[12px] capitalize transition-colors ${
            value === o ? "bg-surface-hover text-text" : "text-text-faint hover:text-text-muted"
          }`}
        >
          {labelize && o !== "All" ? o : o}
        </button>
      ))}
    </div>
  );
}

function EventDetail({ row }: { row: Row }) {
  const sev = (row.severity || "none").toLowerCase();
  return (
    <div className="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
      <div className="space-y-4">
        <div>
          <div className="eyebrow mb-1.5">Verdict</div>
          {row.decision_reason ? (
            <p className={`text-[13px] ${severityStyle(sev).fg}`}>{row.decision_reason}</p>
          ) : (
            <p className="text-[13px] text-text-muted">
              Nothing outside the approved profile was observed during this call.
            </p>
          )}
        </div>

        {row.evidence?.length > 0 && (
          <div>
            <div className="eyebrow mb-1.5">Evidence</div>
            <ul className="space-y-1">
              {row.evidence.map((e, i) => (
                <li
                  key={i}
                  className="rounded-md border border-border bg-surface px-2.5 py-1.5 font-mono text-[11.5px] leading-relaxed text-text-muted"
                >
                  {e}
                </li>
              ))}
            </ul>
          </div>
        )}

        {row.findings?.length > 0 && (
          <div>
            <div className="eyebrow mb-1.5">Detector findings for this call</div>
            <div className="space-y-2">
              {row.findings.map((f, i) => (
                <div key={i} className="rounded-lg border border-border bg-surface p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <span className="text-[12.5px] text-text">{f.title}</span>
                    <Mono className="text-text-faint">{f.detector}</Mono>
                    {f.kernel_attested && (
                      <span className="rounded border border-primary/35 bg-primary/12 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                        kernel-attested
                      </span>
                    )}
                  </div>
                  {f.detail && <p className="mt-1.5 text-[12px] text-text-muted">{f.detail}</p>}
                  {f.evidence?.length > 0 && (
                    <ul className="mt-2 space-y-0.5">
                      {f.evidence.slice(0, 6).map((e, j) => (
                        <li key={j} className="font-mono text-[11px] text-text-faint">
                          {e}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {row.sensitive_data_categories?.length > 0 && (
          <div>
            <div className="eyebrow mb-1.5">Sensitive data categories</div>
            <div className="flex flex-wrap gap-1.5">
              {row.sensitive_data_categories.map((c) => (
                <span
                  key={c}
                  className="rounded border border-sev-high/25 bg-sev-high/10 px-2 py-0.5 font-mono text-[11px] text-sev-high"
                >
                  {c}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="space-y-4">
        <div className="rounded-lg border border-border bg-surface p-3.5">
          <div className="eyebrow mb-2">What the kernel saw</div>
          <KeyValue k="Syscalls" v={num(row.syscall_count)} />
          <KeyValue k="Distinct paths" v={num(row.distinct_paths)} />
          <KeyValue k="File read" v={bytes(row.file_read_bytes)} />
          <KeyValue k="File written" v={bytes(row.file_write_bytes)} />
          <KeyValue k="Network out" v={bytes(row.net_write_bytes)} />
          <KeyValue k="Process spawns" v={num(row.process_spawns)} />
          <KeyValue k="Seccomp denials" v={num(row.seccomp_denials)} />
          {(row.syscall_count === null || row.distinct_paths === null) && (
            <p className="mt-2 text-[11px] leading-snug text-text-faint">
              A dash means not observed rather than zero — gVisor writes its trace
              asynchronously, so a very recent call may still be catching up.
            </p>
          )}
        </div>

        <div className="rounded-lg border border-border bg-surface p-3.5">
          <div className="eyebrow mb-2">Call</div>
          <KeyValue k="Request" v={<Mono>{row.request_id || "—"}</Mono>} />
          <KeyValue k="Session" v={<Mono>{row.session_id.slice(0, 24) || "—"}</Mono>} />
          <KeyValue k="Posture" v={row.posture || "—"} />
          <KeyValue k="Bytes in / out" v={`${bytes(row.bytes_sent)} / ${bytes(row.bytes_received)}`} />
          <KeyValue k="Egress allowed" v={row.destination_declared || "none"} />
          <KeyValue k="Egress attempted" v={row.destination_actual || "none"} />
        </div>
      </div>
    </div>
  );
}
