"use client";

import { useCallback, useEffect, useState } from "react";
import { api, ApiError, ServerSummary, Tool } from "@/lib/api";
import { Badge, Card, EmptyState, ErrorState, Spinner } from "@/components/ui";
import { Modal } from "@/components/Modal";

interface ServerCardData {
  server: ServerSummary;
  tools: Tool[];
  live: boolean;
  toolsError?: string;
}

export default function DiscoveryPage() {
  const [rows, setRows] = useState<ServerCardData[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [showRegister, setShowRegister] = useState(false);
  const [callTarget, setCallTarget] = useState<{ serverId: string; serverLabel: string; tool: Tool } | null>(null);

  const load = useCallback(async () => {
    try {
      const servers = await api.listServers();
      const rows = await Promise.all(
        servers.map(async (server): Promise<ServerCardData> => {
          const [tools, live] = await Promise.all([
            api.getTools(server.server_id).catch(() => [] as Tool[]),
            api.getLiveStatus(server.server_id).then((s) => s.running).catch(() => false),
          ]);
          return { server, tools, live };
        })
      );
      setRows(rows);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the backend API.");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const filtered = rows?.filter((r) => {
    if (!query.trim()) return true;
    const q = query.toLowerCase();
    return (
      r.server.source.toLowerCase().includes(q) ||
      r.tools.some((t) => t.name.toLowerCase().includes(q))
    );
  });

  return (
    <div>
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-text">Discovery Hub</h1>
          <p className="mt-1 text-sm text-text-muted">
            Every server registered with the trust &amp; reputation platform, and what it exposes.
          </p>
        </div>
        <button
          onClick={() => setShowRegister(true)}
          className="shrink-0 rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-white hover:bg-accent-soft"
        >
          + Connect a server
        </button>
      </div>

      <div className="mt-5">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search by server or tool name…"
          className="w-full max-w-sm rounded-lg border border-border bg-surface px-3.5 py-2 text-sm text-text placeholder:text-text-faint focus:border-accent focus:outline-none"
        />
      </div>

      {error && !rows ? (
        <Card className="mt-6">
          <ErrorState message={error} />
        </Card>
      ) : !rows ? (
        <div className="mt-16 flex justify-center">
          <Spinner />
        </div>
      ) : filtered && filtered.length === 0 ? (
        <Card className="mt-6">
          <EmptyState
            title={rows.length === 0 ? "No servers registered yet" : "No matches"}
            hint={rows.length === 0 ? "Connect a GitHub-hosted MCP server to get started." : "Try a different search term."}
          />
        </Card>
      ) : (
        <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered!.map((row) => (
            <ServerCard key={row.server.server_id} row={row} onCallTool={(tool) => setCallTarget({ serverId: row.server.server_id, serverLabel: row.server.source, tool })} />
          ))}
        </div>
      )}

      {showRegister && (
        <RegisterModal
          onClose={() => setShowRegister(false)}
          onRegistered={() => {
            setShowRegister(false);
            load();
          }}
        />
      )}

      {callTarget && (
        <CallToolModal
          serverId={callTarget.serverId}
          serverLabel={callTarget.serverLabel}
          tool={callTarget.tool}
          onClose={() => setCallTarget(null)}
        />
      )}
    </div>
  );
}

function ServerCard({ row, onCallTool }: { row: ServerCardData; onCallTool: (tool: Tool) => void }) {
  const { server, tools, live } = row;
  return (
    <Card className="flex flex-col">
      <div className="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold text-text" title={server.source}>
            {server.source}
          </p>
          <p className="mt-0.5 font-mono text-[11px] text-text-faint">{server.server_id.slice(0, 13)}…</p>
        </div>
        <Badge tone={live ? "success" : "neutral"}>
          <span className={`h-1.5 w-1.5 rounded-full ${live ? "bg-emerald-400" : "bg-text-faint"}`} />
          {live ? "Live" : "Offline"}
        </Badge>
      </div>

      <div className="flex gap-4 border-b border-border px-5 py-3 text-xs">
        <Metric label="Reputation" value={server.overall_score !== null ? server.overall_score.toFixed(0) : "—"} />
        <Metric label="Security" value={server.security_score !== null ? server.security_score.toFixed(0) : "—"} />
        <Metric label="Tools" value={String(tools.length)} />
      </div>

      <div className="flex-1 px-5 py-3">
        <p className="mb-2 text-xs font-medium uppercase tracking-wide text-text-faint">Exposed tools</p>
        {tools.length === 0 ? (
          <p className="text-xs text-text-faint">No tools discovered yet.</p>
        ) : (
          <ul className="space-y-1.5">
            {tools.slice(0, 5).map((t) => (
              <li key={t.name} className="flex items-center justify-between gap-2 rounded-md px-2 py-1.5 hover:bg-surface-hover">
                <div className="min-w-0">
                  <p className="truncate text-xs font-medium text-text">{t.name}</p>
                  {t.description && <p className="truncate text-[11px] text-text-faint">{t.description}</p>}
                </div>
                <button
                  onClick={() => onCallTool(t)}
                  disabled={!live}
                  className="shrink-0 rounded-md border border-border-strong px-2 py-1 text-[11px] font-medium text-text-muted hover:border-accent hover:text-accent disabled:cursor-not-allowed disabled:opacity-40"
                  title={live ? "Call this tool" : "Server is not live"}
                >
                  Try it
                </button>
              </li>
            ))}
            {tools.length > 5 && (
              <li className="px-2 text-[11px] text-text-faint">+{tools.length - 5} more</li>
            )}
          </ul>
        )}
      </div>
    </Card>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-text-faint">{label}</p>
      <p className="font-semibold text-text">{value}</p>
    </div>
  );
}

function RegisterModal({ onClose, onRegistered }: { onClose: () => void; onRegistered: () => void }) {
  const [repoUrl, setRepoUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    if (!repoUrl.trim()) return;
    setSubmitting(true);
    setErr(null);
    try {
      await api.registerServer({ repo_url: repoUrl.trim(), installation_id: 1, allowed_destinations: [] });
      onRegistered();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Registration failed.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal title="Connect a server" onClose={onClose}>
      <p className="text-xs text-text-muted">
        GitHub repo, either <code className="rounded bg-surface px-1 py-0.5">owner/repo</code> or a full URL.
      </p>
      <input
        autoFocus
        value={repoUrl}
        onChange={(e) => setRepoUrl(e.target.value)}
        placeholder="owner/repo"
        className="mt-3 w-full rounded-lg border border-border bg-surface px-3.5 py-2 text-sm text-text placeholder:text-text-faint focus:border-accent focus:outline-none"
      />
      {err && <p className="mt-2 text-xs text-red-300">{err}</p>}
      <div className="mt-4 flex justify-end gap-2">
        <button onClick={onClose} className="rounded-lg px-3.5 py-2 text-sm text-text-muted hover:bg-surface-hover">
          Cancel
        </button>
        <button
          onClick={submit}
          disabled={submitting || !repoUrl.trim()}
          className="rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-white hover:bg-accent-soft disabled:opacity-50"
        >
          {submitting ? "Registering…" : "Register"}
        </button>
      </div>
      <p className="mt-3 text-[11px] text-text-faint">
        Registration starts static analysis in the background. To actually run it live, set a launch command from
        Security Controls, or wait for an approved Warden profile.
      </p>
    </Modal>
  );
}

function CallToolModal({
  serverId,
  serverLabel,
  tool,
  onClose,
}: {
  serverId: string;
  serverLabel: string;
  tool: Tool;
  onClose: () => void;
}) {
  const [argsText, setArgsText] = useState("{}");
  const [result, setResult] = useState<string | null>(null);
  const [errMsg, setErrMsg] = useState<string | null>(null);
  const [calling, setCalling] = useState(false);

  async function call() {
    setCalling(true);
    setErrMsg(null);
    setResult(null);
    try {
      const args = JSON.parse(argsText || "{}");
      const res = await api.callTool(serverId, tool.name, args);
      setResult(JSON.stringify(res, null, 2));
    } catch (e) {
      setErrMsg(e instanceof ApiError ? e.message : e instanceof SyntaxError ? "Arguments must be valid JSON." : "Call failed.");
    } finally {
      setCalling(false);
    }
  }

  return (
    <Modal title={`Call ${tool.name}`} onClose={onClose} wide>
      <p className="text-xs text-text-muted">
        {serverLabel} · {tool.description || "no description"}
      </p>
      <p className="mt-3 text-xs font-medium uppercase tracking-wide text-text-faint">Arguments (JSON)</p>
      <textarea
        value={argsText}
        onChange={(e) => setArgsText(e.target.value)}
        rows={4}
        className="mt-1.5 w-full rounded-lg border border-border bg-surface px-3.5 py-2 font-mono text-xs text-text focus:border-accent focus:outline-none"
      />
      <div className="mt-3 flex justify-end">
        <button
          onClick={call}
          disabled={calling}
          className="rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-white hover:bg-accent-soft disabled:opacity-50"
        >
          {calling ? "Calling…" : "Call tool"}
        </button>
      </div>
      {errMsg && (
        <div className="mt-3 rounded-lg border border-red-700/40 bg-danger-bg px-3.5 py-2.5 text-xs text-red-300">
          {errMsg}
        </div>
      )}
      {result && (
        <pre className="mt-3 max-h-56 overflow-auto rounded-lg border border-border bg-bg px-3.5 py-2.5 font-mono text-xs text-text-muted">
          {result}
        </pre>
      )}
      <p className="mt-3 text-[11px] text-text-faint">
        This call is recorded to the audit trail in real time — check Audit &amp; Activity right after.
      </p>
    </Modal>
  );
}
