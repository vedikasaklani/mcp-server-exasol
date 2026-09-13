"use client";

import { useCallback, useEffect, useState } from "react";
import { api, ApiError, type ServerSummary, type Tool } from "@/lib/api";
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  LiveBadge,
  Mono,
  PageHeader,
  ScoreRing,
  Spinner,
  num,
} from "@/components/ui";
import { Modal } from "@/components/Modal";

interface Row {
  server: ServerSummary;
  tools: Tool[];
  live: boolean;
}

export default function DiscoveryPage() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [showRegister, setShowRegister] = useState(false);
  const [callTarget, setCallTarget] = useState<{ serverId: string; label: string; tool: Tool } | null>(null);

  const load = useCallback(async () => {
    try {
      const servers = await api.listServers();
      setRows(
        await Promise.all(
          servers.map(async (server): Promise<Row> => {
            const [tools, live] = await Promise.all([
              api.getTools(server.server_id).catch(() => [] as Tool[]),
              api.getLiveStatus(server.server_id).then((s) => s.running).catch(() => false),
            ]);
            return { server, tools, live };
          })
        )
      );
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the backend API.");
    }
  }, []);

  useEffect(() => {
    const id = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(id);
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
    <>
      <PageHeader
        title="Discovery"
        subtitle="Every MCP server registered with the gateway, and the tools it exposes."
        right={
          <div className="flex items-center gap-2">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search servers or tools…"
              className="w-60 rounded-lg border border-border bg-surface-2 px-3 py-2 text-[13px] text-text placeholder:text-text-faint focus:border-accent focus:outline-none"
            />
            <Button variant="primary" onClick={() => setShowRegister(true)}>
              Connect a server
            </Button>
          </div>
        }
      />

      {error && <ErrorState message={error} onRetry={load} />}
      {!error && !filtered && <Spinner label="Loading servers…" />}
      {!error && filtered?.length === 0 && (
        <Card>
          <EmptyState
            title={query ? "Nothing matches that search" : "No servers registered yet"}
            hint={query ? undefined : "Connect one from GitHub or npm to get started."}
          />
        </Card>
      )}

      {!error && filtered && filtered.length > 0 && (
        <div className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
          {filtered.map(({ server, tools, live }) => (
            <Card key={server.server_id} padded={false} className="flex flex-col">
              <div className="flex items-start gap-3.5 border-b border-border px-5 py-4">
                <ScoreRing score={server.overall_score} size={48} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <h3 className="truncate text-[13.5px] font-semibold text-text">{server.source}</h3>
                    <LiveBadge live={live} />
                  </div>
                  <Mono className="mt-0.5 block text-text-faint">{server.server_id.slice(0, 18)}…</Mono>
                  <div className="mt-1.5 flex gap-3 text-[11.5px] text-text-faint">
                    <span className="tabular">
                      security {server.security_score === null ? "—" : server.security_score}
                    </span>
                    <span className="tabular">{num(tools.length)} tools</span>
                  </div>
                </div>
              </div>

              <div className="flex-1 px-5 py-3">
                <div className="eyebrow mb-2">Exposed tools</div>
                {tools.length === 0 ? (
                  <p className="text-[12px] text-text-faint">
                    Nothing discovered yet — scan it or start a session to populate the catalogue.
                  </p>
                ) : (
                  <ul className="space-y-1.5">
                    {tools.map((t) => (
                      <li key={t.name} className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <Mono className="text-text">{t.name}</Mono>
                          {t.description && (
                            <p className="truncate text-[11.5px] text-text-faint">{t.description}</p>
                          )}
                        </div>
                        <div className="flex shrink-0 items-center gap-2">
                          <span
                            className={`rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wide ${
                              t.source === "observed"
                                ? "bg-accent-bg text-accent"
                                : "bg-surface-2 text-text-faint"
                            }`}
                            title={
                              t.source === "observed"
                                ? "Advertised by the running server"
                                : "Extracted from source by static analysis"
                            }
                          >
                            {t.source || "—"}
                          </span>
                          <Button
                            size="sm"
                            onClick={() => setCallTarget({ serverId: server.server_id, label: server.source, tool: t })}
                          >
                            Run
                          </Button>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </Card>
          ))}
        </div>
      )}

      {showRegister && (
        <RegisterModal
          onClose={() => setShowRegister(false)}
          onDone={() => {
            setShowRegister(false);
            void load();
          }}
        />
      )}
      {callTarget && <CallModal {...callTarget} onClose={() => setCallTarget(null)} />}
    </>
  );
}

const EXAMPLES = [
  { value: "npm:@modelcontextprotocol/server-memory", note: "official knowledge-graph server" },
  { value: "npm:@modelcontextprotocol/server-sequential-thinking", note: "official reasoning server" },
];

function RegisterModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.registerServer({ repo_url: value.trim(), installation_id: 1 });
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Registration failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="Connect an MCP server" onClose={onClose}>
      <p className="text-[12.5px] leading-relaxed text-text-muted">
        Give an npm package or a GitHub repository. Registration establishes identity only —
        nothing runs until it has passed a scan.
      </p>

      <input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && value.trim() && !busy && submit()}
        placeholder="npm:@modelcontextprotocol/server-memory"
        autoFocus
        className="mt-4 w-full rounded-lg border border-border bg-surface px-3 py-2 font-mono text-[12.5px] text-text placeholder:text-text-faint focus:border-accent focus:outline-none"
      />

      <div className="mt-3">
        <div className="eyebrow mb-1.5">Known to work</div>
        <div className="space-y-1">
          {EXAMPLES.map((ex) => (
            <button
              key={ex.value}
              onClick={() => setValue(ex.value)}
              className="flex w-full items-center justify-between gap-3 rounded-md border border-border bg-surface px-2.5 py-1.5 text-left transition-colors hover:bg-surface-hover"
            >
              <Mono className="truncate text-text-muted">{ex.value}</Mono>
              <span className="shrink-0 text-[11px] text-text-faint">{ex.note}</span>
            </button>
          ))}
        </div>
      </div>

      {error && <p className="mt-3 text-[12.5px] text-danger">{error}</p>}

      <div className="mt-5 flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" onClick={submit} disabled={busy || !value.trim()}>
          {busy ? "Registering…" : "Register"}
        </Button>
      </div>
    </Modal>
  );
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
  const [args, setArgs] = useState("{}");
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
      <textarea
        value={args}
        onChange={(e) => setArgs(e.target.value)}
        rows={5}
        className="w-full rounded-lg border border-border bg-surface px-3 py-2 font-mono text-[12px] text-text focus:border-accent focus:outline-none"
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
