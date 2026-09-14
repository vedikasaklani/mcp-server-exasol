"use client";

import Link from "next/link";
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

interface Row {
  server: ServerSummary;
  tools: Tool[];
  live: boolean;
}

// GitHub's standard install URL for an app, by slug - lands the installer
// on the app's own repo/permission picker, then redirects to this backend's
// /github/setup (the app's configured setup URL) with a real installation_id.
// The dashboard's own registration form talked to POST /servers with a
// hardcoded installation_id: 1, which is exactly the kind of stale/fake id
// mismatch debugged earlier (a server registered under one installation_id,
// webhooks arriving under another) - going through the real GitHub flow is
// what keeps that id correct from the start.
const GITHUB_APP_INSTALL_URL = "https://github.com/apps/mcp-server-scan/installations/new";

export default function DiscoveryPage() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

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
              className="w-60 rounded-lg border border-border bg-surface-2 px-3 py-2 text-[13px] text-text placeholder:text-text-faint transition-colors focus:border-primary focus:outline-none focus:ring-[3px] focus:ring-primary/15"
            />
            <a href={GITHUB_APP_INSTALL_URL} target="_blank" rel="noopener noreferrer">
              <Button variant="primary">Connect a server</Button>
            </a>
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
            <Link key={server.server_id} href={`/servers/${server.server_id}`}>
              <Card className="flex items-start gap-3.5 transition-colors hover:border-border-strong hover:bg-surface-hover">
                <ScoreRing score={server.overall_score} size={48} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <h3 className="truncate text-[13.5px] font-medium text-text">{server.source}</h3>
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
              </Card>
            </Link>
          ))}
        </div>
      )}
    </>
  );
}
