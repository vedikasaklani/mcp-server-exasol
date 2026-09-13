// Thin client for the Warden backend (server_management/api/api.py, which
// mounts telemetry_api.py's router). One base URL, no other dependency.
//
// Recovered from the committed dev chunk after the original was lost to the
// root .gitignore's `lib/` rule (now excepted) - runtime code is verbatim,
// types are reconstructed from what the pages read.

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") || "http://localhost:8000";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    cache: "no-store",
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      /* body wasn't JSON */
    }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

/* ---------- shapes ---------- */

export interface ServerSummary {
  server_id: string;
  source: string;
  overall_score: number | null;
  security_score: number | null;
  operational_score?: number | null;
  [extra: string]: unknown;
}

export interface Tool {
  name: string;
  description?: string | null;
  parameter_schema?: Record<string, unknown> | null;
  source?: string | null; // "declared" | "observed"
}

// Mirrors telemetry_api.RuntimeEvent (what warden-serve posts).
export interface RuntimeEvent {
  event_id: string;
  tool_name: string;
  session_id: string;
  event_ts: string;
  agent_id?: string | null;
  destination_declared: string | null;
  destination_actual: string | null;
  destination_match?: boolean | null;
  intent_match?: boolean | null;
  sensitive_data_flag: boolean;
  sensitive_data_categories: string[];
  decision: "ALLOWED" | "BLOCKED" | "FLAGGED";
  decision_reason: string | null;
  latency_ms: number;
  status_code?: number;
  bytes_sent: number;
  bytes_received: number;
  retry_count?: number;
  severity: string | null;
  evidence: string[];
  findings: RuntimeFinding[];
  request_id: string | null;
  container_id?: string | null;
  posture: string | null;
  syscall_count: number | null;
  distinct_paths: number | null;
  file_read_bytes: number | null;
  file_write_bytes: number | null;
  net_read_bytes: number | null;
  net_write_bytes: number | null;
  process_spawns: number | null;
  seccomp_denials: number | null;
  unsolicited_msgs?: number | null;
}

export interface RuntimeFinding {
  severity: string;
  title?: string;
  detail?: string;
  detector?: string;
  kernel_attested?: boolean;
  evidence: string[];
  event_ts: string;
}

export interface SessionSummary {
  session_id: string;
  started_at: string;
  posture: string;
  requests: number;
  critical: number;
  high: number;
  denials: number;
  confinement: string;
  [extra: string]: unknown;
}

export interface LiveStatus {
  running: boolean;
  [extra: string]: unknown;
}

export interface LiveMetrics {
  target: string;
  pool_size: number;
  ready: boolean;
  profile_digest: string;
  metrics: {
    uptime_seconds: number;
    gauges: Record<string, number | undefined>;
    counters: Record<string, number | undefined>;
  };
}

export interface ScanFinding {
  severity: string;
  rule_id?: string | null;
  message?: string | null;
  file_path?: string | null;
  file?: string | null;
  line?: number | null;
  [extra: string]: unknown;
}

export interface ScanHistoryEntry {
  scan_run_id: string;
  commit_sha: string;
  status: string;
  verdict?: string | null;
  started_at?: string | null;
  severity_counts: Record<string, number>;
  findings: ScanFinding[];
}

export interface ScanResult {
  verdict: string;
  severity_counts: Record<string, number>;
  findings: ScanFinding[];
  package: { name: string; version: string; dependencies: number };
  [extra: string]: unknown;
}

export interface Manifest {
  server_id: string;
  allowed_destinations: string[];
  tool_declarations: Record<string, unknown>[] | null;
  version: number;
}

export interface Health {
  status: string;
  postgres: boolean;
  exasol: boolean;
  [extra: string]: unknown;
}

/* ---------- client ---------- */

export const api = {
  listServers: () => req<ServerSummary[]>("/servers"),
  getTools: (serverId: string) => req<Tool[]>(`/servers/${serverId}/tools`),
  getRuntimeEvents: (serverId: string, limit = 100) =>
    req<RuntimeEvent[]>(`/servers/${serverId}/runtime-events?limit=${limit}`),
  getRuntimeFindings: (serverId: string, limit = 50) =>
    req<RuntimeFinding[]>(`/servers/${serverId}/runtime-findings?limit=${limit}`),
  getSessions: (serverId: string, limit = 20) =>
    req<SessionSummary[]>(`/servers/${serverId}/sessions?limit=${limit}`),
  getTrustScore: (serverId: string) =>
    req<Record<string, unknown>>(`/servers/${serverId}/trust-score`).catch((e) => {
      if (e instanceof ApiError && e.status === 404) return null;
      throw e;
    }),
  getSummary: (serverId: string) => req<Record<string, unknown>>(`/servers/${serverId}/summary`),
  computeScores: () => req<unknown>("/compute-scores", { method: "POST" }),
  getGlobalTools: (params?: { server_id?: string; q?: string }) => {
    const qs = new URLSearchParams();
    if (params?.server_id) qs.set("server_id", params.server_id);
    if (params?.q) qs.set("q", params.q);
    const suffix = qs.toString() ? `?${qs}` : "";
    return req<Tool[]>(`/tools${suffix}`);
  },
  getManifest: (serverId: string) => req<Manifest>(`/servers/${serverId}/manifest`),
  updateManifest: (serverId: string, body: { allowed_destinations: string[] }) =>
    req<Manifest>(`/servers/${serverId}/manifest`, { method: "PATCH", body: JSON.stringify(body) }),
  getLiveStatus: (serverId: string) => req<LiveStatus>(`/servers/${serverId}/live/status`),
  getLiveMetrics: (serverId: string) =>
    req<LiveMetrics>(`/servers/${serverId}/live/metrics`).catch((e) => {
      if (e instanceof ApiError && e.status === 503) return null;
      throw e;
    }),
  getLiveTools: (serverId: string) => req<Tool[]>(`/servers/${serverId}/live/tools`),
  callTool: (serverId: string, toolName: string, args: Record<string, unknown>) =>
    req<unknown>(`/servers/${serverId}/call`, {
      method: "POST",
      body: JSON.stringify({ tool_name: toolName, arguments: args }),
    }),
  runScan: (serverId: string) => req<ScanResult>(`/servers/${serverId}/scan`, { method: "POST" }),
  getScans: (serverId: string) => req<ScanHistoryEntry[]>(`/servers/${serverId}/scans`),
  registerServer: (body: Record<string, unknown>) =>
    req<ServerSummary>("/servers", { method: "POST", body: JSON.stringify(body) }),
  health: () => req<Health>("/health"),
};
