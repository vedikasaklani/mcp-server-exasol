"use client";

import { useEffect, useState } from "react";
import { api, ApiError, Manifest, ServerSummary } from "@/lib/api";
import { Badge, Card, CardHeader, EmptyState, ErrorState, Spinner } from "@/components/ui";

export default function SecurityPage() {
  const [servers, setServers] = useState<ServerSummary[] | null>(null);
  const [selected, setSelected] = useState<string>("");
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [destinations, setDestinations] = useState<string[]>([]);
  const [newDestination, setNewDestination] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api
      .listServers()
      .then((list) => {
        setServers(list);
        if (list.length > 0) setSelected(list[0].server_id);
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : "Could not reach the backend API."));
  }, []);

  useEffect(() => {
    if (!selected) return;
    api
      .getManifest(selected)
      .then((m) => {
        setManifest(m);
        setDestinations(m.allowed_destinations);
        setSaved(false);
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : "Could not load manifest."));
  }, [selected]);

  async function save() {
    if (!selected) return;
    setSaving(true);
    setSaved(false);
    try {
      const m = await api.updateManifest(selected, { allowed_destinations: destinations });
      setManifest(m);
      setSaved(true);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Save failed.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div>
      <h1 className="text-xl font-semibold text-text">Security Controls</h1>
      <p className="mt-1 text-sm text-text-muted">
        Access policy, rate limits, and allowed scopes for a registered server.
      </p>

      {error && !servers ? (
        <Card className="mt-6">
          <ErrorState message={error} />
        </Card>
      ) : servers && servers.length === 0 ? (
        <Card className="mt-6">
          <EmptyState title="No servers to configure" hint="Register a server from the Discovery Hub first." />
        </Card>
      ) : (
        <>
          <div className="mt-5">
            <select
              value={selected}
              onChange={(e) => {
                setManifest(null);
                setSelected(e.target.value);
              }}
              className="w-full max-w-sm rounded-lg border border-border bg-surface px-3.5 py-2 text-sm text-text focus:border-accent focus:outline-none"
            >
              {servers?.map((s) => (
                <option key={s.server_id} value={s.server_id}>
                  {s.source}
                </option>
              ))}
            </select>
          </div>

          {!manifest ? (
            <div className="mt-16 flex justify-center">
              <Spinner />
            </div>
          ) : (
            <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
              <Card>
                <CardHeader
                  title="Allowed Destinations"
                  subtitle="Network egress this server's confinement policy permits"
                  action={<Badge tone="success">Enforced</Badge>}
                />
                <div className="px-5 py-4">
                  <div className="flex flex-wrap gap-2">
                    {destinations.length === 0 && <p className="text-xs text-text-faint">No destinations allowed — fully egress-restricted.</p>}
                    {destinations.map((d, i) => (
                      <span
                        key={i}
                        className="flex items-center gap-1.5 rounded-md border border-border-strong bg-surface-hover px-2.5 py-1 text-xs text-text"
                      >
                        {d}
                        <button
                          onClick={() => setDestinations(destinations.filter((_, idx) => idx !== i))}
                          className="text-text-faint hover:text-red-300"
                        >
                          ✕
                        </button>
                      </span>
                    ))}
                  </div>
                  <div className="mt-3 flex gap-2">
                    <input
                      value={newDestination}
                      onChange={(e) => setNewDestination(e.target.value)}
                      placeholder="e.g. api.example.com"
                      onKeyDown={(e) => {
                        if (e.key === "Enter" && newDestination.trim()) {
                          setDestinations([...destinations, newDestination.trim()]);
                          setNewDestination("");
                        }
                      }}
                      className="flex-1 rounded-lg border border-border bg-surface px-3 py-1.5 text-xs text-text placeholder:text-text-faint focus:border-accent focus:outline-none"
                    />
                    <button
                      onClick={() => {
                        if (newDestination.trim()) {
                          setDestinations([...destinations, newDestination.trim()]);
                          setNewDestination("");
                        }
                      }}
                      className="rounded-lg border border-border-strong px-3 py-1.5 text-xs font-medium text-text-muted hover:border-accent hover:text-accent"
                    >
                      Add
                    </button>
                  </div>
                  <div className="mt-4 flex items-center gap-3">
                    <button
                      onClick={save}
                      disabled={saving}
                      className="rounded-lg bg-accent px-3.5 py-2 text-sm font-medium text-white hover:bg-accent-soft disabled:opacity-50"
                    >
                      {saving ? "Saving…" : "Save policy"}
                    </button>
                    {saved && <span className="text-xs text-emerald-300">Saved · manifest v{manifest.version}</span>}
                  </div>
                </div>
              </Card>

              <Card>
                <CardHeader
                  title="Warden Confinement Profile"
                  subtitle="Capability profile approval status for this server"
                />
                <dl className="grid grid-cols-2 gap-4 px-5 py-4 text-xs">
                  <Field label="Launch command">
                    {manifest.launch_executable ? (
                      <code className="text-text">
                        {manifest.launch_executable} {manifest.launch_args.join(" ")}
                      </code>
                    ) : (
                      <span className="text-text-faint">not configured</span>
                    )}
                  </Field>
                  <Field label="Profile approved by">{manifest.warden_approved_by || <span className="text-text-faint">—</span>}</Field>
                  <Field label="Approved commit">
                    {manifest.warden_approved_commit ? (
                      <code className="text-text-muted">{manifest.warden_approved_commit.slice(0, 10)}</code>
                    ) : (
                      <span className="text-text-faint">—</span>
                    )}
                  </Field>
                  <Field label="Approved at">
                    {manifest.warden_approved_at ? new Date(manifest.warden_approved_at).toLocaleString() : <span className="text-text-faint">—</span>}
                  </Field>
                </dl>
              </Card>

              <Card>
                <CardHeader
                  title="Rate Limits"
                  subtitle="Per-tool call throttling"
                  action={<Badge tone="warning">Preview</Badge>}
                />
                <div className="space-y-3 px-5 py-4 text-xs text-text-muted">
                  <PlaceholderRow label="Max calls / minute" value="60" />
                  <PlaceholderRow label="Max concurrent sessions" value="2" />
                  <PlaceholderRow label="Burst allowance" value="10" />
                  <p className="pt-1 text-[11px] text-text-faint">
                    Not yet enforced by the backend — the pool size that bounds concurrency today is set per-session
                    at launch time, not configured here. Shown for the layout this panel will grow into.
                  </p>
                </div>
              </Card>

              <Card>
                <CardHeader
                  title="Allowed Scopes"
                  subtitle="Which declared tools an agent may invoke"
                  action={<Badge tone="warning">Preview</Badge>}
                />
                <div className="space-y-2 px-5 py-4 text-xs">
                  {manifest.tool_declarations && Array.isArray(manifest.tool_declarations) && manifest.tool_declarations.length > 0 ? (
                    (manifest.tool_declarations as Array<{ name: string }>).map((t, i) => (
                      <label key={i} className="flex items-center gap-2 text-text-muted">
                        <input type="checkbox" defaultChecked className="accent-accent" />
                        {t.name}
                      </label>
                    ))
                  ) : (
                    <p className="text-text-faint">No declared tools yet — scope selection appears once static analysis completes.</p>
                  )}
                  <p className="pt-2 text-[11px] text-text-faint">
                    Not yet enforced — every declared tool is currently callable. Per-tool allow/deny is a natural
                    next step on top of the existing tool catalog.
                  </p>
                </div>
              </Card>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-text-faint">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  );
}

function PlaceholderRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between rounded-lg border border-border bg-bg px-3 py-2">
      <span>{label}</span>
      <span className="rounded-md border border-border-strong bg-surface px-2 py-0.5 font-mono text-text-muted">{value}</span>
    </div>
  );
}
