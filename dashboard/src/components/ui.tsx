import { ReactNode } from "react";

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={`rounded-xl border border-border bg-surface shadow-sm shadow-black/20 ${className}`}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
      <div>
        <h2 className="text-sm font-semibold text-text">{title}</h2>
        {subtitle && <p className="mt-0.5 text-xs text-text-muted">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

const badgeTones: Record<string, string> = {
  neutral: "bg-white/5 text-text-muted border-border-strong",
  accent: "bg-accent-bg text-blue-300 border-accent-soft/40",
  success: "bg-success-bg text-emerald-300 border-emerald-700/40",
  warning: "bg-warning-bg text-amber-300 border-amber-700/40",
  danger: "bg-danger-bg text-red-300 border-red-700/40",
};

export function Badge({
  children,
  tone = "neutral",
  className = "",
}: {
  children: ReactNode;
  tone?: keyof typeof badgeTones;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium ${badgeTones[tone]} ${className}`}
    >
      {children}
    </span>
  );
}

/** Maps a runtime decision (ALLOWED/BLOCKED/FLAGGED) to the right badge tone. */
export function DecisionBadge({ decision }: { decision: string }) {
  const upper = decision.toUpperCase();
  if (upper === "ALLOWED") return <Badge tone="success">● Allowed</Badge>;
  if (upper === "BLOCKED") return <Badge tone="danger">● Blocked</Badge>;
  if (upper === "FLAGGED") return <Badge tone="warning">● Warning</Badge>;
  return <Badge tone="neutral">{decision || "Unknown"}</Badge>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  const upper = (severity || "").toUpperCase();
  if (upper === "CRITICAL") return <Badge tone="danger">Critical</Badge>;
  if (upper === "HIGH") return <Badge tone="danger">High</Badge>;
  if (upper === "MEDIUM") return <Badge tone="warning">Medium</Badge>;
  if (upper === "LOW") return <Badge tone="accent">Low</Badge>;
  return <Badge tone="neutral">{severity || "Unknown"}</Badge>;
}

export function StatCard({
  label,
  value,
  hint,
  tone = "neutral",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "neutral" | "success" | "warning" | "danger";
}) {
  const valueTone =
    tone === "success"
      ? "text-emerald-300"
      : tone === "warning"
        ? "text-amber-300"
        : tone === "danger"
          ? "text-red-300"
          : "text-text";
  return (
    <Card className="px-5 py-4">
      <p className="text-xs font-medium uppercase tracking-wide text-text-faint">{label}</p>
      <div className={`mt-2 text-2xl font-semibold tabular-nums ${valueTone}`}>{value}</div>
      {hint && <p className="mt-1 text-xs text-text-muted">{hint}</p>}
    </Card>
  );
}

export function Spinner({ className = "" }: { className?: string }) {
  return (
    <div
      className={`h-4 w-4 animate-spin rounded-full border-2 border-border-strong border-t-accent ${className}`}
    />
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1 px-6 py-14 text-center">
      <p className="text-sm font-medium text-text-muted">{title}</p>
      {hint && <p className="max-w-sm text-xs text-text-faint">{hint}</p>}
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      <Badge tone="danger">Connection error</Badge>
      <p className="max-w-md text-xs text-text-faint">{message}</p>
    </div>
  );
}
