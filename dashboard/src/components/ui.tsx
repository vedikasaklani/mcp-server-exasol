"use client";

import { ReactNode } from "react";

/* ------------------------------------------------------------------ shell */

export function Card({
  children,
  className = "",
  padded = true,
}: {
  children: ReactNode;
  className?: string;
  padded?: boolean;
}) {
  return (
    <div
      className={`rounded-xl border border-border bg-surface ${padded ? "p-5" : ""} ${className}`}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  title,
  subtitle,
  right,
}: {
  title: string;
  subtitle?: string;
  right?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
      <div className="min-w-0">
        <h2 className="text-[13.5px] font-semibold tracking-tight text-text">{title}</h2>
        {subtitle && <p className="mt-0.5 text-xs text-text-faint">{subtitle}</p>}
      </div>
      {right && <div className="shrink-0">{right}</div>}
    </div>
  );
}

export function PageHeader({
  title,
  subtitle,
  right,
}: {
  title: string;
  subtitle?: string;
  right?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-[22px] font-semibold tracking-tight text-text">{title}</h1>
        {subtitle && <p className="mt-1 text-[13px] text-text-muted">{subtitle}</p>}
      </div>
      {right}
    </div>
  );
}

export function Button({
  children,
  onClick,
  variant = "default",
  disabled,
  size = "md",
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "default" | "primary" | "danger" | "ghost";
  disabled?: boolean;
  size?: "sm" | "md";
  type?: "button" | "submit";
}) {
  const base =
    "inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-45";
  const sizes = size === "sm" ? "px-2.5 py-1 text-xs" : "px-3.5 py-2 text-[13px]";
  const variants = {
    default: "border border-border-strong bg-surface-2 text-text hover:bg-surface-hover",
    primary: "bg-accent text-[#04100e] hover:bg-accent-dim font-semibold",
    danger: "border border-danger/40 bg-danger/10 text-danger hover:bg-danger/20",
    ghost: "text-text-muted hover:bg-surface-hover hover:text-text",
  }[variant];
  return (
    <button type={type} onClick={onClick} disabled={disabled} className={`${base} ${sizes} ${variants}`}>
      {children}
    </button>
  );
}

/* ----------------------------------------------------------------- status */

const SEVERITY_STYLE: Record<string, { fg: string; bg: string; label: string }> = {
  critical: { fg: "text-sev-critical", bg: "bg-sev-critical/12 border-sev-critical/30", label: "Critical" },
  high: { fg: "text-sev-high", bg: "bg-sev-high/12 border-sev-high/30", label: "High" },
  medium: { fg: "text-sev-medium", bg: "bg-sev-medium/12 border-sev-medium/30", label: "Medium" },
  low: { fg: "text-sev-low", bg: "bg-sev-low/12 border-sev-low/30", label: "Low" },
  none: { fg: "text-text-faint", bg: "bg-surface-2 border-border", label: "Clean" },
  info: { fg: "text-text-faint", bg: "bg-surface-2 border-border", label: "Info" },
};

export function severityStyle(severity: string) {
  return SEVERITY_STYLE[severity?.toLowerCase()] ?? SEVERITY_STYLE.none;
}

export function SeverityBadge({ severity, label }: { severity: string; label?: string }) {
  const s = severityStyle(severity);
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10.5px] font-semibold uppercase tracking-wide ${s.bg} ${s.fg}`}
    >
      {label ?? s.label}
    </span>
  );
}

export function DecisionBadge({ decision }: { decision: string }) {
  const map: Record<string, string> = {
    ALLOWED: "border-success/30 bg-success/10 text-success",
    FLAGGED: "border-sev-medium/30 bg-sev-medium/10 text-sev-medium",
    BLOCKED: "border-danger/35 bg-danger/12 text-danger",
  };
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-medium ${
        map[decision] ?? "border-border bg-surface-2 text-text-muted"
      }`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {decision.charAt(0) + decision.slice(1).toLowerCase()}
    </span>
  );
}

export function LiveBadge({ live }: { live: boolean }) {
  if (!live) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded border border-border bg-surface-2 px-2 py-0.5 text-[11px] text-text-faint">
        <span className="h-1.5 w-1.5 rounded-full bg-text-faint" />
        Offline
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded border border-success/30 bg-success/10 px-2 py-0.5 text-[11px] font-medium text-success">
      <span className="live-dot h-1.5 w-1.5 rounded-full bg-success" />
      Live
    </span>
  );
}

/* ------------------------------------------------------------------ stats */

export function StatCard({
  label,
  value,
  hint,
  tone = "default",
  chart,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "default" | "good" | "warn" | "bad" | "accent";
  chart?: ReactNode;
}) {
  const toneClass = {
    default: "text-text",
    good: "text-success",
    warn: "text-warning",
    bad: "text-danger",
    accent: "text-accent",
  }[tone];
  return (
    <div className="rounded-xl border border-border bg-surface p-4">
      <div className="eyebrow">{label}</div>
      <div className="mt-2 flex items-end justify-between gap-3">
        <div className={`tabular text-[27px] font-semibold leading-none ${toneClass}`}>{value}</div>
        {chart}
      </div>
      {hint && <div className="mt-2 text-[11.5px] text-text-faint">{hint}</div>}
    </div>
  );
}

/* ----------------------------------------------------------------- charts */

/** A compact trend line. Pure SVG: a charting library would be more code
 *  shipped than the whole dashboard for one shape. */
export function Sparkline({
  values,
  width = 96,
  height = 30,
  stroke = "var(--accent)",
}: {
  values: number[];
  width?: number;
  height?: number;
  stroke?: string;
}) {
  if (values.length < 2) return <div style={{ width, height }} />;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  const step = width / (values.length - 1);
  const pts = values.map((v, i) => [i * step, height - ((v - min) / span) * (height - 3) - 1.5]);
  const d = pts.map((p, i) => `${i === 0 ? "M" : "L"}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  const area = `${d} L${width},${height} L0,${height} Z`;
  return (
    <svg width={width} height={height} className="overflow-visible">
      <path d={area} fill={stroke} opacity={0.1} />
      <path d={d} fill="none" stroke={stroke} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

/** Horizontal severity distribution. Shows counts, not just proportion —
 *  a purely proportional bar hides whether "mostly critical" is 3 findings
 *  or 300. */
export function SeverityBar({
  counts,
  total,
}: {
  counts: Record<string, number>;
  total?: number;
}) {
  const order = ["critical", "high", "medium", "low", "none"];
  const sum = total ?? order.reduce((a, k) => a + (counts[k] || 0), 0);
  if (!sum) {
    return <div className="h-1.5 w-full rounded-full bg-surface-2" />;
  }
  return (
    <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
      {order.map((k) =>
        counts[k] ? (
          <div
            key={k}
            style={{ width: `${(counts[k] / sum) * 100}%`, background: `var(--sev-${k})` }}
            title={`${k}: ${counts[k]}`}
          />
        ) : null
      )}
    </div>
  );
}

export function ScoreRing({ score, size = 56 }: { score: number | null; size?: number }) {
  const r = (size - 6) / 2;
  const c = 2 * Math.PI * r;
  const pct = score === null ? 0 : Math.max(0, Math.min(100, score)) / 100;
  const color =
    score === null ? "var(--sev-none)" : score >= 80 ? "var(--success)" : score >= 50 ? "var(--warning)" : "var(--danger)";
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--surface-2)" strokeWidth={4} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={4}
          strokeLinecap="round"
          strokeDasharray={`${c * pct} ${c}`}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="tabular text-[13px] font-semibold" style={{ color }}>
          {score === null ? "—" : Math.round(score)}
        </span>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ misc */

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-text-faint">
      <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-border-strong border-t-accent" />
      {label && <span className="text-[13px]">{label}</span>}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
      <p className="text-[13px] font-medium text-text-muted">{title}</p>
      {hint && <p className="mt-1 max-w-md text-xs text-text-faint">{hint}</p>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-danger/25 bg-danger/5 px-6 py-8 text-center">
      <p className="text-[13px] text-danger">{message}</p>
      {onRetry && (
        <Button size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function Mono({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <span className={`font-mono text-[11.5px] ${className}`}>{children}</span>;
}

export function KeyValue({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1">
      <span className="shrink-0 text-[11.5px] text-text-faint">{k}</span>
      <span className="tabular min-w-0 truncate text-right text-[12px] text-text">{v}</span>
    </div>
  );
}

export function bytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function num(n: number | null | undefined): string {
  return n === null || n === undefined ? "—" : n.toLocaleString();
}

export function relativeTime(iso: string): string {
  if (!iso) return "—";
  const then = new Date(iso.includes("T") ? iso : iso.replace(" ", "T") + "Z").getTime();
  if (Number.isNaN(then)) return iso;
  const secs = Math.max(0, (Date.now() - then) / 1000);
  if (secs < 45) return "just now";
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}

export function formatTime(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso.includes("T") ? iso : iso.replace(" ", "T") + "Z");
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
