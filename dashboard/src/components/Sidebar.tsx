"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

const NAV = [
  { href: "/", label: "Overview", icon: OverviewIcon },
  { href: "/discovery", label: "Discovery Hub", icon: DiscoveryIcon },
  { href: "/audit", label: "Audit & Activity", icon: AuditIcon },
  { href: "/security", label: "Security Controls", icon: SecurityIcon },
];

export function Sidebar() {
  const pathname = usePathname();
  const [backendUp, setBackendUp] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;
    const check = () =>
      api
        .health()
        .then((h) => !cancelled && setBackendUp(h.status === "ok"))
        .catch(() => !cancelled && setBackendUp(false));
    check();
    const id = setInterval(check, 15000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  return (
    <aside className="flex h-screen w-64 shrink-0 flex-col border-r border-border bg-bg-elevated">
      <div className="flex items-center gap-2.5 border-b border-border px-5 py-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent-bg text-accent">
          <ShieldIcon />
        </div>
        <div>
          <p className="text-sm font-semibold text-text leading-none">MCP Warden</p>
          <p className="mt-1 text-[11px] text-text-faint leading-none">Trust &amp; Reputation</p>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-3 py-4">
        {NAV.map(({ href, label, icon: Icon }) => {
          const active = pathname === href;
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                active
                  ? "bg-accent-bg text-blue-300"
                  : "text-text-muted hover:bg-surface-hover hover:text-text"
              }`}
            >
              <Icon active={active} />
              {label}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-border px-5 py-4">
        <div className="flex items-center gap-2 text-xs">
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              backendUp === null
                ? "bg-text-faint"
                : backendUp
                  ? "bg-success animate-pulse"
                  : "bg-danger"
            }`}
          />
          <span className="text-text-muted">
            {backendUp === null ? "Checking backend…" : backendUp ? "Backend connected" : "Backend unreachable"}
          </span>
        </div>
      </div>
    </aside>
  );
}

function iconProps(active?: boolean) {
  return {
    width: 18,
    height: 18,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: active ? 2.2 : 1.8,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };
}

function OverviewIcon({ active }: { active?: boolean }) {
  return (
    <svg {...iconProps(active)}>
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </svg>
  );
}
function DiscoveryIcon({ active }: { active?: boolean }) {
  return (
    <svg {...iconProps(active)}>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.5-3.5" />
    </svg>
  );
}
function AuditIcon({ active }: { active?: boolean }) {
  return (
    <svg {...iconProps(active)}>
      <path d="M9 3h6l3 3v15H6V6z" />
      <path d="M9 12h6M9 16h6M9 8h2" />
    </svg>
  );
}
function SecurityIcon({ active }: { active?: boolean }) {
  return (
    <svg {...iconProps(active)}>
      <path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z" />
      <path d="m9.5 12 1.8 1.8L15 10" />
    </svg>
  );
}
function ShieldIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z" />
    </svg>
  );
}
