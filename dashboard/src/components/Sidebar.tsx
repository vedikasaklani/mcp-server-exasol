"use client";

import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

const NAV = [
  { href: "/", label: "Overview", hint: "Fleet posture" },
  { href: "/discovery", label: "Discovery", hint: "Servers & tools" },
  { href: "/audit", label: "Audit Trail", hint: "Every call" },
] as const;

function Icon({ name, active }: { name: string; active: boolean }) {
  const cls = `h-[15px] w-[15px] ${active ? "text-primary" : "text-text-faint"}`;
  const common = { fill: "none", stroke: "currentColor", strokeWidth: 1.6, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  switch (name) {
    case "Overview":
      return (
        <svg viewBox="0 0 24 24" className={cls} {...common}>
          <rect x="3" y="3" width="7" height="8" rx="1.5" />
          <rect x="14" y="3" width="7" height="5" rx="1.5" />
          <rect x="14" y="11" width="7" height="10" rx="1.5" />
          <rect x="3" y="14" width="7" height="7" rx="1.5" />
        </svg>
      );
    case "Discovery":
      return (
        <svg viewBox="0 0 24 24" className={cls} {...common}>
          <circle cx="11" cy="11" r="7" />
          <path d="m20 20-3.5-3.5" />
        </svg>
      );
    default:
      return (
        <svg viewBox="0 0 24 24" className={cls} {...common}>
          <path d="M4 5h16M4 10h16M4 15h10M4 20h7" />
        </svg>
      );
  }
}

export function Sidebar() {
  const pathname = usePathname();
  const [health, setHealth] = useState<{ exasol: boolean; postgres: boolean } | null>(null);
  const [down, setDown] = useState(false);

  useEffect(() => {
    let alive = true;
    const check = async () => {
      try {
        const h = await api.health();
        if (alive) {
          setHealth(h);
          setDown(false);
        }
      } catch {
        if (alive) setDown(true);
      }
    };
    const id = window.setTimeout(() => void check(), 0);
    const interval = setInterval(check, 20000);
    return () => {
      alive = false;
      window.clearTimeout(id);
      clearInterval(interval);
    };
  }, []);

  const healthy = !down && health?.exasol && health?.postgres;

  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-border bg-bg-elevated">
      <div className="flex items-center gap-2.5 px-5 py-5">
        <Image src="/logo.png" alt="" width={30} height={30} className="shrink-0" priority />
        <div className="text-[13.5px] font-semibold tracking-tight text-text">MCP Warden</div>
      </div>

      <nav className="flex-1 space-y-0.5 px-3 py-2">
        {NAV.map((item) => {
          const active =
            pathname === item.href || (item.href === "/discovery" && pathname.startsWith("/servers/"));
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`group flex items-center gap-2.5 rounded-lg px-3 py-2 transition-colors ${
                active ? "bg-primary/12 text-text" : "text-text-muted hover:bg-surface-hover hover:text-text"
              }`}
            >
              <Icon name={item.label} active={active} />
              <span className="flex-1 text-[13px] font-medium">{item.label}</span>
              {active && <span className="h-4 w-[2px] rounded-full bg-primary" />}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-border px-4 py-3.5">
        <div className="eyebrow mb-2">Backend</div>
        <div className="space-y-1.5">
          <HealthRow label="API" ok={!down} />
          <HealthRow label="PostgreSQL" ok={!!health?.postgres && !down} />
          <HealthRow label="Exasol" ok={!!health?.exasol && !down} />
        </div>
        {!healthy && (
          <p className="mt-2.5 text-[11px] leading-snug text-warning">
            {down ? "API unreachable — is it running on :8000?" : "A store is unavailable."}
          </p>
        )}
      </div>
    </aside>
  );
}

function HealthRow({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[11.5px] text-text-muted">{label}</span>
      <span className={`flex items-center gap-1.5 text-[11px] ${ok ? "text-success" : "text-danger"}`}>
        <span className={`h-1.5 w-1.5 rounded-full ${ok ? "bg-success" : "bg-danger"}`} />
        {ok ? "up" : "down"}
      </span>
    </div>
  );
}
