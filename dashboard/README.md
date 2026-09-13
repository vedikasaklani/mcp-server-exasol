# MCP Warden dashboard

Next.js + Tailwind frontend for the trust/reputation backend
(`server_management/api/api.py`). Dark-mode-first, sidebar navigation, four
views: Overview, Discovery Hub, Audit & Activity, Security Controls.

## Run it

All commands below run **from this `dashboard/` directory**, not the repo root:

```bash
cd dashboard   # skip if you're already here
npm install
cp .env.example .env.local   # point NEXT_PUBLIC_API_BASE_URL at your backend
npm run dev                  # http://localhost:3000
```

The backend must be running and reachable at `NEXT_PUBLIC_API_BASE_URL`
(default `http://localhost:8000`) — see `../HOSTCONFIG_INTEGRATION.md` §7 for
how to stand that up. The backend also needs CORS enabled for this to work
from a browser; `server_management/api/api.py` already has this (wide-open
origin, appropriate for an internal ops tool, not a public multi-tenant API).

## What's wired to real data vs. still a preview

Everything except two panels on Security Controls calls the real backend —
there is no mock data layer. Specifically:

- **Overview, Discovery Hub, Audit & Activity**: fully live. Registering a
  server, calling a tool, and everything you see update from the real
  Postgres/Exasol-backed API.
- **Security Controls → Allowed Destinations**: live, editable, saves via
  `PATCH /servers/{id}/manifest`.
- **Security Controls → Rate Limits / Allowed Scopes**: intentionally marked
  "Preview" — the backend doesn't enforce either yet (see
  `HOSTCONFIG_INTEGRATION.md` §3). Shown for the layout, not wired to a real
  toggle.

## Structure

```
src/lib/api.ts          typed client for every backend endpoint this UI uses
src/components/ui.tsx   Card, Badge, StatCard, DecisionBadge, etc.
src/components/Sidebar.tsx
src/components/Modal.tsx
src/app/page.tsx         Overview
src/app/discovery/       Discovery Hub (server grid, tool browser, "Try it" live call modal)
src/app/audit/           Audit & Activity Logs (filterable table)
src/app/security/        Security Controls
```

## Production build

```bash
npm run build && npm start
```

Type-checks clean, builds statically (no server-side data fetching — every
page is a client component that calls the API directly from the browser).
