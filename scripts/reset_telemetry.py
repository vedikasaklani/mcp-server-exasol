"""Clear the Exasol telemetry store so it agrees with an empty PostgreSQL.

Registration lives in PostgreSQL and telemetry in Exasol. Dropping and
recreating the PostgreSQL container - which is the usual way to get a clean
slate - leaves Exasol holding servers, scores and audit history that nothing
in PostgreSQL backs any more. The dashboard reads its server list from
Exasol, so those orphans keep appearing while every manifest lookup behind
them 404s.

Run this whenever you reset PostgreSQL, so both stores start empty together.

    python3 scripts/reset_telemetry.py [--yes]

DIM_DATE is preserved: it is a static calendar dimension, not per-server
data, and regenerating it is needless work.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pyexasol

# Child tables first - DIM_SERVER and DIM_TOOL are referenced by the facts.
TABLES = (
    "STG_STATIC_FINDINGS",
    "FACT_STATIC_FINDINGS",
    "FACT_RUNTIME_FINDINGS",
    "FACT_RUNTIME_EVENTS",
    "FACT_TRUST_SCORE",
    "FACT_SESSION",
    "FACT_SCAN_RUN",
    "FACT_MANIFEST_HISTORY",
    "ETL_SYNC_STATE",
    "DIM_TOOL",
    "DIM_ANALYZER",
    "DIM_SERVER",
)


def _load_dotenv() -> None:
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return
    for raw in env_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def main() -> int:
    _load_dotenv()
    if "--yes" not in sys.argv:
        print("This deletes every server, audit event, finding and score in")
        print("Exasol's MCP_ANALYTICS schema. Re-run with --yes to confirm.")
        return 1

    exa = pyexasol.connect(
        dsn=os.environ["EXASOL_DSN"],
        user=os.environ["EXASOL_USER"],
        password=os.environ["EXASOL_PASSWORD"],
    )
    try:
        exa.execute("OPEN SCHEMA MCP_ANALYTICS")
        for table in TABLES:
            try:
                exa.execute(f"DELETE FROM {table}")
            except Exception as exc:  # table may not exist in older schemas
                print(f"  skipped {table}: {str(exc).splitlines()[0][:80]}")
        exa.commit()
        remaining = exa.execute("SELECT count(*) FROM DIM_SERVER").fetchval()
        print(f"telemetry store cleared; DIM_SERVER now holds {remaining} row(s)")
    finally:
        exa.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
