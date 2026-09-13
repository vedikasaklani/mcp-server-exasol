-- ============================================================================
-- compute_trust_score.sql - daily rollup into FACT_TRUST_SCORE.
--
-- Run this on a schedule (cron/Airflow calling it over pyexasol - Exasol
-- has no built-in job scheduler). Daily is enough: static/behavioral
-- posture doesn't shift hour to hour, and the runtime side already decays
-- fast (3-day half-life) so a once-a-day refresh keeps it current.
--
-- TUNABLES (all in one place, adjust and re-run):
--   static/behavioral half-life  : 45 days  - code-level posture is slow-moving
--   runtime half-life            : 3 days   - operational health is volatile
--   severity weights             : SEV_CRITICAL 40 / SEV_HIGH 20 / SEV_MEDIUM 8 / SEV_LOW 2
--   reachable multiplier (SCA)   : 2x  - a called vulnerable function beats
--                                        an uncalled transitive one
--   destination-violation weight : 3x on the violation rate
--   exfiltration-flag weight     : 5x on the flag rate - proven bad behavior,
--                                        weighted worse than a policy mismatch
--   security vs operational blend: 60% / 40% for OVERALL_SCORE - a trust/
--                                        discovery platform should weight
--                                        "is it safe" over "is it fast"
-- ============================================================================

OPEN SCHEMA MCP_ANALYTICS;

MERGE INTO FACT_TRUST_SCORE t
USING (
WITH static_weighted AS (
    -- Decayed, severity- and reachability-weighted penalty, summed across
    -- ALL historical findings for the server (not just the latest scan) -
    -- the decay itself is what makes old findings stop mattering, so a
    -- separate "latest scan" filter isn't needed.
    SELECT
        f.SERVER_ID,
        SUM(
            (CASE UPPER(f.SEVERITY)
                WHEN 'SEV_CRITICAL' THEN 40
                WHEN 'SEV_HIGH'     THEN 20
                WHEN 'SEV_MEDIUM'   THEN 8
                WHEN 'SEV_LOW'      THEN 2
                ELSE 0
             END)
            * (CASE WHEN f.REACHABLE = TRUE THEN 2 ELSE 1 END)
            * POWER(0.5, DAYS_BETWEEN(CURRENT_DATE, d.FULL_DATE) / 45.0)
        ) AS static_penalty
    FROM FACT_STATIC_FINDINGS f
    JOIN DIM_DATE d ON d.DATE_KEY = f.DATE_KEY
    GROUP BY f.SERVER_ID
),

runtime_weighted AS (
    -- Same decay idea applied to runtime telemetry, with a much shorter
    -- half-life. The 90-day WHERE floor is just to bound the scan - at a
    -- 3-day half-life, anything older than ~60 days is already
    -- indistinguishable from zero weight.
    SELECT
        e.SERVER_ID,
        SUM(POWER(0.5, DAYS_BETWEEN(CURRENT_DATE, CAST(e.EVENT_TS AS DATE)) / 3.0)) AS weight_total,
        SUM(CASE WHEN e.DESTINATION_MATCH = FALSE
                 THEN POWER(0.5, DAYS_BETWEEN(CURRENT_DATE, CAST(e.EVENT_TS AS DATE)) / 3.0) ELSE 0 END
        ) AS violation_weighted,
        SUM(CASE WHEN e.SENSITIVE_DATA_FLAG = TRUE
                 THEN POWER(0.5, DAYS_BETWEEN(CURRENT_DATE, CAST(e.EVENT_TS AS DATE)) / 3.0) ELSE 0 END
        ) AS exfil_weighted,
        SUM(CASE WHEN e.STATUS_CODE < 400
                 THEN POWER(0.5, DAYS_BETWEEN(CURRENT_DATE, CAST(e.EVENT_TS AS DATE)) / 3.0) ELSE 0 END
        ) AS success_weighted,
        COUNT(*) AS total_calls,
        PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY e.LATENCY_MS) AS p95_latency_ms
    FROM FACT_RUNTIME_EVENTS e
    WHERE e.EVENT_TS >= CURRENT_TIMESTAMP - INTERVAL '90' DAY
    GROUP BY e.SERVER_ID
),

combined AS (
    SELECT
        s.SERVER_ID,
        COALESCE(sw.static_penalty, 0) AS static_penalty,

        GREATEST(0, 100
            - COALESCE(sw.static_penalty, 0)
            - (COALESCE(rw.violation_weighted, 0) / NULLIF(rw.weight_total, 0)) * 100 * 3
            - (COALESCE(rw.exfil_weighted, 0)     / NULLIF(rw.weight_total, 0)) * 100 * 5
        ) AS security_score,

        LEAST(100, GREATEST(0,
            100 * (
                  0.5 * (COALESCE(rw.success_weighted, 0) / NULLIF(rw.weight_total, 0))
                + 0.3 * (1 - LEAST(1, COALESCE(rw.p95_latency_ms, 0) / 5000.0))
                -- confidence/throughput term: don't let a server with a
                -- handful of calls this window look as solid as one under
                -- real load - scales up to full credit at 100+ calls.
                + 0.2 * LEAST(1, COALESCE(rw.total_calls, 0) / 100.0)
            )
        )) AS operational_score,

        rw.violation_weighted,
        rw.exfil_weighted,
        (rw.success_weighted / NULLIF(rw.weight_total, 0)) AS success_rate,
        rw.p95_latency_ms,
        rw.total_calls
    FROM DIM_SERVER s
    LEFT JOIN static_weighted sw  ON sw.SERVER_ID = s.SERVER_ID
    LEFT JOIN runtime_weighted rw ON rw.SERVER_ID = s.SERVER_ID
)
    SELECT
        SERVER_ID,
        TO_NUMBER(TO_CHAR(CURRENT_DATE, 'YYYYMMDD')) AS DATE_KEY,
        security_score,
        operational_score,
        (0.6 * security_score + 0.4 * operational_score) AS overall_score,
        static_penalty,
        -- NOTE: these two are decay-weighted "effective" counts, not raw
        -- COUNT(*) - a violation from 3 days ago counts less than one from
        -- today. Keep that in mind reading this column directly.
        violation_weighted AS runtime_violation_count,
        exfil_weighted AS runtime_exfil_flag_count,
        success_rate,
        p95_latency_ms,
        total_calls AS total_calls_in_window
    FROM combined
) c
ON (t.SERVER_ID = c.SERVER_ID AND t.DATE_KEY = c.DATE_KEY)
WHEN MATCHED THEN UPDATE SET
    t.SECURITY_SCORE           = c.security_score,
    t.OPERATIONAL_SCORE        = c.operational_score,
    t.OVERALL_SCORE            = c.overall_score,
    t.STATIC_PENALTY           = c.static_penalty,
    t.RUNTIME_VIOLATION_COUNT  = c.runtime_violation_count,
    t.RUNTIME_EXFIL_FLAG_COUNT = c.runtime_exfil_flag_count,
    t.SUCCESS_RATE             = c.success_rate,
    t.P95_LATENCY_MS           = c.p95_latency_ms,
    t.TOTAL_CALLS_IN_WINDOW    = c.total_calls_in_window,
    t.COMPUTED_AT              = CURRENT_TIMESTAMP
WHEN NOT MATCHED THEN INSERT (
    SERVER_ID, DATE_KEY, SECURITY_SCORE, OPERATIONAL_SCORE, OVERALL_SCORE, STATIC_PENALTY,
    RUNTIME_VIOLATION_COUNT, RUNTIME_EXFIL_FLAG_COUNT, SUCCESS_RATE, P95_LATENCY_MS, TOTAL_CALLS_IN_WINDOW
) VALUES (
    c.SERVER_ID, c.DATE_KEY, c.security_score, c.operational_score, c.overall_score, c.static_penalty,
    c.runtime_violation_count, c.runtime_exfil_flag_count, c.success_rate, c.p95_latency_ms, c.total_calls_in_window
);