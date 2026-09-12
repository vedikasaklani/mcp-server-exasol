-- ============================================================================
-- Exasol star schema - MCP server trust/reputation platform
--
-- Notes specific to Exasol (not Postgres):
--   - No native JSON type. Any variable-shaped payload is stored as
--     VARCHAR holding serialized JSON text, read back with JSON_VALUE /
--     JSON_EXTRACT. Write it with json.dumps() on the Python side.
--   - Dimension tables are NOT given a DISTRIBUTE BY - they're small enough
--     to fall under the replication border (default 100k rows) and get
--     auto-replicated to every node, which is what you want for star-schema
--     dims. Only the fact tables get an explicit DISTRIBUTE BY.
--   - PRIMARY KEY / FOREIGN KEY here are informational (used by the query
--     optimizer for join elimination), not enforced constraints the way
--     Postgres enforces them. Uniqueness/integrity is the ETL's job.
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS MCP_ANALYTICS;
OPEN SCHEMA MCP_ANALYTICS;

-- ----------------------------------------------------------------------------
-- Dimensions
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS DIM_SERVER (
    SERVER_ID        VARCHAR(36)   NOT NULL,
    REPO_URL         VARCHAR(500)  NOT NULL,
    INSTALLATION_ID  DECIMAL(18,0),
    REGISTERED_AT    TIMESTAMP,
    SYNCED_AT        TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (SERVER_ID)
);

CREATE TABLE IF NOT EXISTS DIM_TOOL (
    TOOL_KEY    INT IDENTITY PRIMARY KEY,
    SERVER_ID   VARCHAR(36)   NOT NULL,
    TOOL_NAME   VARCHAR(255)  NOT NULL,
    FIRST_SEEN_SCAN_RUN_ID VARCHAR(36),
    SYNCED_AT   TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT FK_DIM_TOOL_SERVER FOREIGN KEY (SERVER_ID) REFERENCES DIM_SERVER (SERVER_ID) DISABLE
    -- natural key is (SERVER_ID, TOOL_NAME) - the ETL's MERGE ... ON clause
    -- enforces this, Exasol won't reject a duplicate pair on its own.
);

CREATE TABLE IF NOT EXISTS DIM_ANALYZER (
    ANALYZER_KEY   INT IDENTITY PRIMARY KEY,
    ANALYZER_NAME  VARCHAR(100) NOT NULL   -- "semgrep_sast" | "semgrep_supply_chain" |
                                            -- Cisco's vulnerable-package analyzer key | "behavioral_analyzer"
);

CREATE TABLE IF NOT EXISTS DIM_DATE (
    DATE_KEY     DECIMAL(8,0)  NOT NULL,   -- YYYYMMDD, e.g. 20260911
    FULL_DATE    DATE          NOT NULL,
    DAY_OF_WEEK  VARCHAR(10)   NOT NULL,
    MONTH_NUM    DECIMAL(2,0)  NOT NULL,
    YEAR_NUM     DECIMAL(4,0)  NOT NULL,
    IS_WEEKEND   BOOLEAN       NOT NULL,
    PRIMARY KEY (DATE_KEY)
);

-- Facts

-- One row per Phase 1 / Phase 2 finding. Mirrors RuleFinding +
-- ToolBehavioralFinding from Postgres, unioned - `phase` tells you which
-- source table it came from, `source_table`/`source_id` let you trace a
-- row back to Postgres for drill-through.
CREATE TABLE IF NOT EXISTS FACT_STATIC_FINDINGS (
    FINDING_KEY   INT IDENTITY,
    SOURCE_TABLE  VARCHAR(30)   NOT NULL,   -- "rule_finding" | "tool_behavioral_finding"
    SOURCE_ID     DECIMAL(18,0) NOT NULL,   -- original Postgres row id
    SCAN_RUN_ID   VARCHAR(36)   NOT NULL,   -- degenerate dimension - no separate dim_scan needed for this alone
    SERVER_ID     VARCHAR(36)   NOT NULL,
    TOOL_KEY      INT,                      -- nullable: some findings aren't tool-specific
    ANALYZER_KEY  INT           NOT NULL,
    DATE_KEY      DECIMAL(8,0)  NOT NULL,   -- date the scan was reviewed
    PHASE         VARCHAR(10)   NOT NULL,   -- "rule" | "llm"
    SEVERITY      VARCHAR(20)   NOT NULL,
    REACHABLE     BOOLEAN,                  -- SCA-only signal; NULL when not applicable
    MESSAGE       VARCHAR(2000),
    DETAILS       VARCHAR(2000000),         -- serialized JSON - see note at top of file
    LOADED_AT     TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (FINDING_KEY),
    CONSTRAINT FK_FSF_SERVER   FOREIGN KEY (SERVER_ID)   REFERENCES DIM_SERVER (SERVER_ID)     DISABLE,
    CONSTRAINT FK_FSF_TOOL     FOREIGN KEY (TOOL_KEY)    REFERENCES DIM_TOOL (TOOL_KEY)         DISABLE,
    CONSTRAINT FK_FSF_ANALYZER FOREIGN KEY (ANALYZER_KEY)REFERENCES DIM_ANALYZER (ANALYZER_KEY) DISABLE,
    CONSTRAINT FK_FSF_DATE     FOREIGN KEY (DATE_KEY)    REFERENCES DIM_DATE (DATE_KEY)         DISABLE,
    DISTRIBUTE BY SERVER_ID    -- most queries/joins group or filter by server
);

-- One row per proxy call. This is the audit log from the egress proxy,
-- landed directly here (not sourced from Postgres) - see the field
-- rationale from the earlier audit-log design discussion.
CREATE TABLE IF NOT EXISTS FACT_RUNTIME_EVENTS (
    EVENT_ID                   VARCHAR(255)  NOT NULL,
    SERVER_ID                  VARCHAR(36)   NOT NULL,
    TOOL_KEY                   INT,
    AGENT_ID                   VARCHAR(255),
    SESSION_ID                 VARCHAR(64),
    DATE_KEY                   DECIMAL(8,0)  NOT NULL,
    EVENT_TS                   TIMESTAMP     NOT NULL,  
    DESTINATION_DECLARED       VARCHAR(500),
    DESTINATION_ACTUAL         VARCHAR(500),
    DESTINATION_MATCH          BOOLEAN,
    INTENT_MATCH                BOOLEAN,            ---- ???     
    SENSITIVE_DATA_FLAG         BOOLEAN,   ---??
    SENSITIVE_DATA_CATEGORIES   VARCHAR(500),    ---??           -- serialized JSON array, e.g. ["api_key","email"]
    DECISION                    VARCHAR(20),               -- "ALLOWED" | "BLOCKED" | "FLAGGED"
    DECISION_REASON              VARCHAR(255), -- ????
    LATENCY_MS                   DECIMAL(10,0),
    STATUS_CODE                  DECIMAL(5,0),
    BYTES_SENT                   DECIMAL(18,0),
    BYTES_RECEIVED                DECIMAL(18,0),
    RETRY_COUNT                   DECIMAL(5,0),
    LOADED_AT                     TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (EVENT_ID),
    CONSTRAINT FK_FRE_SERVER FOREIGN KEY (SERVER_ID) REFERENCES DIM_SERVER (SERVER_ID) DISABLE,
    CONSTRAINT FK_FRE_TOOL   FOREIGN KEY (TOOL_KEY)  REFERENCES DIM_TOOL (TOOL_KEY)     DISABLE,
    CONSTRAINT FK_FRE_DATE   FOREIGN KEY (DATE_KEY)  REFERENCES DIM_DATE (DATE_KEY) DISABLE,
    DISTRIBUTE BY SERVER_ID
);

-- One row per runtime detector finding emitted by the proxy.
CREATE TABLE IF NOT EXISTS FACT_RUNTIME_FINDINGS (
    FINDING_ID       VARCHAR(255)  NOT NULL,
    SERVER_ID        VARCHAR(36)   NOT NULL,
    TOOL_KEY         INT,
    SESSION_ID       VARCHAR(64),
    REQUEST_ID       VARCHAR(64),
    EVENT_TS         TIMESTAMP     NOT NULL,
    DETECTOR         VARCHAR(100)  NOT NULL,
    FAMILY           VARCHAR(100),
    SEVERITY         VARCHAR(20)   NOT NULL,
    CONFIDENCE       VARCHAR(30),
    KERNEL_ATTESTED  BOOLEAN,
    TITLE            VARCHAR(2000),
    DETAIL           VARCHAR(2000000),
    EVIDENCE         VARCHAR(2000000),
    OCCURRENCES      DECIMAL(18,0),
    LOADED_AT        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (FINDING_ID),
    DISTRIBUTE BY SERVER_ID
);

-- One row per completed proxy session.
CREATE TABLE IF NOT EXISTS FACT_SESSION (
    SESSION_ID            VARCHAR(64) NOT NULL,
    SERVER_ID             VARCHAR(36) NOT NULL,
    STARTED_AT            TIMESTAMP,
    ENDED_AT              TIMESTAMP,
    DURATION_SECONDS      DECIMAL(18,6),
    POSTURE               VARCHAR(30),
    POSTURE_REASON        VARCHAR(255),
    SEV_CRITICAL          DECIMAL(18,0),
    SEV_HIGH              DECIMAL(18,0),   -- was HIGH: reserved word (skyline PREFERRING clause), broke parser
    SEV_MEDIUM            DECIMAL(18,0),
    SEV_LOW               DECIMAL(18,0),   -- was LOW: same reserved-word issue
    KERNEL_ATTESTED       DECIMAL(18,0),
    REQUESTS              DECIMAL(18,0),
    FAILURES              DECIMAL(18,0),
    DENIALS               DECIMAL(18,0),
    P50_LATENCY_MS        DECIMAL(18,0),
    P95_LATENCY_MS        DECIMAL(18,0),
    P99_LATENCY_MS        DECIMAL(18,0),
    SYSCALL_COUNT         DECIMAL(18,0),
    DISTINCT_PATHS        DECIMAL(18,0),
    FILE_READ_BYTES       DECIMAL(18,0),
    FILE_WRITE_BYTES      DECIMAL(18,0),
    NET_WRITE_BYTES       DECIMAL(18,0),
    PROCESS_SPAWNS        DECIMAL(18,0),
    ANALYSIS_HEALTHY      BOOLEAN,
    LEARNING_MODE         BOOLEAN,
    CONFINEMENT           VARCHAR(100),
    RUNTIME               VARCHAR(100),
    AUDIT_ENTRIES         DECIMAL(18,0),
    AUDIT_CHAIN_VERIFIED  BOOLEAN,
    LOADED_AT             TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (SESSION_ID),
    DISTRIBUTE BY SERVER_ID
);

-- One row per scan run. This preserves lifecycle and verdict state even when
-- a scan is rejected or fails before it produces findings.
CREATE TABLE IF NOT EXISTS FACT_SCAN_RUN (
    SCAN_RUN_ID       VARCHAR(36)   NOT NULL,
    SERVER_ID         VARCHAR(36)   NOT NULL,
    COMMIT_SHA        VARCHAR(64)   NOT NULL,
    STATUS            VARCHAR(40)   NOT NULL,
    RULE_VERDICT      VARCHAR(30),
    LLM_VERDICT       VARCHAR(30),
    DATE_KEY          DECIMAL(8,0)  NOT NULL,
    STARTED_AT        TIMESTAMP,
    FINISHED_AT       TIMESTAMP,
    DURATION_SECONDS  DECIMAL(18,6),
    LOADED_AT         TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (SCAN_RUN_ID),
    CONSTRAINT FK_FSR_SERVER FOREIGN KEY (SERVER_ID) REFERENCES DIM_SERVER (SERVER_ID) DISABLE,
    CONSTRAINT FK_FSR_DATE   FOREIGN KEY (DATE_KEY)   REFERENCES DIM_DATE (DATE_KEY) DISABLE,
    DISTRIBUTE BY SERVER_ID
);

-- Immutable manifest-version audit rows, synchronized from PostgreSQL.
CREATE TABLE IF NOT EXISTS FACT_MANIFEST_HISTORY (
    SERVER_ID           VARCHAR(36)   NOT NULL,
    VERSION             DECIMAL(18,0)  NOT NULL,
    ALLOWED_DESTINATIONS VARCHAR(2000000),
    CHANGE_REASON       VARCHAR(100),
    DATE_KEY            DECIMAL(8,0)  NOT NULL,
    CHANGED_AT          TIMESTAMP,
    LOADED_AT           TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (SERVER_ID, VERSION),
    CONSTRAINT FK_FMH_SERVER FOREIGN KEY (SERVER_ID) REFERENCES DIM_SERVER (SERVER_ID) DISABLE,
    CONSTRAINT FK_FMH_DATE   FOREIGN KEY (DATE_KEY)   REFERENCES DIM_DATE (DATE_KEY) DISABLE,
    DISTRIBUTE BY SERVER_ID
);

-- One row per server per day - the precomputed rollup. This is the only
-- table dashboards should query directly; everything upstream is for the
-- scoring job and drill-through.
CREATE TABLE IF NOT EXISTS FACT_TRUST_SCORE (
    SERVER_ID                VARCHAR(36)   NOT NULL,
    DATE_KEY                  DECIMAL(8,0)  NOT NULL,
    SECURITY_SCORE             DECIMAL(5,2),
    OPERATIONAL_SCORE           DECIMAL(5,2),
    OVERALL_SCORE                DECIMAL(5,2),
    STATIC_PENALTY                DECIMAL(6,2),   -- raw weighted-severity penalty before clipping - kept for "why did this drop" debugging
    RUNTIME_VIOLATION_COUNT        DECIMAL(10,0),
    RUNTIME_EXFIL_FLAG_COUNT        DECIMAL(10,0),
    SUCCESS_RATE                     DECIMAL(6,4),
    P95_LATENCY_MS                    DECIMAL(10,0),
    TOTAL_CALLS_IN_WINDOW               DECIMAL(10,0),
    COMPUTED_AT                          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (SERVER_ID, DATE_KEY),
    CONSTRAINT FK_FTS_SERVER FOREIGN KEY (SERVER_ID) REFERENCES DIM_SERVER (SERVER_ID) DISABLE,
    CONSTRAINT FK_FTS_DATE   FOREIGN KEY (DATE_KEY)  REFERENCES DIM_DATE (DATE_KEY) DISABLE,
    DISTRIBUTE BY SERVER_ID
);


-- ETL bookkeeping (not a dimension/fact - tracks incremental sync watermarks)

CREATE TABLE IF NOT EXISTS ETL_SYNC_STATE (
    SYNC_KEY        VARCHAR(50) NOT NULL,   -- e.g. "fact_static_findings"
    LAST_SYNCED_AT  TIMESTAMP   NOT NULL,
    PRIMARY KEY (SYNC_KEY)
);

-- Staging table for the per-scan sync job (sync.py).
--
-- pyexasol's import_from_iterable can't reliably target a subset of a
-- table's columns, which is a problem when the target has an IDENTITY
-- column (FINDING_KEY) and a DEFAULT column (LOADED_AT) that shouldn't be
-- supplied by the caller. So: bulk-load the exact columns we have into this
-- plain staging table, then INSERT ... SELECT into the real fact table
-- (where IDENTITY/DEFAULT populate correctly), then truncate staging.
-- Same columns as FACT_STATIC_FINDINGS, minus FINDING_KEY and LOADED_AT.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS STG_STATIC_FINDINGS (
    SOURCE_TABLE  VARCHAR(30),
    SOURCE_ID     DECIMAL(18,0),
    SCAN_RUN_ID   VARCHAR(36),
    SERVER_ID     VARCHAR(36),
    TOOL_KEY      INT,
    ANALYZER_KEY  INT,
    DATE_KEY      DECIMAL(8,0),
    PHASE         VARCHAR(10),
    SEVERITY      VARCHAR(20),
    REACHABLE     BOOLEAN,
    MESSAGE       VARCHAR(2000),
    DETAILS       VARCHAR(2000000)
);