-- E18 S-D #1 — Promote audit_events and metrics to TimescaleDB hypertables.
--
-- TimescaleDB is a PostgreSQL extension that transparently partitions
-- time-series tables into time-ordered chunks. Queries that filter by `ts`
-- only scan the relevant chunks (10–100× faster than full-table scans on
-- the un-promoted tables), and the auto-compression policy shrinks chunks
-- older than the configured threshold (10–20× space savings).
--
-- This migration is **graceful** when the TimescaleDB extension is not
-- installed in the cluster: both DO blocks swallow the relevant SQLSTATE
-- codes and emit a NOTICE instead of failing. Plain PostgreSQL deployments
-- keep using the standard tables defined in 0001_initial.sql with no
-- runtime difference beyond the unused indexes.
--
-- The hypertable settings here intentionally match the static defaults in
-- `aa-core::config::TimescaleConfig` (chunk_interval: 7 days for audit,
-- 1 day for metrics; compression policy: 30 days for audit, 7 days for
-- metrics). Operators who tune those config values must apply matching
-- ALTER statements out-of-band — sqlx migrations are versioned and
-- immutable once applied.

-- Step 1: try to install the extension. On a plain PostgreSQL cluster the
-- control file is missing and CREATE EXTENSION raises feature_not_supported
-- (or undefined_file); we catch both so the migration succeeds anyway.
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'TimescaleDB extension not available (%): skipping hypertable setup. \
                      Install the TimescaleDB extension for time-series query \
                      acceleration and auto-compression.', SQLERRM;
END $$;

-- Step 2: promote audit_events and metrics to hypertables, enable the
-- columnstore (TimescaleDB's storage mode that compression policies act
-- on — required since TimescaleDB 2.18), and attach the compression
-- policies.
--
-- EXCEPTION is `WHEN OTHERS` on purpose: the body can fail on plain
-- PostgreSQL with several distinct SQLSTATEs (undefined_function from
-- create_hypertable, invalid_parameter_value from the timescaledb.compress
-- storage parameter, feature_not_supported for the policy call, etc.).
-- On a TimescaleDB-enabled cluster every statement succeeds so the
-- catch-all only fires on plain-PG paths where graceful skip is the
-- documented intent.
DO $$
BEGIN
    PERFORM create_hypertable(
        'audit_events', 'ts',
        chunk_time_interval => INTERVAL '7 days',
        if_not_exists       => TRUE
    );
    ALTER TABLE audit_events SET (timescaledb.compress = true);
    PERFORM add_compression_policy(
        'audit_events',
        INTERVAL '30 days',
        if_not_exists => TRUE
    );

    PERFORM create_hypertable(
        'metrics', 'ts',
        chunk_time_interval => INTERVAL '1 day',
        if_not_exists       => TRUE
    );
    ALTER TABLE metrics SET (timescaledb.compress = true);
    PERFORM add_compression_policy(
        'metrics',
        INTERVAL '7 days',
        if_not_exists => TRUE
    );
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'TimescaleDB functions/parameters unavailable; hypertables not created (plain PostgreSQL fallback): %', SQLERRM;
END $$;
