-- AAASM-1890 BUGFIX — 0002 attaches `add_compression_policy()` directly
-- after `create_hypertable()` without first enabling columnstore
-- (TimescaleDB's term for the compressed storage mode). On TimescaleDB
-- 2.18+ that raises `columnstore not enabled on hypertable "audit_events"`
-- and aborts the migration outright (0002's EXCEPTION clause only catches
-- `undefined_function`, which is a different SQLSTATE).
--
-- This migration runs the missing `ALTER TABLE … SET (timescaledb.compress
-- = true)` step on each hypertable and (re-)attaches the policies with
-- `if_not_exists => TRUE` so it's safe to apply on databases where 0002
-- already partially landed (the `create_hypertable` half succeeded and is
-- captured by the sqlx tracking table).
--
-- A new migration file (not an in-place edit of 0002) is required: sqlx
-- records the original checksum of 0002 on every database that ran it —
-- even on plain PostgreSQL where the second DO block fell into its
-- exception handler. Mutating 0002 would surface `MigrationCheckChecksum`
-- failures on the next `migrate()`.

DO $$
BEGIN
    ALTER TABLE audit_events SET (timescaledb.compress = true);
    PERFORM add_compression_policy(
        'audit_events',
        INTERVAL '30 days',
        if_not_exists => TRUE
    );

    ALTER TABLE metrics SET (timescaledb.compress = true);
    PERFORM add_compression_policy(
        'metrics',
        INTERVAL '7 days',
        if_not_exists => TRUE
    );
EXCEPTION
    -- WHEN OTHERS — broad on purpose. The ALTER TABLE + add_compression_policy
    -- pair can fail on plain PostgreSQL with several different SQLSTATEs that
    -- are awkward to enumerate stably across PG versions, e.g.:
    --   * 22023 (invalid_parameter_value) — "unrecognized parameter namespace timescaledb"
    --   * 42883 (undefined_function)      — add_compression_policy doesn't exist
    --   * 0A000 (feature_not_supported)   — table isn't a hypertable
    -- On a TimescaleDB-enabled cluster the statements all succeed, so the
    -- catch-all only runs on plain-PG paths where graceful skip is intended.
    WHEN OTHERS THEN
        RAISE NOTICE 'Skipping columnstore + compression policy setup: %', SQLERRM;
END $$;
