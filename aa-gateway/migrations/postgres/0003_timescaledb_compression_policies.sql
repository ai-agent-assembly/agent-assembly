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
    -- `undefined_function`     → plain PostgreSQL (no add_compression_policy)
    -- `feature_not_supported`  → table is not a TimescaleDB hypertable
    -- `undefined_parameter`    → TimescaleDB present but ALTER TABLE rejected
    --                            the timescaledb.compress storage parameter
    -- `undefined_object`       → either table missing in this database
    WHEN undefined_function
      OR feature_not_supported
      OR undefined_parameter
      OR undefined_object THEN
        RAISE NOTICE 'Skipping columnstore + compression policy setup: %', SQLERRM;
END $$;
