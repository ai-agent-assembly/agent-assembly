-- Cross-database smoke migration used by storage::migrations tests.
-- Valid syntax on both SQLite and PostgreSQL.
CREATE TABLE IF NOT EXISTS migration_test_marker (
    id INTEGER PRIMARY KEY
);
