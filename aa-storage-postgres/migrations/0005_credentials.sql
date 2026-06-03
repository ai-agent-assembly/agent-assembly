-- Credentials: named secret material stored as opaque ciphertext.
--
-- The CredentialStore contract takes opaque bytes ("backends are expected to
-- encrypt at rest"); this table holds them in a single `ciphertext` BYTEA
-- column. There is deliberately NO plaintext column.
CREATE TABLE credentials (
    key        TEXT PRIMARY KEY,
    ciphertext BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
