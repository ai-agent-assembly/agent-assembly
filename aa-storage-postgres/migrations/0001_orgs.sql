-- Organizations: the top-level tenant boundary an agent belongs to.
CREATE TABLE orgs (
    id         UUID PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
