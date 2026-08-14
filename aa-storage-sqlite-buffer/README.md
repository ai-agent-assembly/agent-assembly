# aa-storage-sqlite-buffer

Local in-process SQLite event buffer that survives brief gateway/queue outages and
flushes audit events on reconnect.

[![crates.io](https://img.shields.io/crates/v/aa-storage-sqlite-buffer?logo=rust&label=crates.io)](https://crates.io/crates/aa-storage-sqlite-buffer)
[![docs.rs](https://img.shields.io/docsrs/aa-storage-sqlite-buffer?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-storage-sqlite-buffer)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/LICENSE)

A single WAL-mode SQLite file that buffers governance `AuditEntry` records when the
upstream NATS/gateway is briefly unreachable, then flushes the backlog in insertion
order on reconnect. Buffered events survive a process restart, giving Assembly
partial autonomy so a transient outage never silently loses audit-trail data.

Part of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly) — [documentation](https://docs.agent-assembly.com/) · [monorepo](https://github.com/ai-agent-assembly/agent-assembly).
