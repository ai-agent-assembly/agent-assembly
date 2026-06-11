# Protocol versioning policy

Use this page to decide how a protocol change must be versioned before you ship it. It defines the versioning scheme, the rules for classifying a change as breaking or non-breaking, and the deprecation lifecycle. Every change to proto schemas, JSON schemas, IPC framing, and wire formats is governed by this policy.

The short version: **add fields and RPCs freely (MINOR); never remove, rename, or retype an existing field without a MAJOR bump and a migration guide.**

---

## Versioning scheme

The protocol uses **Semantic Versioning (MAJOR.MINOR.PATCH)**:

| Component | Meaning |
|---|---|
| `MAJOR` | Breaking change — existing SDKs must be updated to remain compatible |
| `MINOR` | Non-breaking addition — new fields, new RPCs, new enum values (backward compatible) |
| `PATCH` | Non-breaking fix — documentation corrections, description updates, no wire format change |

The current protocol version is **`protocol/v1`** (pre-stable: `v0.0.1`).

---

## Change classification

### Non-breaking changes (MINOR or PATCH)

These changes can be made without requiring SDK updates:

| Change | Classification | Reason |
|---|---|---|
| Add an optional field to a message | MINOR | Existing decoders ignore unknown fields (proto3) |
| Add a new RPC method to a service | MINOR | Existing clients simply don't call it |
| Add a new enum value | MINOR | Unknown enum values fall back to `_UNSPECIFIED = 0` |
| Add a new service | MINOR | Existing clients don't depend on it |
| Rename a field **description** (not the field itself) | PATCH | No wire format change |
| Fix a typo in a comment or doc string | PATCH | No wire format change |
| Tighten a JSON Schema description | PATCH | No wire format change |

### Breaking changes (MAJOR)

These changes require a MAJOR version bump and a migration guide:

| Change | Classification | Reason |
|---|---|---|
| Remove a field from a message | MAJOR | Existing encoders/decoders break |
| Rename a field | MAJOR | Field number stays but name change breaks JSON/gRPC-gateway |
| Change a field's type | MAJOR | Wire encoding changes |
| Change a field number | MAJOR | Proto3 wire encoding is field-number based |
| Remove an RPC method | MAJOR | Existing callers get `UNIMPLEMENTED` errors |
| Remove an enum value | MAJOR | Existing code holding that value breaks |
| Add a required field | MAJOR | Existing messages missing the field become invalid |
| Change a JSON Schema `type` constraint | MAJOR | Existing valid documents become invalid |
| Narrow a JSON Schema constraint (e.g. add `minLength`) | MAJOR | Previously valid values may now fail validation |

---

## Deprecation lifecycle

Before a breaking change is introduced, the affected field, method, or value must go through a formal deprecation period:

```
Deprecated in vX.Y  →  Removed no earlier than v(X+2).0
```

### Steps

1. **Deprecate** — Mark the item as deprecated in the proto or JSON Schema with a `deprecated` annotation and a description explaining what to use instead. Bump MINOR version.
2. **Announce** — Add an entry to `CHANGELOG.md` under `Deprecated`. Notify SDK maintainers.
3. **Support period** — The deprecated item remains fully functional for at least **two MAJOR versions** after the deprecating release.
4. **Remove** — Remove the item in a future MAJOR release (no earlier than `v(X+2).0`). Add a migration guide. Update `CHANGELOG.md` under `Removed`.

### Runtime backward compatibility

**Runtime N must support SDKs speaking protocol N-1.**

This means an `aa-runtime` at protocol `v2.x` must continue to accept connections from SDKs still using protocol `v1.x`. SDKs have a two-major-version window to migrate before a runtime drops support for the older protocol.

### Example: deprecating a field

```protobuf
// Before (v1.2 — field is still used)
message AgentId {
  string org_id   = 1;
  string team_id  = 2;
  string agent_id = 3;  // original field name
}

// After (v1.3 — field deprecated, replacement added)
message AgentId {
  string org_id   = 1;
  string team_id  = 2;
  string agent_id = 3 [deprecated = true];  // deprecated: use `id` instead (removed in v3.0)
  string id       = 4;  // replacement field
}
```

CHANGELOG entry at v1.3:
```
### Deprecated
- `AgentId.agent_id` — use `AgentId.id` instead. Will be removed in v3.0.
```

---

## Example migration guide — `AgentId.agent_id` → `AgentId.id`

**Breaking change introduced in:** protocol/v3.0  
**Deprecated since:** protocol/v1.3  
**Affected SDK versions:** All SDKs using `AgentId.agent_id`  
**Estimated migration effort:** Low

### What changed

The field `AgentId.agent_id` (field number 3) was removed. Use `AgentId.id` (field number 4) instead. The semantic meaning is identical — the field carries the agent's own identifier (DID).

### Before (protocol/v1.x — v2.x)

**Proto encoding:**
```protobuf
AgentId {
  org_id:   "acme"
  team_id:  "platform"
  agent_id: "did:key:z6Mk..."   // field 3
}
```

**Python SDK:**
```python
agent_id = AgentId(org_id="acme", team_id="platform", agent_id="did:key:z6Mk...")
```

### After (protocol/v3.0+)

**Proto encoding:**
```protobuf
AgentId {
  org_id:  "acme"
  team_id: "platform"
  id:      "did:key:z6Mk..."    // field 4
}
```

**Python SDK:**
```python
agent_id = AgentId(org_id="acme", team_id="platform", id="did:key:z6Mk...")
```

### Migration steps

1. Search your codebase for all usages of `AgentId.agent_id` (or the SDK-language equivalent).
2. Replace each with `AgentId.id`.
3. Run your SDK's conformance test suite against a `aa-runtime` at protocol/v3.0.
4. Deploy the updated SDK before upgrading `aa-runtime` past v2.x (runtime v2.x still supports protocol/v1 per the backward compatibility rule).

---

| Runtime protocol | Must support |
|---|---|
| protocol/v1 | protocol/v1 only (first version) |
| protocol/v2 | protocol/v1, protocol/v2 |
| protocol/v3 | protocol/v2, protocol/v3 (v1 support may be dropped) |

---

For the blank template to copy when writing a new migration guide, see [`docs/migration/template.md`](migration/template.md).
