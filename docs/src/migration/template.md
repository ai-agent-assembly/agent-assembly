# Migration Guide — [FILL IN: brief title, e.g. "`AgentId.agent_id` renamed to `AgentId.id`"]

> **Template instructions:** Copy this file to `docs/migration/<vX.Y-to-vZ.0>.md`,
> fill in every `[FILL IN]` section, and delete these instruction lines.
> See the completed worked example in [`docs/versioning.md`](../versioning.md)
> for a reference of what a finished guide looks like.

---

**Breaking change introduced in:** `protocol/v[FILL IN]`
**Deprecated since:** `protocol/v[FILL IN]` *(omit if not previously deprecated)*
**Affected SDK versions:** [FILL IN: e.g. "All SDKs using `MessageName.field_name`"]
**Estimated migration effort:** [FILL IN: Low / Medium / High]

> **Low** — mechanical find-and-replace, no logic change.
> **Medium** — logic changes in a small number of call sites.
> **High** — widespread changes or dependent schema updates required.

---

## What changed

[FILL IN: One or two paragraphs describing what was removed, renamed, or altered and why.
Include the field number, message name, and proto file. Explain the motivation briefly —
e.g. naming consistency, type safety, protocol simplification.]

---

## Before (`protocol/v[FILL IN].x`)

**Proto encoding:**

```protobuf
[FILL IN: show the relevant message with the old field]
MessageName {
  field_name: "example-value"   // field N — old name/type
}
```

**Python SDK:**

```python
[FILL IN: show the old API call]
obj = MessageName(field_name="example-value")
```

**Node.js SDK:**

```typescript
[FILL IN: show the old API call]
const obj = new MessageName({ fieldName: 'example-value' });
```

**Go SDK:**

```go
[FILL IN: show the old API call]
obj := &pb.MessageName{FieldName: "example-value"}
```

---

## After (`protocol/v[FILL IN].0+`)

**Proto encoding:**

```protobuf
[FILL IN: show the relevant message with the new field]
MessageName {
  new_field_name: "example-value"   // field M — new name/type
}
```

**Python SDK:**

```python
[FILL IN: show the new API call]
obj = MessageName(new_field_name="example-value")
```

**Node.js SDK:**

```typescript
[FILL IN: show the new API call]
const obj = new MessageName({ newFieldName: 'example-value' });
```

**Go SDK:**

```go
[FILL IN: show the new API call]
obj := &pb.MessageName{NewFieldName: "example-value"}
```

---

## Migration steps

1. [FILL IN: First step — e.g. "Search your codebase for all usages of `MessageName.field_name`."]
2. [FILL IN: Second step — e.g. "Replace each with `MessageName.new_field_name`."]
3. [FILL IN: Third step — e.g. "Run the conformance test suite to verify."]
4. [FILL IN: Deployment order step if relevant — e.g. "Deploy the updated SDK before
   upgrading `aa-runtime` past vN.x (runtime vN.x still supports protocol/v(N-1))."]

---

## Verification

Run the conformance suite against a runtime at `protocol/v[FILL IN]`:

```bash
[FILL IN: exact command, e.g.]
cargo test -p conformance
python conformance/runner/runner.py --verbose
```

Expected: all vectors pass with no failures referencing `[FILL IN: old field name]`.

---

## See also

- [`docs/versioning.md`](../versioning.md) — change classification rules and deprecation
  lifecycle
- [`docs/protocol/CHANGELOG.md`](../protocol/CHANGELOG.md) — full protocol changelog
- [`conformance/vectors/`](../../../conformance/vectors/) — test vectors for the affected
  message category
