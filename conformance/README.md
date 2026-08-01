# Agent Assembly Conformance Suite

Language-neutral JSON test vectors and multi-language runners that verify
SDK implementations against the reference Rust implementation.

## Directory layout

```
conformance/
├── src/lib.rs                  # Rust helpers: vector types, load_vectors(), load_golden_bin(), hex_decode()
├── src/bin/generate_golden.rs  # Generates conformance/vectors/proto/*.bin golden files
├── tests/
│   ├── ipc_framing.rs          # IPC framing (varint length-delimited encode/decode)
│   ├── message_serialization.rs # Proto message wire-format vs. golden .bin files
│   ├── policy_query.rs         # CheckActionRequest/Response decision invariants
│   ├── credential_detection.rs # CredentialScanner::scan() + ScanResult::redact()
│   └── session_lifecycle.rs    # Agent lifecycle message round-trips
├── vectors/
│   ├── ipc_framing/            # 10 vectors: basic, large-message, edge-cases
│   ├── message_serialization/  # 10 vectors: one per proto message golden
│   ├── proto/                  # *.bin golden files (prost encode_to_vec output)
│   ├── policy_query/           # 10 vectors: ALLOW, DENY, PENDING, REDACT decisions
│   ├── credential_detection/   # 34 vectors: API keys, auth tokens, DB URLs, PII, entropy
│   └── session_lifecycle/      # 10 vectors: Register, Heartbeat, Deregister, ControlCommand
└── runner/
    ├── requirements.txt        # Python runner dependencies (colorama)
    ├── runner.py               # Python SDK conformance runner
    ├── test_runner_redact.py   # Regression tests for the runner's own redaction logic
    └── check_redact_equivalence.py  # Differential sweep vs. the pre-AAASM-5371 redaction
```

## Test categories

### 1. IPC framing (`vectors/ipc_framing/`)

Verifies prost varint length-delimited framing used over Unix domain sockets:

- **encode**: prepend varint(len) to raw proto bytes
- **decode**: strip varint prefix, return inner bytes
- **edge cases**: empty payload, boundary lengths (127, 128, 300 bytes), split frames,
  consecutive frames, multi-message streams

Vector schema:
```json
{
  "description": "...",
  "message_type": "...",
  "input_hex": "<hex>",
  "expected_framed_hex": "<hex>"
}
```

### 2. Message serialisation (`vectors/message_serialization/` + `vectors/proto/`)

Compares prost `encode_to_vec()` output against pre-generated golden `.bin` files.
Golden files are produced by `cargo run -p conformance --bin generate_golden`.

Vector schema:
```json
{ "description": "...", "message_type": "...", "golden_file": "filename.bin" }
```

### 3. Policy query (`vectors/policy_query/`)

Checks decision-specific invariants on `CheckActionResponse`:
- ALLOW: `redact` null, `approval_id` empty
- DENY: `policy_rule` non-empty
- PENDING: `approval_id` non-empty
- REDACT: `redact.rules` array non-empty, each rule has `field_path` and `replacement`

### 4. Credential detection (`vectors/credential_detection/`)

Drives every vector against `CredentialScanner::scan()` and `ScanResult::redact()`.
Checks finding count, kind, byte offset, and full redacted output string.

Vector schema:
```json
{
  "description": "...",
  "input_text": "...",
  "expected_findings": [{ "kind": "AnthropicKey", "offset": 7 }],
  "expected_redacted": "key=[REDACTED:AnthropicKey]"
}
```

#### Offset unit — normative

`expected_findings[].offset` is a **byte offset into the UTF-8 encoding of
`input_text`**, counting from zero. So is the `end` an SDK reports alongside it.
This is not negotiable per language: it is the unit `CredentialScanner` emits,
and the vectors are the same bytes for every SDK.

It matters because each language's native string index means something different,
and for ASCII input all three units coincide — so a harness that picks the wrong
one still passes every ASCII vector and only breaks on the first multi-byte one:

| Language | Native string index | Correct against this schema? |
|---|---|---|
| Rust | bytes (`&str[a..b]`) | yes, directly |
| Go | bytes (`s[a:b]`) | yes, directly |
| Python | code points (`s[a:b]`) | **no** — encode to `bytes`, splice, decode back |
| Node/TS | UTF-16 code units (`s.slice(a, b)`) | **no** — splice a `Buffer`/`Uint8Array` instead |

An offset that does not fall on a character boundary is not redactable; reject it
rather than splicing, so no harness can emit invalid UTF-8 or a partial value.

Categories: API keys (Anthropic, OpenAI, AWS, GCP, Azure), auth tokens (GitHub,
Slack), database URLs (Postgres, MySQL, MongoDB), private keys (RSA, EC, OpenSSH,
PKCS8, PGP), PII (credit card, SSN, email), high-entropy tokens.

### 5. Session lifecycle (`vectors/session_lifecycle/`)

Round-trips each lifecycle message through prost encode/decode and verifies key
fields survive serialisation. Messages: `RegisterRequest`, `RegisterResponse`,
`HeartbeatRequest`, `HeartbeatResponse`, `DeregisterRequest`, `DeregisterResponse`,
and four `ControlCommand` variants (Suspend, Resume, PolicyUpdate, Kill).

## Running the Rust conformance suite

```bash
# Run all conformance tests
cargo test -p conformance

# Run a specific category
cargo test -p conformance --test credential_detection
cargo test -p conformance --test session_lifecycle
cargo test -p conformance --test ipc_framing
cargo test -p conformance --test message_serialization
cargo test -p conformance --test policy_query

# Regenerate golden .bin files
cargo run -p conformance --bin generate_golden
```

## Running the Python conformance runner

```bash
pip install -r conformance/runner/requirements.txt

# Run against an AA SDK implementation
export AA_SDK_MODULE=your_sdk.credential_scanner  # must expose scan(text) -> list[dict]
python conformance/runner/runner.py --verbose

# Run in CI (exits 0 on pass, 1 on any failure)
python conformance/runner/runner.py
```

The `scan()` function must return a list of dicts, each with:
- `"kind"` (str) — credential kind string matching `CredentialKind.as_str()`
- `"offset"` (int) — byte offset of the finding in the input text
- `"end"` (int) — byte end of the matched region (used for redaction)

Both positions are byte offsets into the UTF-8 encoding of the input, per
[Offset unit — normative](#offset-unit--normative). A Python SDK that reports
`str` indices will pass every ASCII vector and fail every non-ASCII one.

### Testing the runner itself

The runner reconstructs the redacted string from the spans an SDK reports, so it
can be wrong in exactly the same way an SDK can. Its own regression tests run
without an SDK and without any vector file:

```bash
python conformance/runner/test_runner_redact.py
```

Changing how spans are spliced is the change most likely to break the 26 ASCII
vectors without any of them failing, since a wrong unit still lands in the right
place on ASCII. The differential sweep drives the current implementation and the
pre-AAASM-5371 one over every span position in every ASCII vector and requires
byte-identical output:

```bash
python conformance/runner/check_redact_equivalence.py
python conformance/runner/check_redact_equivalence.py --self-check
```

`--self-check` sabotages the implementation by one character and asserts the
sweep notices — a differential harness that silently compares one thing to itself
reports zero mismatches forever and looks exactly like proof.

## Adding new vectors

1. Add a new `*.json` file to the appropriate `vectors/<category>/` directory.
2. Run `cargo test -p conformance --test <category>` to verify it passes.
3. For Python SDKs, run `python conformance/runner/runner.py` with your SDK.

Vector files are loaded in sorted filename order. Use a descriptive filename like
`api_keys_new_provider.json` or `pii_passport_number.json`.

## SDK conformance placeholders

CI jobs for Python, Node.js, and Go SDK conformance runners are defined in
`.github/workflows/ci.yml` and currently run as no-ops. Implement the SDK
shim and remove the `continue-on-error: true` flag to gate merges on
SDK conformance.
