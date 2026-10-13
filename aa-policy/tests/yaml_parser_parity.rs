//! AAASM-6335 — golden corpus pinning how the policy YAML parser interprets
//! documents.
//!
//! This file pins the **pre-swap** semantics, recorded against `serde_yaml`
//! 0.9.34, before RUSTSEC-2024-0449 forced the move to the `serde_norway` fork.
//! Policy YAML is the security boundary: a parser that reads `yes` as a boolean,
//! expands a merge key, or tolerates a duplicate key would change what an
//! operator's policy *means* without any source diff. Replacing (or upgrading)
//! the YAML crate must therefore leave every expectation below untouched; if one
//! has to change, that is a finding to review, not an expectation to edit.
//!
//! Two entry points own YAML policy parsing and both are exercised:
//! `aa_policy::PolicyValidator::from_yaml` (gateway/REST) and
//! `aa_security::policy::PolicyDocument::from_yaml` (cross-layer canonical AST).
//! Where their verdicts on the same input differ, the difference is pinned as it
//! is. (The empty-document disagreement was closed by AAASM-6337.)
//!
//! Every acceptance is paired with a rejection that differs in one respect, so
//! a parser that accepts or rejects everything cannot satisfy the corpus.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use aa_policy::PolicyValidator;
use aa_security::policy::PolicyDocument;

/// Expected verdict of one entry point for one input.
#[derive(Debug, Clone, Copy)]
enum Expect {
    Ok,
    /// Rejected; the rendered error must contain this substring.
    Err(&'static str),
}

struct Case {
    name: &'static str,
    yaml: &'static str,
    /// `aa_security::policy::PolicyDocument::from_yaml`
    sec: Expect,
    /// `aa_policy::PolicyValidator::from_yaml`
    pol: Expect,
}

fn run_sec(yaml: &str) -> Result<PolicyDocument, String> {
    PolicyDocument::from_yaml(yaml).map_err(|e| e.to_string())
}

fn run_pol(yaml: &str) -> Result<aa_policy::PolicyValidatorOutput, String> {
    PolicyValidator::from_yaml(yaml).map_err(|errs| {
        errs.iter()
            .map(|e| format!("{}: {} (line {:?})", e.field, e.message, e.line))
            .collect::<Vec<_>>()
            .join(" | ")
    })
}

fn check(case: &Case, entry: &str, expect: Expect, got: Result<(), String>) {
    match (expect, got) {
        (Expect::Ok, Ok(())) => {}
        (Expect::Err(want), Err(msg)) if msg.contains(want) => {}
        (expect, got) => panic!("[{}] {entry}: expected {expect:?}, got {got:?}", case.name),
    }
}

#[test]
fn golden_corpus_verdicts() {
    // Shorthand: both accept / both reject with the same substring.
    const OK: Expect = Expect::Ok;
    let cases = [
        // ── envelope vs flat ────────────────────────────────────────────────
        Case {
            name: "flat form accepted",
            yaml: "capabilities:\n  deny: [terminal_exec]\n",
            sec: OK,
            pol: OK,
        },
        Case {
            name: "envelope form accepted",
            yaml: "apiVersion: agent-assembly/v1\nkind: Policy\nmetadata:\n  name: x\nspec:\n  capabilities:\n    deny: [terminal_exec]\n",
            sec: OK,
            pol: OK,
        },
        Case {
            name: "envelope metadata without any enforcement section rejected",
            yaml: "apiVersion: agent-assembly/v1\nkind: Policy\nmetadata:\n  name: x\n",
            sec: Expect::Err("no enforcement section"),
            pol: Expect::Err("unknown top-level key 'kind'"),
        },
        // ── anchors, aliases, merge keys ────────────────────────────────────
        Case {
            name: "alias reusing an anchor inside a known section accepted",
            yaml: "capabilities:\n  deny: &d [terminal_exec]\n  allow: *d\n",
            sec: OK,
            pol: OK,
        },
        Case {
            name: "anchor parked under an invented top-level key rejected",
            yaml: "x-d: &d [terminal_exec]\ncapabilities:\n  deny: *d\n",
            sec: Expect::Err("unknown policy key \"x-d\""),
            pol: Expect::Err("unknown top-level key 'x-d'"),
        },
        Case {
            name: "merge key is NOT expanded; it is an unknown key",
            yaml: "capabilities:\n  <<: {deny: [terminal_exec]}\n",
            sec: Expect::Err("unknown policy key \"<<\""),
            pol: Expect::Err("unknown key '<<'"),
        },
        Case {
            name: "merge key via alias is not expanded either",
            yaml: "base: &b {deny: [terminal_exec]}\ncapabilities:\n  <<: *b\n",
            sec: Expect::Err("unknown policy key \"base\""),
            pol: Expect::Err("unknown top-level key 'base'"),
        },
        // ── custom tags ─────────────────────────────────────────────────────
        // The two entry points disagree here: the canonical AST (untagged-enum
        // path) refuses a tagged node, the gateway validator ignores the tag.
        Case {
            name: "custom tag on a sequence",
            yaml: "capabilities:\n  deny: !foo [terminal_exec]\n",
            sec: Expect::Err("do not support enum input"),
            pol: OK,
        },
        Case {
            name: "custom tag on a scalar element",
            yaml: "capabilities:\n  deny: [!foo terminal_exec]\n",
            sec: Expect::Err("do not support enum input"),
            pol: OK,
        },
        // ── duplicate keys ──────────────────────────────────────────────────
        Case {
            name: "duplicate key rejected",
            yaml: "capabilities:\n  deny: [terminal_exec]\n  deny: [file_write]\n",
            sec: Expect::Err("duplicate entry with key \"deny\" at line 2 column 3"),
            pol: Expect::Err("duplicate field `deny` at line 2 column 3"),
        },
        Case {
            name: "distinct keys in the same section accepted",
            yaml: "capabilities:\n  deny: [terminal_exec]\n  allow: [file_read]\n",
            sec: OK,
            pol: OK,
        },
        // ── YAML 1.1 boolean spellings are strings, not booleans ────────────
        Case {
            name: "true is a boolean",
            yaml: "tools:\n  t:\n    allow: true\n",
            sec: OK,
            pol: OK,
        },
        Case {
            name: "True is a boolean",
            yaml: "tools:\n  t:\n    allow: True\n",
            sec: OK,
            pol: OK,
        },
        Case {
            name: "yes is NOT a boolean",
            yaml: "tools:\n  t:\n    allow: yes\n",
            sec: Expect::Err("invalid type: string \"yes\", expected a boolean"),
            pol: Expect::Err("invalid type: string \"yes\", expected a boolean at line 3 column 12"),
        },
        Case {
            name: "on is NOT a boolean",
            yaml: "tools:\n  t:\n    allow: on\n",
            sec: Expect::Err("invalid type: string \"on\", expected a boolean"),
            pol: Expect::Err("invalid type: string \"on\", expected a boolean"),
        },
        Case {
            name: "y is NOT a boolean",
            yaml: "tools:\n  t:\n    allow: y\n",
            sec: Expect::Err("invalid type: string \"y\", expected a boolean"),
            pol: Expect::Err("invalid type: string \"y\", expected a boolean"),
        },
        Case {
            name: "no is NOT a boolean",
            yaml: "tools:\n  t:\n    allow: no\n",
            sec: Expect::Err("invalid type: string \"no\", expected a boolean"),
            pol: Expect::Err("invalid type: string \"no\", expected a boolean"),
        },
        Case {
            name: "off is NOT a boolean",
            yaml: "tools:\n  t:\n    allow: off\n",
            sec: Expect::Err("invalid type: string \"off\", expected a boolean"),
            pol: Expect::Err("invalid type: string \"off\", expected a boolean"),
        },
        Case {
            name: "n is NOT a boolean",
            yaml: "tools:\n  t:\n    allow: n\n",
            sec: Expect::Err("invalid type: string \"n\", expected a boolean"),
            pol: Expect::Err("invalid type: string \"n\", expected a boolean"),
        },
        // ── null spellings ──────────────────────────────────────────────────
        Case {
            name: "tilde and null nodes are accepted as absent values",
            yaml: "tools:\n  t:\n    allow: ~\n",
            sec: OK,
            pol: OK,
        },
        Case {
            name: "explicit null node accepted",
            yaml: "tools:\n  t:\n    allow: null\n",
            sec: OK,
            pol: OK,
        },
        // ── empty / null / scalar / sequence documents (AAASM-3997) ─────────
        // AAASM-6337 deliberately flipped the three blank-document `pol` rows
        // below from OK to Err: the validator used to turn them into a fully
        // permissive policy while `aa_security` rejected them. Both entry
        // points now agree.
        Case {
            name: "empty document",
            yaml: "",
            sec: Expect::Err("empty or null policy document"),
            pol: Expect::Err("empty or null policy document"),
        },
        Case {
            name: "empty mapping",
            yaml: "{}",
            sec: Expect::Err("empty or null policy document"),
            pol: Expect::Err("empty or null policy document"),
        },
        Case {
            name: "comment-only document",
            yaml: "# only a comment\n",
            sec: Expect::Err("empty or null policy document"),
            pol: Expect::Err("empty or null policy document"),
        },
        Case {
            name: "null document",
            yaml: "null",
            sec: Expect::Err("empty or null policy document"),
            pol: Expect::Err("invalid type: unit value, expected struct RawPolicyDocument"),
        },
        Case {
            name: "tilde document",
            yaml: "~",
            sec: Expect::Err("empty or null policy document"),
            pol: Expect::Err("invalid type: unit value, expected struct RawPolicyDocument"),
        },
        Case {
            name: "scalar document",
            yaml: "hello",
            sec: Expect::Err("invalid type: string \"hello\", expected struct Envelope"),
            pol: Expect::Err("invalid type: string \"hello\", expected struct RawPolicyDocument"),
        },
        Case {
            name: "sequence document",
            yaml: "- a\n- b\n",
            sec: Expect::Err("invalid type: sequence, expected struct Envelope"),
            pol: Expect::Err("invalid type: sequence, expected struct RawPolicyDocument"),
        },
        // ── misspelled security keys (AAASM-3874 / 4330 / 5751) ─────────────
        Case {
            name: "capabilities.dney rejected",
            yaml: "capabilities:\n  dney: [terminal_exec]\n",
            sec: Expect::Err("unknown policy key \"dney\" under capabilities"),
            pol: Expect::Err("unknown key 'dney' in the 'capabilities' policy section"),
        },
        Case {
            name: "top-level capabilties rejected",
            yaml: "capabilties:\n  deny: [terminal_exec]\n",
            sec: Expect::Err("unknown policy key \"capabilties\" under (root)"),
            pol: Expect::Err("unknown top-level key 'capabilties'"),
        },
        Case {
            name: "network.allow_list rejected",
            yaml: "network:\n  allow_list: [a.com]\n",
            sec: Expect::Err("unknown policy key \"allow_list\" under network"),
            pol: Expect::Err("unknown key 'allow_list' in the 'network' policy section"),
        },
        Case {
            name: "network.allowlist accepted",
            yaml: "network:\n  allowlist: [a.com]\n",
            sec: OK,
            pol: OK,
        },
        Case {
            name: "filesystem.wrtie rejected",
            yaml: "filesystem:\n  wrtie:\n    allow: [/tmp]\n",
            sec: Expect::Err("unknown policy key \"wrtie\" under filesystem"),
            pol: Expect::Err("unknown key 'wrtie' in the 'filesystem' policy section"),
        },
        Case {
            name: "misspelled key inside spec rejected",
            yaml: "spec:\n  capabilties:\n    deny: [terminal_exec]\n",
            sec: Expect::Err("unknown policy key \"capabilties\" under spec"),
            pol: Expect::Err("unknown top-level key 'capabilties'"),
        },
        Case {
            name: "tools.<name>.alow rejected",
            yaml: "tools:\n  t:\n    alow: true\n",
            sec: Expect::Err("unknown policy key \"alow\" under tools.t"),
            pol: Expect::Err("unknown key 'alow' in the 'tools.t' policy section"),
        },
        // ── multi-document streams ──────────────────────────────────────────
        Case {
            name: "two documents rejected",
            yaml: "capabilities:\n  deny: [terminal_exec]\n---\ncapabilities:\n  deny: [file_write]\n",
            sec: Expect::Err("more than one document is not supported"),
            pol: Expect::Err("more than one document is not supported"),
        },
        Case {
            name: "empty first document then a real one rejected",
            yaml: "---\n---\ncapabilities:\n  deny: [terminal_exec]\n",
            sec: Expect::Err("more than one document is not supported"),
            pol: Expect::Err("more than one document is not supported"),
        },
        // ── encoding / line endings ─────────────────────────────────────────
        Case {
            name: "CRLF line endings accepted",
            yaml: "capabilities:\r\n  deny: [terminal_exec]\r\n",
            sec: OK,
            pol: OK,
        },
        Case {
            name: "leading UTF-8 BOM accepted",
            yaml: "\u{feff}capabilities:\n  deny: [terminal_exec]\n",
            sec: OK,
            pol: OK,
        },
        Case {
            name: "non-ASCII allowlist entry accepted",
            yaml: "network:\n  allowlist: [\"例え.jp\"]\n",
            sec: OK,
            pol: OK,
        },
        Case {
            name: "tab indentation rejected with position",
            yaml: "capabilities:\n\tdeny: [terminal_exec]\n",
            sec: Expect::Err("found character that cannot start any token at line 2 column 1"),
            pol: Expect::Err("found character that cannot start any token at line 2 column 1"),
        },
        Case {
            name: "bad indentation rejected with position",
            yaml: "capabilities:\n  deny: [terminal_exec]\n bad: 1\n",
            sec: Expect::Err("did not find expected key at line 3 column 2"),
            pol: Expect::Err("did not find expected key at line 3 column 2"),
        },
        Case {
            name: "unterminated flow sequence rejected with both positions",
            yaml: "capabilities:\n  deny: [terminal_exec\n",
            sec: Expect::Err("while parsing a flow sequence at line 2 column 9"),
            pol: Expect::Err("while parsing a flow sequence at line 2 column 9"),
        },
        // ── numeric forms where a string is expected ────────────────────────
        // Probes how a scalar is *resolved* before typing: 0x/0o ints become
        // integers (hence a type error for a string field), `1_000` stays text.
        Case {
            name: "numeric-looking allowlist entries",
            yaml: "network:\n  allowlist: [1_000, 0x1F, 0o17]\n",
            sec: Expect::Err("invalid type: integer `31`, expected a string"),
            pol: OK,
        },
        Case {
            name: "float-looking allowlist entries",
            yaml: "network:\n  allowlist: [.inf, .nan, 'a']\n",
            sec: Expect::Err("invalid type: floating point `inf`, expected a string"),
            pol: OK,
        },
        Case {
            name: "quoted allowlist entries stay strings",
            yaml: "network:\n  allowlist: ['1_000', '0x1F', '.inf']\n",
            sec: OK,
            pol: OK,
        },
        // ── numeric forms where a float is expected (aa-policy budget) ──────
        Case {
            name: "budget 1_000 is text, not a number",
            yaml: "budget:\n  daily_limit_usd: 1_000\n",
            sec: Expect::Err("no enforcement section"),
            pol: Expect::Err("invalid type: string \"1_000\", expected f64 at line 2 column 20"),
        },
        Case {
            name: "budget 0x1F is an integer, not an f64",
            yaml: "budget:\n  daily_limit_usd: 0x1F\n",
            sec: Expect::Err("no enforcement section"),
            pol: Expect::Err("invalid type: integer `31`, expected f64"),
        },
        Case {
            name: "budget 0o17 is an integer, not an f64",
            yaml: "budget:\n  daily_limit_usd: 0o17\n",
            sec: Expect::Err("no enforcement section"),
            pol: Expect::Err("invalid type: integer `15`, expected f64"),
        },
        Case {
            name: "budget .inf rejected as non-finite (AAASM-6336, was accepted)",
            yaml: "budget:\n  daily_limit_usd: .inf\n",
            sec: Expect::Err("no enforcement section"),
            pol: Expect::Err("budget.daily_limit_usd: must be a finite number"),
        },
        Case {
            name: "budget .nan rejected as non-finite (AAASM-6336, was accepted)",
            yaml: "budget:\n  daily_limit_usd: .nan\n",
            sec: Expect::Err("no enforcement section"),
            pol: Expect::Err("budget.daily_limit_usd: must be a finite number"),
        },
        Case {
            name: "budget u64::MAX accepted",
            yaml: "budget:\n  daily_limit_usd: 18446744073709551615\n",
            sec: Expect::Err("no enforcement section"),
            pol: OK,
        },
        Case {
            name: "budget beyond u128 accepted as float",
            yaml: "budget:\n  daily_limit_usd: 340282366920938463463374607431768211456\n",
            sec: Expect::Err("no enforcement section"),
            pol: OK,
        },
        Case {
            name: "budget negative rejected by validation",
            yaml: "budget:\n  daily_limit_usd: -5\n",
            sec: Expect::Err("no enforcement section"),
            pol: Expect::Err("budget.daily_limit_usd: must be greater than 0"),
        },
        Case {
            name: "budget quoted number is a string, rejected",
            yaml: "budget:\n  daily_limit_usd: \"5\"\n",
            sec: Expect::Err("no enforcement section"),
            pol: Expect::Err("invalid type: string \"5\", expected f64"),
        },
    ];

    for case in &cases {
        check(
            case,
            "PolicyDocument::from_yaml",
            case.sec,
            run_sec(case.yaml).map(|_| ()),
        );
        check(
            case,
            "PolicyValidator::from_yaml",
            case.pol,
            run_pol(case.yaml).map(|_| ()),
        );
    }
}

/// Typed results, not just verdicts: what the parser *produced* must not drift.
#[test]
fn golden_corpus_typed_results() {
    // Envelope and flat forms produce the same canonical policy; only the
    // `metadata.name` the envelope carries differs.
    let flat = run_sec("capabilities:\n  deny: [terminal_exec]\n").unwrap();
    let env = run_sec(
        "apiVersion: agent-assembly/v1\nkind: Policy\nmetadata:\n  name: x\nspec:\n  capabilities:\n    deny: [terminal_exec]\n",
    )
    .unwrap();
    assert_eq!(flat.name, None);
    assert_eq!(env.name.as_deref(), Some("x"));
    assert_eq!(flat.capabilities, env.capabilities);
    let denied: Vec<String> = env.denied_capabilities().iter().map(|c| c.to_string()).collect();
    assert_eq!(denied, ["terminal_exec"]);

    // Non-ASCII survives byte-for-byte, with and without a BOM / CRLF.
    let uni = run_sec("metadata:\n  name: \"策略-é\"\ncapabilities:\n  deny: [terminal_exec]\n").unwrap();
    assert_eq!(uni.name.as_deref(), Some("策略-é"));
    let net = run_sec("network:\n  allowlist: [\"例え.jp\"]\n").unwrap();
    assert_eq!(net.egress_allowlist(), ["例え.jp"]);
    let crlf = run_sec("capabilities:\r\n  deny: [terminal_exec]\r\n").unwrap();
    let bom = run_sec("\u{feff}capabilities:\n  deny: [terminal_exec]\n").unwrap();
    assert_eq!(crlf.capabilities, flat.capabilities);
    assert_eq!(bom.capabilities, flat.capabilities);

    // Quoted look-alikes stay text.
    let quoted = run_sec("network:\n  allowlist: ['1_000', '0x1F', '.inf']\n").unwrap();
    assert_eq!(quoted.egress_allowlist(), ["1_000", "0x1F", ".inf"]);
    let pol_net = run_pol("network:\n  allowlist: [1_000, 0x1F, 0o17]\n").unwrap();
    assert_eq!(pol_net.document.network.unwrap().allowlist, ["1_000", "0x1F", "0o17"]);

    // `allow: ~` / `allow: null` is "absent", which a tool rule reads as deny.
    for yaml in ["tools:\n  t:\n    allow: ~\n", "tools:\n  t:\n    allow: null\n"] {
        let rule = &run_sec(yaml).unwrap().tools[0];
        assert!(!rule.allow, "null tool.allow must default to deny: {yaml:?}");
    }
    let allowed = run_sec("tools:\n  t:\n    allow: True\n").unwrap();
    assert!(allowed.tools[0].allow);

    // Anchor/alias: both lists are populated from the one anchored node.
    let aliased = run_sec("capabilities:\n  deny: &d [terminal_exec]\n  allow: *d\n").unwrap();
    let caps = aliased.capabilities.unwrap();
    assert_eq!(caps.allow, caps.deny);
    assert_eq!(caps.deny.len(), 1);

    // Numeric edge values the f64 field receives.
    let budget = |v: &str| {
        run_pol(&format!("budget:\n  daily_limit_usd: {v}\n"))
            .unwrap()
            .document
            .budget
            .unwrap()
            .daily_limit_usd
            .unwrap()
    };
    // AAASM-6336 flipped `.inf` / `.nan` from accepted to rejected (they still
    // *parse* as f64; the validator now refuses them), so they are no longer
    // observable through an accepted document.
    for non_finite in [".inf", ".nan"] {
        assert!(run_pol(&format!("budget:\n  daily_limit_usd: {non_finite}\n")).is_err());
    }
    assert_eq!(budget("18446744073709551615"), u64::MAX as f64);
    assert_eq!(budget("340282366920938463463374607431768211456"), 2f64.powi(128));
    assert_eq!(budget("12.5"), 12.5);
}

/// Error positions are part of the operator contract (`ValidationError::line`).
#[test]
fn error_positions_are_reported() {
    let errs = PolicyValidator::from_yaml("tools:\n  t:\n    allow: yes\n").unwrap_err();
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].field, "(document)");
    assert_eq!(errs[0].line, Some(3));
    assert!(errs[0].message.starts_with("YAML parse error: "));

    let errs =
        PolicyValidator::from_yaml("capabilities:\n  deny: [terminal_exec]\n  deny: [file_write]\n").unwrap_err();
    assert_eq!(errs[0].line, Some(2));

    // Multi-document errors carry no location.
    let errs = PolicyValidator::from_yaml("a: 1\n---\nb: 2\n").unwrap_err();
    assert_eq!(errs[0].line, None);

    // Validation (post-parse) errors are not positional.
    let errs = PolicyValidator::from_yaml("budget:\n  daily_limit_usd: -5\n").unwrap_err();
    assert_eq!(errs[0].line, None);

    // A clean document yields no error to position.
    assert!(PolicyValidator::from_yaml("budget:\n  daily_limit_usd: 5\n").is_ok());
}

/// Scalar resolution, observed directly on the generic value tree: this is the
/// layer that decides `yes`/`0o17`/`1_000` before any policy type sees them.
#[test]
fn scalar_resolution_on_generic_value() {
    use serde_yaml::Value;
    let parse = |s: &str| serde_yaml::from_str::<Value>(s).unwrap();

    for text in ["yes", "no", "on", "off", "y", "n", "Yes", "NO", "1_000", "+.inf2"] {
        assert_eq!(parse(text), Value::String(text.into()), "{text:?} must stay a string");
    }
    for (text, want) in [
        ("true", true),
        ("True", true),
        ("TRUE", true),
        ("false", false),
        ("False", false),
    ] {
        assert_eq!(parse(text), Value::Bool(want), "{text:?}");
    }
    for text in ["~", "null", "Null", "NULL", ""] {
        assert_eq!(parse(text), Value::Null, "{text:?}");
    }
    assert_eq!(parse("0o17").as_u64(), Some(15));
    assert_eq!(parse("0x1F").as_u64(), Some(31));
    assert_eq!(parse("0b11").as_u64(), Some(3));
    assert_eq!(
        parse("017"),
        Value::String("017".into()),
        "leading zero is neither octal nor decimal"
    );
    assert_eq!(parse("-0x1F").as_i64(), Some(-31));
    assert_eq!(parse("18446744073709551615").as_u64(), Some(u64::MAX));
    assert_eq!(parse("-9223372036854775808").as_i64(), Some(i64::MIN));
    assert!(parse(".inf").as_f64().unwrap().is_infinite());
    assert!(parse("-.inf").as_f64().unwrap().is_sign_negative());
    assert!(parse(".NaN").as_f64().unwrap().is_nan());

    // Integers above u64 that still fit a u128 cannot become a generic Value (the
    // tree has no 128-bit number): they error rather than wrap. One past u128
    // falls back to a float. Typed f64 fields accept both (see the budget
    // cases), because serde hands the f64 visitor the value directly. Pinned
    // as-is: the generic-tree and typed paths disagree today.
    for text in ["18446744073709551616", "340282366920938463463374607431768211455"] {
        let err = serde_yaml::from_str::<Value>(text).unwrap_err().to_string();
        assert!(err.contains("as u128, expected any YAML value"), "{text}: {err}");
    }
    let past_u128 = parse("340282366920938463463374607431768211456");
    assert_eq!(past_u128.as_u64(), None);
    assert_eq!(past_u128.as_f64(), Some(2f64.powi(128)));

    // Quoting always yields text.
    assert_eq!(parse("'yes'"), Value::String("yes".into()));
    assert_eq!(parse("\"0x1F\""), Value::String("0x1F".into()));

    // Tags are preserved rather than dropped or rejected.
    assert!(matches!(parse("!foo bar"), Value::Tagged(_)));

    // Merge keys are not expanded: `<<` stays an ordinary key.
    let merged = parse("a: &a {x: 1}\nb:\n  <<: *a\n");
    let b = merged.get("b").unwrap().as_mapping().unwrap();
    assert!(b.contains_key("<<"));
    assert!(!b.contains_key("x"));

    // Duplicate keys are an error on the generic tree too.
    let dup = serde_yaml::from_str::<Value>("a: 1\na: 2\n").unwrap_err();
    assert!(dup.to_string().contains("duplicate entry with key \"a\""), "{dup}");
    assert_eq!(
        dup.location().map(|l| (l.line(), l.column())),
        Some((1, 1)),
        "reported at the mapping start, not the second key"
    );

    // Multi-document input is refused for a single-value read.
    let multi = serde_yaml::from_str::<Value>("a: 1\n---\nb: 2\n").unwrap_err();
    assert!(multi.to_string().contains("more than one document"), "{multi}");
}

/// Hostile-input bounds: the parser must refuse or finish quickly, never hang or
/// exhaust memory, on input shapes an API caller can send.
#[test]
fn hostile_inputs_are_bounded() {
    const BUDGET: Duration = Duration::from_secs(10);

    // Alias bomb (billion laughs, 9 levels x 9 aliases).
    let mut bomb = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x]\n");
    for i in 1..9 {
        let prev = format!("*a{}", i - 1);
        let refs = vec![prev; 9].join(", ");
        bomb.push_str(&format!("a{i}: &a{i} [{refs}]\n"));
    }
    let start = Instant::now();
    let sec = run_sec(&bomb);
    let pol = run_pol(&bomb);
    assert!(start.elapsed() < BUDGET, "alias bomb took {:?}", start.elapsed());
    assert!(sec.is_err() && pol.is_err(), "alias bomb must be rejected");
    let msg = serde_yaml::from_str::<serde_yaml::Value>(&bomb)
        .unwrap_err()
        .to_string();
    assert!(msg.contains("repetition limit"), "{msg}");

    // 100k-deep nesting: refused, not a stack overflow.
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    let start = Instant::now();
    let err = serde_yaml::from_str::<serde_yaml::Value>(&deep)
        .unwrap_err()
        .to_string();
    assert!(start.elapsed() < BUDGET, "deep nesting took {:?}", start.elapsed());
    assert!(err.contains("recursion limit exceeded"), "{err}");
    assert!(run_sec(&deep).is_err() && run_pol(&deep).is_err());

    // A 10 MB scalar is parsed in bounded time (it is large, not malicious):
    // as a value inside a known field it is accepted as plain text.
    let big = "a".repeat(10 * 1024 * 1024);
    let yaml = format!("network:\n  allowlist: ['{big}']\n");
    let start = Instant::now();
    let doc = run_sec(&yaml).unwrap();
    assert!(start.elapsed() < BUDGET, "10 MB scalar took {:?}", start.elapsed());
    assert_eq!(doc.egress_allowlist()[0].len(), big.len());
}

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../policy-examples")
}

/// Every shipped example parses through BOTH entry points. The aa-security
/// crate already pins the canonical side; this adds the gateway validator.
#[test]
fn shipped_policy_examples_parse_through_both_entry_points() {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(examples_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let yaml = std::fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        run_sec(&yaml).unwrap_or_else(|e| panic!("{name}: canonical parse failed: {e}"));
        run_pol(&yaml).unwrap_or_else(|e| panic!("{name}: validator parse failed: {e}"));
        names.push(name);
    }
    names.sort();
    // Assert the SET, so deleting an example (or the directory emptying) is red.
    assert_eq!(
        names,
        [
            "audit-only.yaml",
            "balanced.yaml",
            "capability-policy.yaml",
            "file-delete-policy.yaml",
            "filesystem-scoped.yaml",
            "high-risk.yaml",
            "low-risk.yaml",
            "medium-risk.yaml",
            "strict.yaml",
        ]
    );

    // And a corrupted copy of a real example is refused: the corpus is not
    // passing because the parsers accept everything.
    let strict = std::fs::read_to_string(examples_dir().join("strict.yaml")).unwrap();
    let broken = strict.replacen("capabilities:", "capabilties:", 1);
    assert_ne!(broken, strict, "strict.yaml no longer contains `capabilities:`");
    assert!(run_sec(&broken).is_err());
    assert!(run_pol(&broken).is_err());
}

#[test]
fn strict_example_typed_result() {
    let yaml = std::fs::read_to_string(examples_dir().join("strict.yaml")).unwrap();
    let doc = run_sec(&yaml).unwrap();
    assert!(doc.egress_allowlist().contains(&"api.openai.com".to_string()));
    let denied: Vec<String> = doc.denied_capabilities().iter().map(|c| c.to_string()).collect();
    assert!(denied.contains(&"file_write".to_string()));
    assert!(denied.contains(&"terminal_exec".to_string()));
    assert!(doc.tools.iter().any(|t| t.name == "*" && !t.allow));
}
