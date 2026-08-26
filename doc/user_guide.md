# qubit-redact-derive User Guide

[README](../README.md) · [中文用户手册](user_guide.zh_CN.md) · [Runtime User Guide](https://github.com/qubit-ltd/rs-redact/blob/main/doc/user_guide.md)

This crate supplies the `#[derive(Redact)]` macro. The runtime owns policies,
budgets, and masks; the generated implementation only describes how a domain
value writes itself through a `RedactionWriter`.

## Installation

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["derive"] }
qubit-redact-derive = "0.5"
```

The generated code requires `qubit-redact` as a direct dependency. Cargo-renamed
dependencies are supported. Enable the runtime `serde` feature and add a direct
`serde` dependency when using `#[redact(serde)]`; enable `json` for
`#[redact(json)]`.

## Basic redaction

```rust
use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Login {
    account: String,
    #[redact(level = "secret")]
    password: String,
    #[redact(skip)]
    recovery_code: String,
}

let login = Login {
    account: "ada".into(),
    password: "raw-password".into(),
    recovery_code: "never-render".into(),
};
let output = Redactor::standard().redact(&login);
assert!(output.text().as_str().contains("ada"));
assert!(!output.text().as_str().contains("raw-password"));
assert!(!output.text().as_str().contains("never-render"));
assert_eq!(login.password, "raw-password");
```

The source value is borrowed and unchanged. With a custom policy, use
`Redactor::new(policy).redact(&value)`. The generated runtime implementation is
the single `Redact::write_redacted` method; there is no mutable redaction trait.

## Field modes

| Mode | Meaning |
| --- | --- |
| no attribute | Ordinary `Debug` formatting; no sensitivity inference. |
| `level = "low"`, `"medium"`, `"high"`, `"secret"` | Mask with the selected sensitivity. |
| `skip` | Omit the field. |
| `nested` | Delegate to the nested `Redact` implementation. |
| `map` | Apply key-aware policy to supported text-keyed maps. |
| `keyed_by = key` | Classify this field by a sibling text key, using the same policy semantics as one map entry. |
| `json` | Recursively redact supported JSON text values. |

The removed `plain`, `no_mut`, and `require_explicit` attributes are rejected.
Unmarked pass-through is intentional: sensitivity belongs to the downstream
business domain and cannot be inferred reliably from a field name or Rust type.
Ordinary fields are the large majority, so explicit "not sensitive" attributes
would create noise rather than classification knowledge. Downstream types must
annotate sensitive fields and review model changes. The macro supports named,
tuple, and unit structs and enum variants.

Capabilities are checked at compile time. `level` accepts supported scalar
leaves recursively through `Option`, `Vec`, arrays, and tuples, preserving the
container shape and masking every leaf. `nested` supports `Option` and `Vec`
containers whose leaves implement `Redact`. `map` requires text keys and
applies the key's policy to every recursive scalar leaf in its value.
`keyed_by` is available only on named fields; the sibling key must implement
`AsRef<str>`, and the value uses the same recursive scalar capability as
`level`. Standard policies pass unknown keyed values through, so configure
sensitive keys explicitly or use a stricter policy when unknown payload keys
must be masked. `json` accepts `String`, `str`, `&str`, `Cow<str>`, and their
supported optional forms; invalid JSON fails closed. In enabled mode `skip`
does not access the field; in disabled mode it restores the original field.

## Formatting and Serde

Container attributes are opt-in:

```rust
#[derive(Redact)]
#[redact(debug, display, serde)]
struct Event {
    name: String,
    #[redact(level = "secret")]
    token: String,
}
```

`debug` and `display` generate policy-aware formatting for the original type.
`serde` generates policy-aware `Serialize`; deserialization is not generated.
Field modes remain the source of truth for the serialized representation, and
`skip` remains omitted. Serialization-specific adapters are accepted only where
they cannot observe a raw value through a redaction mode.

For a structured REST response, nested values remain objects and arrays rather
than redacted debug strings:

```rust
use std::collections::BTreeMap;

use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde)]
struct Profile {
    name: String,
    #[redact(level = "secret")]
    token: String,
}

#[derive(Redact)]
#[redact(serde)]
struct ApiResponse {
    ok: bool,
    #[redact(level = "medium")]
    attempts: u32,
    #[redact(nested)]
    profiles: Option<Vec<Profile>>,
    #[redact(map)]
    attributes: BTreeMap<String, Vec<String>>,
    #[redact(json)]
    audit: String,
    #[redact(skip)]
    internal_note: String,
}

fn encode(response: &ApiResponse) -> serde_json::Result<String> {
    serde_json::to_string(response)
}
```

When redaction is enabled, masked numeric and boolean scalar leaves serialize
as JSON strings; `Option::None` remains `null`. A disabled application-default
policy restores original JSON scalar types, map values, nested fields, JSON
text, and skipped fields. `skip_serializing_if` always observes the raw field:
it runs before a non-skip mode, is not called for enabled `redact(skip)`, and is
restored for disabled `redact(skip)`. `with` and `serialize_with` are allowed
only for unmarked or skipped fields, never for a sensitive mode.

Direct Serde has no `RedactionSummary` return channel. It still fails closed on
invalid or over-budget structured content, while callers that require detailed
completion reasons should use `Redactor::redact` and inspect its summary.

## Parsed JSON values

The runtime also accepts a borrowed `serde_json::Value` without mutating it:

```rust
let value = serde_json::json!({"password": "raw", "visible": "shown"});
let output = Redactor::standard().redact_json_value(&value);
let inspection = Redactor::standard().inspect_json_value(&value);
assert!(!output.text().as_str().contains("raw"));
assert_eq!(value["password"], "raw");
let _ = inspection;
```

For multiple values, `RedactionBatch::redact_json_value` shares one budget and
summary across the batch.

## Enabled and disabled output

Global disablement intentionally restores raw values as a process-wide
debugging escape hatch:

```rust
use qubit_redact::{RedactionPolicy, Redactor};

let mut policy = RedactionPolicy::disabled();
assert!(policy.is_disabled());
policy.set_disabled(false);
let redactor = Redactor::new(policy);
```

Enabled output remains confidentiality-safe even when its summary is
`Truncated` or `Exhausted`. Check summaries for completeness, provenance, or
auditing—not to decide whether enabled text may contain a secret. Treat an
inconclusive inspection as sensitive when it drives a security decision.

The framework executes the selected application-default policy; downstream
code owns authorization, environment, timing, and any misuse of disabled mode.
Replacing the default affects future snapshots only. Existing redactors,
composers, and batches retain the immutable policy snapshot they already own.
Generated `Debug` and `Display` output does not force callers to handle
incompleteness reasons that formatting cannot act on.

## Safety and review checklist

- Review every unmarked field; the derive does not infer business sensitivity.
- Treat `skip` as output omission, not memory erasure.
- Keep the source value private across unrelated logging and serialization paths.
- Use an explicit `Redactor` policy when a subsystem must not inherit global defaults.
- Run `cargo test --all-features`, `./align-ci.sh`, and `./ci-check.sh` before release.

See the [API documentation](https://docs.rs/qubit-redact-derive) and the
[runtime guide](https://github.com/qubit-ltd/rs-redact/blob/main/doc/user_guide.md)
for policy and format details.

## License

Apache-2.0. See [LICENSE](../LICENSE).
