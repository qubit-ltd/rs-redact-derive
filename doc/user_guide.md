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
| `json` | Recursively redact supported JSON text values. |

The removed `plain`, `no_mut`, and `require_explicit` attributes are rejected.
Use an unmarked field only when ordinary `Debug` output has been deliberately
reviewed. The macro supports named, tuple, and unit structs and enum variants.

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
