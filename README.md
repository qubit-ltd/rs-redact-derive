# qubit-redact-derive

[![Rust CI](https://github.com/qubit-ltd/rs-redact-derive/actions/workflows/ci.yml/badge.svg)](https://github.com/qubit-ltd/rs-redact-derive/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://qubit-ltd.github.io/rs-redact-derive/coverage-badge.json)](https://qubit-ltd.github.io/rs-redact-derive/coverage/)
[![Crates.io](https://img.shields.io/crates/v/qubit-redact-derive.svg?color=blue)](https://crates.io/crates/qubit-redact-derive)
[![Rust](https://img.shields.io/badge/rust-1.94+-blue.svg?logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![中文文档](https://img.shields.io/badge/文档-中文版-blue.svg)](README.zh_CN.md)

Qubit Redact Derive provides procedural macros for the
[`qubit-redact`](https://crates.io/crates/qubit-redact) runtime crate. Use
them to define a deliberate redaction boundary for Rust domain objects: create
safe borrowed diagnostic views with `Redact`, or explicitly replace logical
values with `RedactMut`. A single `#[derive(Redact)]` generates both runtime
capabilities by default.

> **WARNING — unannotated fields are permanently plain.** Generated redaction,
> `strict()` policies, the application default, and inspection never infer
> sensitivity for a field without `#[redact(...)]`. Review every newly added
> field. `#[redact(require_explicit)]` is an opt-in compile-time review aid;
> `#[redact(skip)]` deliberately bypasses redaction.

## Why qubit-redact-derive

- Field annotations make masking, omission, nested redaction, and map
  redaction reviewable at the domain-model boundary.
- The macros support named, tuple, and unit structs, plus enums with all three
  variant shapes.
- Optional Serde support can make direct serialization of the original type
  produce a redacted representation without granting it deserialization or
  exposing an original-value escape hatch.
- The generated code resolves a direct `qubit-redact` dependency, including a
  Cargo-renamed dependency, instead of relying on a fixed import spelling.

## Quick Start

Add the runtime and derive crates together:

```toml
[dependencies]
qubit-redact = "0.5"
qubit-redact-derive = "0.5"
```

```rust
use qubit_redact::domain::Redact as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Credentials {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

fn main() {
    let credentials = Credentials {
        user: "ada".to_owned(),
        password: "raw-password".to_owned(),
    };

    let output = format!("{:?}", credentials.redacted());
    assert_eq!(
        output,
        r#"Credentials { user: "ada", password: "<redacted>" }"#,
    );
}
```

`Redact` creates a borrowed view. The original `Credentials` value remains
available to application logic. The same derive also generates the
`RedactMut` capability:

```rust
use qubit_redact::domain::{Redact as _, RedactMut as _};
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct Credentials {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

fn main() {
    let credentials = Credentials {
        user: "ada".to_owned(),
        password: "raw-password".to_owned(),
    };
    let credentials = credentials.into_redacted();
    assert_eq!(credentials.password, "<redacted>");
}
```

Use `#[redact(no_mut)]` when a type contains sensitive borrowed fields that
cannot be replaced in place.

For types whose fields must all be reviewed explicitly, add
`#[redact(require_explicit)]`. Mark intentionally visible fields with
`#[redact(plain)]`; the default behavior remains unchanged for existing types.

## Choose a Derive

| Need | Derive/attribute | Result |
| --- | --- | --- |
| Safely inspect or log a domain object without changing it | `Redact` | A borrowed `Redacted<T>` view. |
| Replace owned logical values before another boundary | `Redact` | `redact_in_place()` or `into_redacted()` from the generated `RedactMut` capability. |
| Make an original type format through the process default policy | `Redact` with `#[redact(debug)]` or `#[redact(display)]` | Generated `Debug` and/or `Display` for the original type. |
| Serialize the original type as redacted JSON | `Redact` with `#[redact(serde)]` | Direct redacted `Serialize` for the original type plus policy-aware serialization for `Redacted<T>`. |

Use the immutable capability for diagnostics whenever possible. Use the
generated mutable capability only when the next boundary requires a logically
replaced value.

## Attribute Overview

Field attributes select exactly one handling mode:

| Attribute | Effect |
| --- | --- |
| `#[redact(level = "low")]`, `"medium"`, `"high"`, or `"secret"` | Masks the field with the specified runtime sensitivity. |
| `#[redact(plain)]` | Keeps the field visible and documents the intentional pass-through. |
| `#[redact(skip)]` | Omits the field from the redacted view. |
| `#[redact(nested)]` | Delegates redaction to the nested value. |
| `#[redact(map)]` | Redacts text-keyed map values using their keys and the complete runtime policy. |
| `#[redact(json)]` | Redacts JSON stored in a `String` recursively by object key; invalid JSON is replaced opaquely. |

Container attributes are opt-in controls:

| Attribute | Effect |
| --- | --- |
| `#[redact(debug)]` | Generates redacted `Debug` for the original type. |
| `#[redact(display)]` | Generates redacted `Display` for the original type. |
| `#[redact(serde)]` | Generates direct redacted `Serialize` for the original type and preserves policy-aware serialization for `Redacted<T>`. |
| `#[redact(no_mut)]` | Does not generate `RedactMut`; useful for sensitive borrowed fields such as `&str`. |
| `#[redact(require_explicit)]` | Requires every field to select one field mode; it does not change the default behavior. |

The options can be combined in one attribute:

```rust
#[derive(Redact)]
#[redact(debug, display, serde)]
struct Login {
    account: String,
    #[redact(level = "secret")]
    password: String,
}
```

Unmarked fields use their ordinary `Debug` representation by default. They are
neither masked nor recursively traversed. `require_explicit` changes only the
derive invocation where it is written.

Field sensitivity classification belongs to the downstream application and its
domain-model owners. This derive cannot determine whether a field is sensitive
in a particular product, so it intentionally does not require every field to
carry an attribute. Applications should mark the fields that cross their
redaction boundary and choose `plain` only when ordinary visibility is an
intentional, reviewed decision. `require_explicit` is available for models
whose review policy requires every field to make that choice.

When `#[redact(serde)]` is enabled, deserialization-only Serde controls such as
`default`, `alias`, `skip_deserializing`, and `deny_unknown_fields` are accepted
and ignored by the generated serialization. Structural or serialization-side
controls that could bypass redaction remain rejected.
Serialization adapters (`with` and `serialize_with`) are accepted only on
`plain` or `skip` fields. A plain adapter intentionally receives the original
field value; redaction modes that inspect raw state reject adapters so they
cannot bypass the generated redaction.

## Dependencies and Features

The generated code requires `qubit-redact` to be a direct dependency. The
derive crate discovers Cargo renames, so this also works:

```toml
[dependencies]
redaction = { package = "qubit-redact", version = "0.5" }
qubit-redact-derive = "0.5"
```

To use `#[redact(serde)]`, enable the runtime crate's `serde` feature and
declare `serde` directly:

```toml
[dependencies]
qubit-redact = { version = "0.5", features = ["serde"] }
qubit-redact-derive = "0.5"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

`#[redact(json)]` requires the runtime crate's `json` feature. It formats a
redacted JSON view, rewrites the string as compact redacted JSON for
`RedactMut`, and serializes as a JSON string when combined with
`#[redact(serde)]`.

The derive package's `test-json` feature is only for its own test suite; it
does not enable runtime features for downstream crates.

## Safety Boundaries

- The macros protect only the redacted view, generated formatting, or explicit
  in-place operation that you use. They cannot protect unrelated log calls or
  serialization paths.
- An unmarked field always uses its own `Debug` output under every policy and
  during inspection. Mark every field whose
  representation can disclose sensitive data, or opt into
  `#[redact(require_explicit)]` and use `#[redact(plain)]` for intentional
  pass-through fields.
- `skip` omits a value from the redacted representation; it does not erase
  the original value.
- `RedactMut` performs logical replacement only. It does not erase released
  allocations, aliases, copies, or borrowed backing storage.
- Generated `debug`, `display`, `redacted()`, `inspected()`, and no-argument
  `RedactMut` methods use the process-wide application-default policy. Use an
  explicit `redacted_with`, `inspected_with`, or mutation `_with` boundary when a call site
  needs policy isolation.
  Redacted `Debug` output uses the policy diagnostic output budget by default.
  Nested, map, and JSON fields share the same diagnostic session for one
  redacted view, so they cannot independently reset that budget.
- Do not use `skip_serializing_if` with `level`, `nested`, `map`, or `json`; its
  predicate receives the raw field and could reveal sensitive state through
  field presence. It is supported only with `plain` and `skip` fields.

## Learn More

- [English User Guide](doc/user_guide.md) and [中文用户手册](doc/user_guide.zh_CN.md)
- [Runtime README](https://github.com/qubit-ltd/rs-redact/blob/main/README.md) and [runtime user guide](https://github.com/qubit-ltd/rs-redact/blob/main/doc/user_guide.md)
- [Runtime API documentation](https://docs.rs/qubit-redact)
- [Derive API documentation](https://docs.rs/qubit-redact-derive)

## Testing

```bash
# Run tests with the default feature set
cargo test

# Run tests with all declared features
cargo test --all-features

# Project CI checks
./ci-check.sh

# Check code coverage
./coverage.sh
```

## License

Copyright (c) 2025 - 2026. Haixing Hu. All rights reserved.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the
full license text.

## Contributing

Contributions are welcome. Please follow the Rust API guidelines, keep public
API documentation and tests current, and run `./align-ci.sh` to format code and
`./ci-check.sh` to satisfy CI requirements before submitting a pull request.

## Author

**Haixing Hu** - *Qubit Co. Ltd.*

Repository: [https://github.com/qubit-ltd/rs-redact-derive](https://github.com/qubit-ltd/rs-redact-derive)
