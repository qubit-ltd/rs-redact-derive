// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-pass fixture for every enum variant shape.

use qubit_redact::domain::Redact as _;
use qubit_redact::policy::DomainRedactionLimits;
use qubit_redact::RedactionPolicy;
use qubit_redact_derive::Redact;

/// Enum combining named, tuple, and unit variants.
#[derive(Redact)]
enum Event {
    /// Named variant with a sensitive field.
    Named {
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Tuple variant with a sensitive and skipped field.
    Tuple(
        #[redact(level = "secret")] String,
        #[redact(skip)] String,
    ),
    /// Unit variant.
    Ready,
}

/// Exercises complete safe output for every supported variant shape.
fn main() {
    let mut builder = RedactionPolicy::builder();
    builder.limits().domain(
        DomainRedactionLimits::builder().max_nodes(2).max_collection_items(1).max_depth(1).build()
            .expect("the fixture domain limits should be valid"),
    );
    let policy = builder
        .build()
        .expect("the fixture redaction policy should be valid");

    let named = Event::Named {
        secret: "raw-named".to_owned(),
    };
    let tuple = Event::Tuple("raw-tuple".to_owned(), "skipped".to_owned());
    assert_eq!(
        format!("{:?}", named.redacted_with(&policy)),
        r#"Named { secret: "<redacted>" }"#,
    );
    assert_eq!(
        format!("{:?}", tuple.redacted_with(&policy)),
        r#"Tuple("<redacted>")"#,
    );
    assert_eq!(
        format!("{:?}", Event::Ready.redacted_with(&policy)),
        "Ready",
    );
}
