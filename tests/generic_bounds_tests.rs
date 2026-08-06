// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Integration tests for inferred generic capability bounds.

use qubit_redact::{
    Redact as _,
    RedactMut as _,
};
use qubit_redact_derive::Redact;

/// Generic fields receive only the bounds required by their selected modes.
#[derive(Redact)]
#[redact(serde)]
struct GenericRecord<T> {
    /// A plain field requiring ordinary formatting and serialization.
    plain: Option<T>,
    /// A sensitive field requiring immutable and mutable redaction traits.
    #[redact(level = "secret")]
    secret: T,
}

/// Verifies generated impls compile and execute with inferred bounds.
#[test]
fn test_generic_bounds_are_inferred() {
    let mut record = GenericRecord {
        plain: Some(String::from("visible")),
        secret: String::from("secret"),
    };

    let _ = format!("{:?}", record.redacted());
    let _ = serde_json::to_value(record.redacted())
        .expect("generic redacted serialization succeeds");
    record.redact_in_place();
}
