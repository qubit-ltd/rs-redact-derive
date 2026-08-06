// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-pass fixture for inferred field capability bounds.

use qubit_redact::{
    Redact as _,
    RedactMut as _,
};
use qubit_redact_derive::Redact;

/// The derive supplies the bounds required by its selected field modes.
#[derive(Redact)]
#[redact(serde)]
struct GenericRecord<T> {
    /// A visible field requiring `Debug`.
    plain: T,
    /// A nested generic field requiring recursive bound discovery.
    wrapped: Option<T>,
    /// A masked field requiring `RedactValue`.
    #[redact(level = "secret")]
    secret: T,
}

fn main() {
    let mut record = GenericRecord {
        plain: String::from("visible"),
        wrapped: Some(String::from("wrapped")),
        secret: String::from("secret"),
    };
    let _ = format!("{:?}", record.redacted());
    let _ = serde_json::to_value(record.redacted());
    record.redact_in_place();
}
