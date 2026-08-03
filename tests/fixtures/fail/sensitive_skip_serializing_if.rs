// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for raw-value predicates on redacted fields.

use qubit_redact_derive::Redact;

/// A predicate must not inspect a field after it is classified as sensitive.
#[derive(Redact)]
#[redact(serde)]
struct SensitiveRecord {
    /// Sensitive content whose presence must not reveal raw state.
    #[redact(level = "secret")]
    #[serde(skip_serializing_if = "String::is_empty")]
    value: String,
}

/// Tuple fields must reject the same raw-value predicate side channel.
#[derive(Redact)]
#[redact(serde)]
struct SensitiveTuple(
    #[redact(level = "secret")]
    #[serde(skip_serializing_if = "String::is_empty")]
    String,
);

fn main() {}
