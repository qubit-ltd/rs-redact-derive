// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-pass fixture for generic fields using Serde adapters.

use std::fmt;

use qubit_redact::{Redact as _, RedactionPolicy};
use qubit_redact_derive::Redact;

/// A value that implements `Debug` but intentionally not `Serialize`.
struct DebugOnly;

impl fmt::Debug for DebugOnly {
    /// Formats the marker without exposing any payload.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DebugOnly")
    }
}

/// Generic record whose field is serialized exclusively by an adapter.
#[derive(Redact)]
#[redact(serde)]
struct GenericRecord<T> {
    /// Field handled by the generic adapter.
    #[redact(plain)]
    #[serde(serialize_with = "serialize_unit")]
    value: T,
}

/// Serializes any adapted value as a unit.
fn serialize_unit<T, S>(
    _value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_unit()
}

/// Exercises generic adapter expansion without requiring `T: Serialize`.
fn main() {
    let value = GenericRecord { value: DebugOnly };
    let policy = RedactionPolicy::default();
    let _ = value.redacted_with(&policy);
    let _ = serde_json::to_value(value.redacted())
        .expect("generic adapter serialization should succeed");
}
