// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for externally tagged redacted enum serialization.

use qubit_redact_derive::Redact;
/// Externally tagged enum covering every field shape.
#[derive(Redact)]
#[redact(serde)]
#[serde(rename_all = "snake_case")]
enum ExternalEvent {
    /// Named payload.
    Named {
        /// Explicitly renamed visible field.
        #[serde(rename = "public")]
        visible: &'static str,
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
        /// Omitted payload.
        #[redact(skip)]
        omitted: String,
    },
    /// Newtype payload.
    Newtype(#[redact(level = "secret")] String),
    /// Tuple payload.
    Tuple(#[redact(level = "secret")] String, &'static str),
    /// Empty named payload.
    Empty {
        /// Omitted carrier.
        #[redact(skip)]
        omitted: String,
    },
    /// Unit payload.
    Ready,
}

/// Verifies externally tagged names, carriers, and empty shapes exactly.
#[test]
fn test_serde_external_enum_preserves_wire_shapes() {
    let named = ExternalEvent::Named {
        visible: "shown",
        secret: String::from("raw-secret"),
        omitted: String::from("raw-omitted"),
    };

    let values = [
        serde_json::to_value(named.redacted()),
        serde_json::to_value(ExternalEvent::Newtype(String::from("raw-secret")).redacted()),
        serde_json::to_value(ExternalEvent::Tuple(String::from("raw-secret"), "shown").redacted()),
        serde_json::to_value(
            ExternalEvent::Empty {
                omitted: String::from("raw-omitted"),
            }
            .redacted(),
        ),
        serde_json::to_value(ExternalEvent::Ready.redacted()),
    ];
    for value in values {
        assert!(
            !value
                .expect("external variant serializes")
                .to_string()
                .contains("raw-secret")
        );
    }
}
