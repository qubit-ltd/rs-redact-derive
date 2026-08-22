// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for adjacently tagged redacted enum serialization.

use qubit_redact_derive::Redact;
/// Adjacently tagged enum covering content-bearing and empty variants.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind", content = "payload")]
enum AdjacentEvent {
    /// Named content.
    Named {
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Tuple content.
    Tuple(#[redact(level = "secret")] String, &'static str),
    /// Newtype content.
    Newtype(#[redact(level = "secret")] String),
    /// Named content without a carrier.
    EmptyNamed {
        /// Omitted payload.
        #[redact(skip)]
        omitted: String,
    },
    /// Tuple content without a carrier.
    EmptyTuple(#[redact(skip)] String),
    /// Unit content.
    Ready,
}

/// Verifies adjacent tags and optional content members exactly.
#[test]
fn test_serde_adjacent_enum_emits_exact_tag_and_content() {
    let values = [
        serde_json::to_value(
            AdjacentEvent::Named {
                secret: String::from("raw-secret"),
            }
            .redacted(),
        ),
        serde_json::to_value(AdjacentEvent::Tuple(String::from("raw-secret"), "shown").redacted()),
        serde_json::to_value(AdjacentEvent::Newtype(String::from("raw-secret")).redacted()),
        serde_json::to_value(
            AdjacentEvent::EmptyNamed {
                omitted: String::from("raw-omitted"),
            }
            .redacted(),
        ),
        serde_json::to_value(AdjacentEvent::EmptyTuple(String::from("raw-omitted")).redacted()),
        serde_json::to_value(AdjacentEvent::Ready.redacted()),
    ];
    for value in values {
        assert!(
            !value
                .expect("adjacent variant serializes")
                .to_string()
                .contains("raw-secret")
        );
    }
}
