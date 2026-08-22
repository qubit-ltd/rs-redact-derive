// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Integration tests for the unified `Redact` derive.

use qubit_redact::RedactMut as _;
use qubit_redact_derive::Redact;
/// A domain value receiving both immutable and mutable capabilities from one
/// derive.
#[derive(Redact)]
struct User {
    username: &'static str,
    #[redact(level = "secret")]
    password: String,
}

/// A domain value using all optional standard trait integrations together.
#[derive(Redact)]
#[redact(debug, display, serde)]
struct FormattedUser {
    username: &'static str,
    #[redact(level = "secret")]
    password: String,
}

/// A borrowed sensitive value that intentionally disables mutable redaction.
#[derive(Redact)]
#[redact(no_mut)]
struct BorrowedUser<'a> {
    #[redact(level = "secret")]
    password: &'a str,
}

/// A borrowed plain value does not participate in mutable capability checks.
#[derive(Redact)]
struct MixedBorrowedUser<'a> {
    username: &'a str,
    #[redact(level = "secret")]
    password: String,
}

/// Verifies one derive provides immutable and mutable runtime capabilities.
#[test]
fn test_redact_derive_provides_immutable_and_mutable_capabilities() {
    let mut user = User {
        username: "alice",
        password: String::from("raw-password"),
    };

    assert!(!format!("{:?}", user.redacted()).contains("raw-password"));
    user.redact_in_place();
    assert_eq!(user.password, "<redacted>");
}

/// Verifies optional standard integrations use the combined container syntax.
#[test]
fn test_redact_derive_combined_format_and_serde_integrations() {
    let user = FormattedUser {
        username: "alice",
        password: String::from("raw-password"),
    };

    let debug = format!("{user:?}");
    let display = format!("{user}");
    let json = serde_json::to_string(&user).expect("direct redacted serialization should succeed");

    assert!(!debug.contains("raw-password"));
    assert!(!display.contains("raw-password"));
    assert!(!json.contains("raw-password"));
}

/// Verifies `no_mut` permits an immutable borrowed sensitive field.
#[test]
fn test_redact_derive_no_mut_allows_borrowed_sensitive_field() {
    let user = BorrowedUser {
        password: "raw-password",
    };

    assert!(!format!("{:?}", user.redacted()).contains("raw-password"));
}

/// Verifies plain borrowed fields do not disable mutable redaction elsewhere.
#[test]
fn test_redact_derive_plain_borrowed_field_keeps_mutable_capability() {
    let mut user = MixedBorrowedUser {
        username: "alice",
        password: String::from("raw-password"),
    };

    user.redact_in_place();
    assert_eq!(user.username, "alice");
    assert_eq!(user.password, "<redacted>");
}
