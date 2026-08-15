// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for the core expansion entry points.

use qubit_redact_derive_core::RedactOptions;
use qubit_redact_derive_core::expand;
use qubit_redact_derive_core::expand_with_options;
use syn::DeriveInput;
use syn::parse_str;

/// Parses a derive input fixture for the expansion entry-point tests.
fn parse_input() -> DeriveInput {
    parse_str("struct Record { value: String }")
        .expect("the expansion fixture should parse")
}

/// Verifies the standard expansion entry point produces implementation tokens.
#[test]
fn test_expand_generates_redact_implementation() {
    let tokens =
        expand(&parse_input()).expect("standard expansion should succeed");

    assert!(tokens.to_string().contains("Redact"));
}

/// Verifies option-driven expansion accepts all optional integrations.
#[test]
fn test_expand_with_options_generates_requested_implementations() {
    let tokens = expand_with_options(
        &parse_input(),
        RedactOptions {
            debug: true,
            display: true,
            serde: true,
        },
    )
    .expect("option-driven expansion should succeed");
    let rendered = tokens.to_string();

    assert!(rendered.contains("Debug"));
    assert!(rendered.contains("Display"));
    assert!(rendered.contains("Serialize"));
}
