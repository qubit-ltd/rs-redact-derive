// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile tests for supported `Redact` derive inputs.

/// Verifies that all supported derive fixtures compile successfully.
#[test]
fn test_pass_fixtures() {
    trybuild::TestCases::new().pass("tests/fixtures/pass/new_contract.rs");
    trybuild::TestCases::new().pass("tests/fixtures/pass/serde_wire_shape.rs");
}

/// Keeps nested and map fixtures as an explicit regression boundary for the
/// generated mutable-session forwarding contract.
#[test]
fn test_mutable_session_forwarding_fixtures() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/fixtures/pass/new_contract.rs");
    tests.pass("tests/fixtures/pass/serde_wire_shape.rs");
}

/// Verifies that invalid attributes produce stable targeted diagnostics.
#[test]
fn test_compile_fail_fixtures() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/fixtures/fail/removed_attributes.rs");
}
