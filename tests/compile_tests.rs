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
    trybuild::TestCases::new().pass("tests/fixtures/pass/*.rs");
}

/// Keeps nested and map fixtures as an explicit regression boundary for the
/// generated mutable-session forwarding contract.
#[test]
fn test_mutable_session_forwarding_fixtures() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/fixtures/pass/nested_containers.rs");
    tests.pass("tests/fixtures/pass/map_fields.rs");
}

/// Verifies that invalid attributes produce stable targeted diagnostics.
#[test]
fn test_compile_fail_fixtures() {
    let mut fixtures = std::fs::read_dir("tests/fixtures/fail")
        .expect("compile-fail fixture directory should exist")
        .map(|entry| entry.expect("compile-fail fixture entry should exist").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .filter(|_path| {
            #[cfg(feature = "test-json")]
            {
                _path.file_name().is_some_and(|name| name != "json_without_feature.rs")
            }
            #[cfg(not(feature = "test-json"))]
            {
                true
            }
        })
        .collect::<Vec<_>>();
    fixtures.sort();

    let tests = trybuild::TestCases::new();
    for fixture in fixtures {
        tests.compile_fail(fixture);
    }
}
