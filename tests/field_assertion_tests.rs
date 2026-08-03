// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for generated field capability assertions.

mod support;

/// Verifies generated field assertions are exercised by usable expansions.
#[test]
fn test_field_assertion_expansions_are_usable() {
    support::assertions::assert_named_redaction();
    support::assertions::assert_mutable_redaction();
}
