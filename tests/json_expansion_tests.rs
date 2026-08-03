// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for generated JSON redaction integration.

#![cfg(feature = "json")]

mod support;

/// Verifies JSON redaction covers formatting, Serde, and mutation.
#[test]
fn test_json_expansion_covers_all_boundaries() {
    support::assertions::assert_json_expansion();
}
