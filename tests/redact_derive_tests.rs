// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for immutable derive orchestration.

mod support;

/// Verifies immutable derive orchestration accepts enum inputs.
#[test]
fn test_redact_derive_accepts_enum_inputs() {
    support::assertions::assert_enum_redaction();
}

/// Verifies the derive boundary compiles generated map helpers with the
/// mutable session required by runtime 0.5.
#[test]
fn test_redact_derive_forwards_mutable_session_to_map_fields() {
    support::assertions::assert_named_redaction();
}
