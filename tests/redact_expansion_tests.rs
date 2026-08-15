// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for immutable implementation expansion.

mod support;

/// Verifies immutable expansion preserves enum formatting shapes.
#[test]
fn test_redact_expansion_preserves_enum_shapes() {
    support::assertions::assert_enum_redaction();
}

/// Verifies generated field helpers can forward one mutable session into map
/// redaction, which requires the runtime 0.5 session contract.
#[test]
fn test_redact_expansion_forwards_mutable_session_to_map_fields() {
    support::assertions::assert_named_redaction();
}

/// Verifies field admission occurs before plain or skipped field access.
#[test]
fn test_redact_expansion_admits_fields_before_access() {
    support::assertions::assert_field_admission_precedes_access();
}

/// Verifies nested derives reuse the parent session and depth budget.
#[test]
fn test_redact_expansion_reuses_session_for_nested_fields() {
    support::assertions::assert_nested_admission_uses_shared_session();
}

/// Verifies tuple structs retain their complete safe structure.
#[test]
fn test_redact_expansion_preserves_tuple_struct_shape() {
    support::assertions::assert_tuple_redaction();
}
