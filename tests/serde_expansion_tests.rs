// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for redacted Serde expansion.

mod serde_expansion;
mod support;

/// Verifies generated serialization excludes raw sensitive content.
#[test]
fn test_serde_expansion_excludes_raw_content() {
    support::assertions::assert_serde_expansion();
}

/// Verifies plain fields preserve supported Serde serialization adapters.
#[test]
fn test_serde_expansion_preserves_plain_field_adapters() {
    support::assertions::assert_serde_adapter_expansion();
}
