// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for optional redaction expansion integrations.

use qubit_redact_derive_core::RedactOptions;

/// Verifies the default options disable every optional integration.
#[test]
fn test_redact_options_default_disables_integrations() {
    let options = RedactOptions::default();

    assert!(!options.debug);
    assert!(!options.display);
    assert!(!options.serde);
}

/// Verifies callers can independently select each optional integration.
#[test]
fn test_redact_options_selects_integrations_independently() {
    let options = RedactOptions {
        debug: true,
        display: false,
        serde: true,
    };

    assert!(options.debug);
    assert!(!options.display);
    assert!(options.serde);
}
