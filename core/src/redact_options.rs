// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Optional integrations selected by a hosting macro.

/// Optional redaction integrations selected by a hosting macro.
#[derive(Clone, Copy, Debug, Default)]
pub struct RedactOptions {
    /// Generates a redacted `Debug` implementation.
    pub debug: bool,
    /// Generates a redacted `Display` implementation.
    pub display: bool,
    /// Generates redacted `Serialize` support.
    pub serde: bool,
}
