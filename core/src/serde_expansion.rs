// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Redacted Serde implementation generation.

mod internal;

/// Generates the redacted Serde implementation for one derive input.
pub(crate) use internal::expand;
