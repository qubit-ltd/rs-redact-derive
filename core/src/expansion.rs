// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public entry points for redaction derive expansion.

use proc_macro2::TokenStream;
use syn::DeriveInput;
use syn::Result;

use crate::redact_expansion;
use crate::redact_options::RedactOptions;
use crate::runtime_path;

/// Generates the standard `Redact` derive expansion.
///
/// # Parameters
///
/// * `input` - Complete derive input to expand.
///
/// # Returns
///
/// Generated implementations for the requested redaction behavior.
///
/// # Errors
///
/// Returns a targeted syntax error when the runtime crate, input shape, or
/// redaction attributes cannot be resolved.
pub fn expand(input: &DeriveInput) -> Result<TokenStream> {
    let runtime = runtime_path::resolve(input)?;
    redact_expansion::expand(input, &runtime)
}

/// Generates a redaction expansion using options supplied by another macro.
///
/// # Parameters
///
/// * `input` - Complete derive input to expand.
/// * `options` - Optional formatting and serialization integrations to emit.
///
/// # Returns
///
/// Generated implementations selected by `options`.
///
/// # Errors
///
/// Returns a targeted syntax error when the runtime crate, input shape, or
/// redaction attributes cannot be resolved.
pub fn expand_with_options(input: &DeriveInput, options: RedactOptions) -> Result<TokenStream> {
    let runtime = runtime_path::resolve(input)?;
    redact_expansion::expand_with_options(input, &runtime, options)
}
