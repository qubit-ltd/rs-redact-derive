// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================

//! Shared expansion implementation for redaction procedural macros.

mod container_attributes;
mod field_assertion;
mod field_attributes;
mod field_mode;
mod format_expansion;
mod generic_bounds;
mod immutable_trait_name;
mod input_model;
mod internal;
mod named_fields;
mod redact_expansion;
mod redact_mut_expansion;
mod runtime_path;
mod sensitivity;
mod serde_attributes;
mod serde_container_attributes;
mod serde_enum_representation;
mod serde_expansion;
mod serde_path;
mod serde_rename_rule;
mod serde_variant_attributes;
mod serialization_context;
mod unnamed_fields;

use proc_macro2::TokenStream;
use syn::DeriveInput;
use syn::Result;

/// Generates the standard `Redact` derive expansion.
pub fn expand(input: &DeriveInput) -> Result<TokenStream> {
    let runtime = runtime_path::resolve(input)?;
    redact_expansion::expand(input, &runtime)
}

/// Generates a redaction expansion using options supplied by another macro.
pub fn expand_with_options(input: &DeriveInput, options: RedactOptions) -> Result<TokenStream> {
    let runtime = runtime_path::resolve(input)?;
    redact_expansion::expand_with_options(input, &runtime, options)
}

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
