// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Derive macros for `qubit-redact` domain objects.

use proc_macro::TokenStream;
use qubit_redact_derive_core::expand;
use syn::Error;
use syn::parse;

/// Derives immutable redacted formatting for a struct or enum.
///
/// Named, tuple, and unit structs are accepted, as are enums with named,
/// tuple, and unit variants. Unmarked fields use ordinary `Debug` by default;
/// masking, recursion, map processing, and omission require explicit field
/// attributes. This derive macro deliberately does not infer which fields are
/// sensitive: type owners must classify newly added fields and choose the
/// appropriate attributes. Add `#[redact(require_explicit)]` as an opt-in
/// review aid to require every field to select a mode, and use
/// `#[redact(plain)]` for fields that should remain visible. It is not an
/// automatic privacy guarantee.
///
/// # Parameters
///
/// * `input` - Rust item annotated with `#[derive(Redact)]`.
///
/// # Returns
///
/// Implementations of `qubit_redact::Redact` and, unless disabled by
/// `#[redact(no_mut)]`, `qubit_redact::RedactMut`, plus any requested optional
/// formatting or serialization implementations. Invalid input produces a
/// targeted compile error.
#[proc_macro_derive(Redact, attributes(redact, serde))]
#[inline(always)]
pub fn derive_redact(input: TokenStream) -> TokenStream {
    parse(input)
        .and_then(|input| expand(&input))
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
