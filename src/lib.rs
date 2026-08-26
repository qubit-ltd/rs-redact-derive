// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Derive macros for borrowing, policy-aware `qubit-redact` domain objects.

use proc_macro::TokenStream;
use syn::Error;
use syn::parse;

mod attributes;
mod expand;
mod model;
mod runtime_path;
mod serde;

#[cfg(test)]
mod tests;

/// Derives the borrowing `qubit_redact::Redact` implementation.
///
/// Fields without an attribute intentionally use ordinary `Debug` formatting.
/// Sensitivity is downstream business-domain knowledge that the macro cannot
/// infer reliably from a field name or Rust type. Ordinary fields are the large
/// majority, so an explicit "not sensitive" attribute on every field would add
/// noise without adding knowledge. Downstream types must explicitly annotate
/// sensitive fields and review that classification when their model changes;
/// strict policy and inspection deliberately do not override this decision.
///
/// Supported field modes are:
///
/// - `#[redact(level = "low" | "medium" | "high" | "secret")]` masks every
///   supported scalar leaf while preserving recursive container shape;
/// - `#[redact(nested)]` delegates to nested `Redact` values;
/// - `#[redact(map)]` classifies text-keyed map values by key;
/// - `#[redact(json)]` recursively redacts supported JSON text values;
/// - `#[redact(skip)]` omits the field while redaction is enabled.
///
/// Container options `#[redact(debug)]` and `#[redact(display)]` generate
/// policy-aware formatting implementations. `#[redact(serde)]` generates a
/// structured `serde::Serialize` implementation and requires direct runtime
/// and Serde dependencies. Generated formatting writes enabled-policy text
/// directly for every completion state because it remains confidentiality-safe;
/// callers that require completeness must use the runtime API and inspect its
/// summary instead.
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
/// use qubit_redact_derive::Redact;
///
/// #[derive(Redact)]
/// struct Login {
///     user: String,
///     #[redact(level = "secret")]
///     password: String,
/// }
///
/// let login = Login {
///     user: "ada".to_owned(),
///     password: "raw-secret".to_owned(),
/// };
/// let output = Redactor::standard().redact(&login);
/// assert!(output.text().as_str().contains("ada"));
/// assert!(!output.text().as_str().contains("raw-secret"));
/// ```
#[proc_macro_derive(Redact, attributes(redact, serde))]
pub fn derive_redact(input: TokenStream) -> TokenStream {
    parse(input)
        .and_then(|input| expand::expand(&input))
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
