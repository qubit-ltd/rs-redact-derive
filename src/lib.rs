//! Derive macros for `qubit-redact` domain objects.

use proc_macro::TokenStream;
use syn::Error;
use syn::parse;

mod container_attributes;
mod expansion;
mod field_attributes;
mod field_mode;
mod format_expansion;
mod generic_bounds;
mod input_model;
mod internal;
mod named_fields;
mod redact_expansion;
mod runtime_path;
mod sensitivity;
mod serde_attributes;
mod serde_container_attributes;
mod serde_enum_representation;
mod serde_expansion;
mod serde_path;
mod serde_rename_rule;
mod serde_variant_attributes;
mod unnamed_fields;

/// Derives the borrowing Redact implementation for qubit-redact.
#[proc_macro_derive(Redact, attributes(redact, serde))]
pub fn derive_redact(input: TokenStream) -> TokenStream {
    parse(input)
        .and_then(|input| expansion::expand(&input))
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
