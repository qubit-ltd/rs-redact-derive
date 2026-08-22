// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Combined immutable and mutable `Redact` implementation generation.

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use quote::quote_spanned;
use syn::DeriveInput;
use syn::Field;
use syn::Ident;
use syn::Path;
use syn::Result;
use syn::spanned::Spanned;

use crate::container_attributes::ContainerAttributes;
use crate::field_mode::FieldMode;
use crate::format_expansion;
use crate::generic_bounds;
use crate::input_model;
use crate::internal::ContainerData;
use crate::internal::FieldsData;
use crate::internal::VariantData;
use crate::serde_container_attributes::SerdeContainerAttributes;
use crate::serde_expansion;
use crate::serde_path;
/// Expands a struct into its runtime `Redact` implementation.
///
/// # Parameters
///
/// * `input` - Parsed derive input whose generics and fields are preserved.
/// * `runtime` - Resolved path to the `qubit-redact` runtime crate.
///
/// # Returns
///
/// Generated immutable redaction, optional mutable redaction, and optional
/// formatting or serde implementation tokens.
///
/// # Errors
///
/// Returns a targeted syntax error when container or field controls are
/// invalid or when Serde controls conflict with the input shape.
pub(crate) fn expand(input: &DeriveInput, runtime: &Path) -> Result<TokenStream> {
    let container_attributes = ContainerAttributes::parse(input)?;
    expand_with_container_attributes(input, runtime, container_attributes)
}

/// Generates the implementation from already-validated container controls.
///
/// # Parameters
///
/// * `input` - Complete derive input to expand.
/// * `runtime` - Resolved path to the `qubit-redact` runtime crate.
/// * `container_attributes` - Validated controls selected for the expansion.
///
/// # Returns
///
/// Generated implementations for the validated input.
///
/// # Errors
///
/// Returns a targeted syntax error when field, Serde, or capability controls
/// are incompatible with the input.
fn expand_with_container_attributes(
    input: &DeriveInput,
    runtime: &Path,
    container_attributes: ContainerAttributes,
) -> Result<TokenStream> {
    let model = input_model::parse(input, "Redact", container_attributes.serde_enabled())?;
    let serde = container_attributes
        .serde_enabled()
        .then(|| serde_path::resolve(input))
        .transpose()?;
    let serde_container_attributes = SerdeContainerAttributes::parse(input, container_attributes.serde_enabled())?;
    let serde_impl = serde_expansion::expand(input, runtime, serde.as_ref(), &serde_container_attributes, &model)?;
    let mut redaction_generics = input.generics.clone();
    generic_bounds::add_immutable_bounds(&mut redaction_generics, &model, runtime);
    let write_body = match &model {
        ContainerData::Struct(fields) => writer_struct_body(&input.ident, fields, runtime),
        ContainerData::Enum(variants) => writer_enum_body(&input.ident, variants, runtime),
    };
    let format_impl = format_expansion::expand(input, runtime, &container_attributes, &redaction_generics);
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = redaction_generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #runtime::Redact for #name #type_generics #where_clause {
            fn write_redacted(
                &self,
                writer: &mut #runtime::RedactionWriter<'_>,
            ) {
                #write_body
            }
        }
        #format_impl
        #serde_impl
    })
}

/// Generates a structured writer body for one struct.
fn writer_struct_body(type_name: &Ident, fields: &FieldsData<'_>, runtime: &Path) -> TokenStream {
    match fields {
        FieldsData::Named(fields) => {
            let calls = fields.iter().filter_map(|field| {
                let identifier = field.identifier();
                writer_field_call(
                    type_name,
                    field.field(),
                    &field.identifier().to_string(),
                    &field.identifier().to_string(),
                    field.attributes().mode(),
                    quote!(&self.#identifier),
                    runtime,
                )
            });
            quote! {
                writer.record(stringify!(#type_name), |__fields| {
                    #(#calls)*
                });
            }
        }
        FieldsData::Unnamed(fields) => {
            let calls = fields.iter().filter_map(|field| {
                let index = field.index();
                writer_field_call(
                    type_name,
                    field.field(),
                    &index.index.to_string(),
                    &index.index.to_string(),
                    field.attributes().mode(),
                    quote!(&self.#index),
                    runtime,
                )
            });
            quote! {
                writer.tuple(stringify!(#type_name), |__fields| {
                    #(#calls)*
                });
            }
        }
        FieldsData::Unit => quote! { writer.record(stringify!(#type_name), |_| {}); },
    }
}

/// Generates a structured writer match for one enum.
fn writer_enum_body(type_name: &Ident, variants: &[VariantData<'_>], runtime: &Path) -> TokenStream {
    let arms = variants.iter().map(|variant| {
        let variant_name = &variant.variant().ident;
        match variant.fields() {
            FieldsData::Named(fields) => {
                let patterns = fields.iter().map(|field| {
                    let identifier = field.identifier();
                    quote!(#identifier)
                });
                let calls = fields.iter().filter_map(|field| {
                    let identifier = field.identifier();
                    let field_name = identifier.to_string();
                    let context = variant_field_context(variant.index(), variant_name, &field_name);
                    writer_field_call(
                        type_name,
                        field.field(),
                        &field_name,
                        &context,
                        field.attributes().mode(),
                        quote!(#identifier),
                        runtime,
                    )
                });
                quote! {
                    Self::#variant_name { #(#patterns),* } => {
                        writer.record(stringify!(#variant_name), |__fields| {
                            #(#calls)*
                        });
                    }
                }
            }
            FieldsData::Unnamed(fields) => {
                let bindings = fields
                    .iter()
                    .map(|field| {
                        format_ident!(
                            "__qubit_redact_field_{}",
                            field.index().index,
                            span = field.field().span(),
                        )
                    })
                    .collect::<Vec<_>>();
                let patterns = fields.iter().zip(&bindings).map(|(field, binding)| {
                    let _ = field;
                    quote!(#binding)
                });
                let calls = fields.iter().zip(&bindings).filter_map(|(field, binding)| {
                    let field_name = field.index().index.to_string();
                    let context = variant_field_context(variant.index(), variant_name, &field_name);
                    writer_field_call(
                        type_name,
                        field.field(),
                        &field_name,
                        &context,
                        field.attributes().mode(),
                        quote!(#binding),
                        runtime,
                    )
                });
                quote! {
                    Self::#variant_name(#(#patterns),*) => {
                        writer.tuple(stringify!(#variant_name), |__fields| {
                            #(#calls)*
                        });
                    }
                }
            }
            FieldsData::Unit => {
                quote! { Self::#variant_name => writer.record(stringify!(#variant_name), |_| {}), }
            }
        }
    });
    quote! {
        match self {
            #(#arms),*
        }
    }
}

/// Generates one structured writer field call.
fn writer_field_call(
    _type_name: &Ident,
    field: &Field,
    field_name: &str,
    _capability_name: &str,
    mode: &FieldMode,
    value: TokenStream,
    runtime: &Path,
) -> Option<TokenStream> {
    let call = match mode {
        FieldMode::Plain => quote! { __fields.unmarked(#field_name, || #value); },
        FieldMode::Level(level) => {
            let level = level.runtime_tokens(runtime);
            quote! { __fields.sensitive(#level, #field_name, || #value); }
        }
        FieldMode::Nested => quote! { __fields.nested(#field_name, #value); },
        FieldMode::Map => {
            quote! { __fields.map_value(#field_name, #value); }
        }
        FieldMode::Json => quote! { __fields.json(#field_name, #value); },
        FieldMode::Skip => quote! { __fields.skipped(#field_name, || #value); },
    };
    Some(quote_spanned! {field.span()=> #call })
}

fn variant_field_context(variant_index: u32, variant_name: &Ident, field_name: &str) -> String {
    format!("{variant_name}_{variant_index}_{field_name}")
}
