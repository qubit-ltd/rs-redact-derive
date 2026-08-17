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
use syn::Ident;
use syn::Path;
use syn::Result;
use syn::spanned::Spanned;

use crate::RedactOptions;
use crate::container_attributes::ContainerAttributes;
use crate::field_assertion;
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

/// Expands a redacted model using integrations supplied by a hosting macro.
///
/// # Parameters
///
/// * `input` - Complete derive input to expand.
/// * `runtime` - Resolved path to the `qubit-redact` runtime crate.
/// * `options` - Optional formatting and serialization integrations to emit.
///
/// # Returns
///
/// Generated immutable, mutable, formatting, and serialization implementations.
///
/// # Errors
///
/// Returns a targeted syntax error when the input shape or enabled attributes
/// are invalid.
pub(crate) fn expand_with_options(
    input: &DeriveInput,
    runtime: &Path,
    options: RedactOptions,
) -> Result<TokenStream> {
    let container_attributes =
        ContainerAttributes::from_options(options.debug, options.display, options.serde);
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
    let model = input_model::parse(
        input,
        "Redact",
        container_attributes.serde_enabled(),
        container_attributes.require_explicit(),
    )?;
    let serde = container_attributes
        .serde_enabled()
        .then(|| serde_path::resolve(input))
        .transpose()?;
    let serde_container_attributes =
        SerdeContainerAttributes::parse(input, container_attributes.serde_enabled())?;
    let serde_impl = serde_expansion::expand(
        input,
        runtime,
        serde.as_ref(),
        &serde_container_attributes,
        &model,
    )?;
    let mut redaction_generics = input.generics.clone();
    generic_bounds::add_immutable_bounds(&mut redaction_generics, &model, runtime);
    let immutable_assertions = match &model {
        ContainerData::Struct(fields) => {
            immutable_assertions(&input.ident, fields, runtime)
        }
        ContainerData::Enum(variants) => {
            enum_immutable_assertions(&input.ident, variants, runtime)
        }
    };
    let write_body = match &model {
        ContainerData::Struct(fields) => {
            writer_struct_body(&input.ident, fields)
        }
        ContainerData::Enum(variants) => {
            writer_enum_body(&input.ident, variants)
        }
    };
    let format_impl =
        format_expansion::expand(input, runtime, &container_attributes, &redaction_generics);
    let mutable_impl = if container_attributes.mutable_disabled() {
        TokenStream::new()
    } else {
        crate::redact_mut_expansion::expand(input, runtime, &model)?
    };
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = redaction_generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #runtime::domain::Redact for #name #type_generics #where_clause {
            fn write_redacted(
                &self,
                writer: &mut #runtime::domain::RedactionWriter<'_, '_>,
            ) {
                #(#immutable_assertions)*
                #write_body
            }
        }
        #format_impl
        #serde_impl
        #mutable_impl
    })
}

/// Generates a structured writer body for one struct.
fn writer_struct_body(
    type_name: &Ident,
    fields: &FieldsData<'_>,
) -> TokenStream {
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
                )
            });
            quote! {
                writer.tuple(stringify!(#type_name), |__fields| {
                    #(#calls)*
                });
            }
        }
        FieldsData::Unit => quote! {
            writer.unit(stringify!(#type_name));
        },
    }
}

/// Generates a structured writer match for one enum.
fn writer_enum_body(
    type_name: &Ident,
    variants: &[VariantData<'_>],
) -> TokenStream {
    let arms = variants.iter().map(|variant| {
        let variant_name = &variant.variant().ident;
        match variant.fields() {
            FieldsData::Named(fields) => {
                let patterns = fields.iter().map(|field| {
                    let identifier = field.identifier();
                    if matches!(field.attributes().mode(), FieldMode::Skip) {
                        quote!(#identifier: _)
                    } else {
                        quote!(#identifier)
                    }
                });
                let calls = fields.iter().filter_map(|field| {
                    let identifier = field.identifier();
                    let field_name = identifier.to_string();
                    let context = variant_field_context(
                        variant.index(),
                        variant_name,
                        &field_name,
                    );
                    writer_field_call(
                        type_name,
                        field.field(),
                        &field_name,
                        &context,
                        field.attributes().mode(),
                        quote!(#identifier),
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
                let bindings = fields.iter().map(|field| {
                    format_ident!(
                        "__qubit_redact_field_{}",
                        field.index().index,
                        span = field.field().span(),
                    )
                }).collect::<Vec<_>>();
                let patterns = fields.iter().zip(&bindings).map(|(field, binding)| {
                    if matches!(field.attributes().mode(), FieldMode::Skip) {
                        quote!(_)
                    } else {
                        quote!(#binding)
                    }
                });
                let calls = fields.iter().zip(&bindings).filter_map(|(field, binding)| {
                    let field_name = field.index().index.to_string();
                    let context = variant_field_context(
                        variant.index(),
                        variant_name,
                        &field_name,
                    );
                    writer_field_call(
                        type_name,
                        field.field(),
                        &field_name,
                        &context,
                        field.attributes().mode(),
                        quote!(#binding),
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
            FieldsData::Unit => quote! {
                Self::#variant_name => writer.unit(stringify!(#variant_name)),
            },
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
    type_name: &Ident,
    field: &syn::Field,
    field_name: &str,
    capability_name: &str,
    mode: &FieldMode,
    value: TokenStream,
) -> Option<TokenStream> {
    if matches!(mode, FieldMode::Skip) {
        return None;
    }
    let call = match mode {
        FieldMode::Plain => quote! {
            __fields.field(#field_name, || #value);
        },
        FieldMode::Level(_) | FieldMode::Nested | FieldMode::Map | FieldMode::Json => {
            let helper = field_assertion::helper_name(
                type_name,
                field,
                capability_name,
                immutable_trait_name(mode),
            );
            let argument = if matches!(mode, FieldMode::Map)
                && field_assertion::is_direct_option(field)
            {
                quote! {
                    __fields.optional_value(
                        #field_name,
                        #value,
                        |__value, __session| {
                            ::std::format!("{:?}", #helper(__value, __session))
                        },
                    );
                }
            } else {
                quote! {
                    __fields.value(#field_name, |__session| {
                        #helper(#value, __session)
                    });
                }
            };
            argument
        }
        FieldMode::Skip => unreachable!(),
    };
    Some(quote_spanned! {field.span()=> #call })
}

/// Returns the immutable capability name for one field mode.
const fn immutable_trait_name(mode: &FieldMode) -> &'static str {
    match mode {
        FieldMode::Level(_) => "RedactValue",
        FieldMode::Nested => "Redact",
        FieldMode::Map => "RedactMapValue",
        FieldMode::Json => "Json",
        FieldMode::Plain | FieldMode::Skip => "Unused",
    }
}

/// Generates immutable capability assertions for every enum variant.
fn enum_immutable_assertions(
    type_name: &Ident,
    variants: &[VariantData<'_>],
    runtime: &Path,
) -> Vec<TokenStream> {
    variants
        .iter()
        .flat_map(|variant| {
            let variant_name = &variant.variant().ident;
            match variant.fields() {
                FieldsData::Named(fields) => fields
                    .iter()
                    .map(|parsed| {
                        let field_name = parsed.identifier().to_string();
                        let context =
                            variant_field_context(variant.index(), variant_name, &field_name);
                        field_assertion::immutable(
                            type_name,
                            parsed.field(),
                            &context,
                            parsed.attributes().mode(),
                            runtime,
                        )
                    })
                    .collect::<Vec<_>>(),
                FieldsData::Unnamed(fields) => fields
                    .iter()
                    .map(|parsed| {
                        let field_name = parsed.index().index.to_string();
                        let context =
                            variant_field_context(variant.index(), variant_name, &field_name);
                        field_assertion::immutable(
                            type_name,
                            parsed.field(),
                            &context,
                            parsed.attributes().mode(),
                            runtime,
                        )
                    })
                    .collect(),
                FieldsData::Unit => Vec::new(),
            }
        })
        .collect()
}

/// Generates immutable capability assertions for one struct shape.
///
/// # Parameters
///
/// * `type_name` - Type receiving the generated implementation.
/// * `fields` - Parsed fields in source order.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// Zero-cost local capability assertions for explicitly redacted fields.
fn immutable_assertions(
    type_name: &Ident,
    fields: &FieldsData<'_>,
    runtime: &Path,
) -> Vec<TokenStream> {
    match fields {
        FieldsData::Named(fields) => fields
            .iter()
            .map(|parsed| {
                let field_name = parsed.identifier().to_string();
                field_assertion::immutable(
                    type_name,
                    parsed.field(),
                    &field_name,
                    parsed.attributes().mode(),
                    runtime,
                )
            })
            .collect(),
        FieldsData::Unnamed(fields) => fields
            .iter()
            .map(|parsed| {
                let field_name = parsed.index().index.to_string();
                field_assertion::immutable(
                    type_name,
                    parsed.field(),
                    &field_name,
                    parsed.attributes().mode(),
                    runtime,
                )
            })
            .collect(),
        FieldsData::Unit => Vec::new(),
    }
}

fn variant_field_context(variant_index: u32, variant_name: &Ident, field_name: &str) -> String {
    format!("{variant_name}_{variant_index}_{field_name}")
}
