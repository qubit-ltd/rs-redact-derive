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

use crate::container_attributes::ContainerAttributes;
use crate::field_assertion;
use crate::field_mode::FieldMode;
use crate::format_expansion;
use crate::generic_bounds;
use crate::input_model;
use crate::internal::ContainerData;
use crate::internal::FieldsData;
use crate::internal::NamedField;
use crate::internal::UnnamedField;
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
pub(crate) fn expand(
    input: &DeriveInput,
    runtime: &Path,
) -> Result<TokenStream> {
    let container_attributes = ContainerAttributes::parse(input)?;
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
    let serde_container_attributes = SerdeContainerAttributes::parse(
        input,
        container_attributes.serde_enabled(),
    )?;
    let serde_impl = serde_expansion::expand(
        input,
        runtime,
        serde.as_ref(),
        &serde_container_attributes,
        &model,
    )?;
    let mut redaction_generics = input.generics.clone();
    generic_bounds::add_immutable_bounds(
        &mut redaction_generics,
        &model,
        runtime,
    );
    let (immutable_assertions, format_body) = match &model {
        ContainerData::Struct(fields) => (
            immutable_assertions(&input.ident, fields, runtime),
            format_body(&input.ident, fields, runtime),
        ),
        ContainerData::Enum(variants) => (
            enum_immutable_assertions(&input.ident, variants, runtime),
            enum_format_body(&input.ident, variants, runtime),
        ),
    };
    let format_impl = format_expansion::expand(
        input,
        runtime,
        &container_attributes,
        &redaction_generics,
    );
    let mutable_impl = if container_attributes.mutable_disabled() {
        TokenStream::new()
    } else {
        crate::redact_mut_expansion::expand(input, runtime, &model)?
    };
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) =
        redaction_generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #runtime::Redact for #name #type_generics #where_clause {
            fn fmt_redacted(
                &self,
                session: &#runtime::RedactionSession<'_>,
                formatter: &mut ::core::fmt::Formatter<'_>,
            ) -> ::core::fmt::Result {
                #(#immutable_assertions)*
                #format_body
            }
        }
        #format_impl
        #serde_impl
        #mutable_impl
    })
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

/// Generates the formatter body for one struct shape.
///
/// # Parameters
///
/// * `type_name` - Type name shown in formatter output.
/// * `fields` - Parsed fields in source order.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// A complete formatter expression for named, tuple, or unit structs.
fn format_body(
    type_name: &Ident,
    fields: &FieldsData<'_>,
    runtime: &Path,
) -> TokenStream {
    match fields {
        FieldsData::Named(fields) => {
            named_format_body(type_name, fields, runtime)
        }
        FieldsData::Unnamed(fields) => {
            unnamed_format_body(type_name, fields, runtime)
        }
        FieldsData::Unit => quote! {
            formatter.write_str(stringify!(#type_name))
        },
    }
}

/// Generates the formatter body for named fields.
///
/// # Parameters
///
/// * `type_name` - Type name shown in formatter output.
/// * `fields` - Parsed named fields in source order.
///
/// # Returns
///
/// A `DebugStruct` expression omitting skipped fields.
fn named_format_body(
    type_name: &Ident,
    fields: &[NamedField<'_>],
    runtime: &Path,
) -> TokenStream {
    let field_calls = fields.iter().map(|parsed| {
        let field = parsed.field();
        let identifier = parsed.identifier();
        let attributes = parsed.attributes();
        let field_name = identifier.to_string();
        match attributes.mode() {
            FieldMode::Plain => quote_spanned! {field.span()=>
                .field(#field_name, &self.#identifier)
            },
            FieldMode::Level(_) | FieldMode::Nested | FieldMode::Map => {
                let helper = field_assertion::helper_name(
                    type_name,
                    field,
                    &field_name,
                    immutable_trait_name(attributes.mode()),
                );
                quote_spanned! {field.span()=>
                    .field(#field_name, &#helper(&self.#identifier, session))
                }
            }
            FieldMode::Json => {
                let helper = field_assertion::helper_name(
                    type_name,
                    field,
                    &field_name,
                    immutable_trait_name(attributes.mode()),
                );
                quote_spanned! {field.span()=>
                    .field(
                        #field_name,
                        &#runtime::__qubit_redact_json!(#helper(&self.#identifier, session)),
                    )
                }
            }
            FieldMode::Skip => TokenStream::new(),
        }
    });
    quote! {
        formatter
            .debug_struct(stringify!(#type_name))
            #(#field_calls)*
            .finish()
    }
}

/// Generates the formatter body for positional fields.
///
/// # Parameters
///
/// * `type_name` - Type name shown in formatter output.
/// * `fields` - Parsed tuple fields in source order.
///
/// # Returns
///
/// A `DebugTuple` expression omitting skipped fields.
fn unnamed_format_body(
    type_name: &Ident,
    fields: &[UnnamedField<'_>],
    runtime: &Path,
) -> TokenStream {
    let field_calls = fields.iter().map(|parsed| {
        let field = parsed.field();
        let index = parsed.index();
        let attributes = parsed.attributes();
        let field_name = index.index.to_string();
        match attributes.mode() {
            FieldMode::Plain => quote_spanned! {field.span()=>
                .field(&self.#index)
            },
            FieldMode::Level(_) | FieldMode::Nested | FieldMode::Map => {
                let helper = field_assertion::helper_name(
                    type_name,
                    field,
                    &field_name,
                    immutable_trait_name(attributes.mode()),
                );
                quote_spanned! {field.span()=>
                    .field(&#helper(&self.#index, session))
                }
            }
            FieldMode::Json => {
                let helper = field_assertion::helper_name(
                    type_name,
                    field,
                    &field_name,
                    immutable_trait_name(attributes.mode()),
                );
                quote_spanned! {field.span()=>
                    .field(
                        &#runtime::__qubit_redact_json!(#helper(&self.#index, session)),
                    )
                }
            }
            FieldMode::Skip => TokenStream::new(),
        }
    });
    quote! {
        formatter
            .debug_tuple(stringify!(#type_name))
            #(#field_calls)*
            .finish()
    }
}

/// Returns the immutable capability name for one field mode.
///
/// # Parameters
///
/// * `mode` - Validated field redaction mode.
///
/// # Returns
///
/// The runtime trait name encoded into generated helper identifiers.
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
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated implementation.
/// * `variants` - Parsed variants in declaration order.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// Zero-cost local capability assertions with variant-qualified names.
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
                        let context = variant_field_context(
                            variant.index(),
                            variant_name,
                            &field_name,
                        );
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
                        let context = variant_field_context(
                            variant.index(),
                            variant_name,
                            &field_name,
                        );
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

/// Generates the formatter match for every enum variant.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated implementation.
/// * `variants` - Parsed variants in declaration order.
///
/// # Returns
///
/// A complete match expression preserving each variant's debug shape.
fn enum_format_body(
    type_name: &Ident,
    variants: &[VariantData<'_>],
    runtime: &Path,
) -> TokenStream {
    let arms = variants.iter().map(|variant| {
        let variant_name = &variant.variant().ident;
        match variant.fields() {
            FieldsData::Named(fields) => {
                enum_named_format_arm(type_name, variant.index(), variant_name, fields, runtime)
            }
            FieldsData::Unnamed(fields) => {
                enum_unnamed_format_arm(type_name, variant.index(), variant_name, fields, runtime)
            }
            FieldsData::Unit => quote! {
                Self::#variant_name => formatter.write_str(stringify!(#variant_name)),
            },
        }
    });
    quote! {
        match self {
            #(#arms)*
        }
    }
}

/// Generates one named enum variant formatter arm.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated implementation.
/// * `variant_index` - Zero-based declaration index of the owning variant.
/// * `variant_name` - Variant name shown in formatter output.
/// * `fields` - Parsed named fields in source order.
///
/// # Returns
///
/// A match arm using `DebugStruct` semantics.
fn enum_named_format_arm(
    type_name: &Ident,
    variant_index: u32,
    variant_name: &Ident,
    fields: &[NamedField<'_>],
    runtime: &Path,
) -> TokenStream {
    let patterns = fields.iter().map(|parsed| {
        let identifier = parsed.identifier();
        if matches!(parsed.attributes().mode(), FieldMode::Skip) {
            quote!(#identifier: _)
        } else {
            quote!(#identifier)
        }
    });
    let field_calls = fields.iter().map(|parsed| {
        let field = parsed.field();
        let identifier = parsed.identifier();
        let mode = parsed.attributes().mode();
        let field_name = identifier.to_string();
        match mode {
            FieldMode::Plain => quote_spanned! {field.span()=>
                .field(#field_name, #identifier)
            },
            FieldMode::Level(_) | FieldMode::Nested | FieldMode::Map => {
                let context = variant_field_context(variant_index, variant_name, &field_name);
                let helper = field_assertion::helper_name(
                    type_name,
                    field,
                    &context,
                    immutable_trait_name(mode),
                );
                quote_spanned! {field.span()=>
                    .field(#field_name, &#helper(#identifier, session))
                }
            }
            FieldMode::Json => {
                let context = variant_field_context(variant_index, variant_name, &field_name);
                let helper = field_assertion::helper_name(
                    type_name,
                    field,
                    &context,
                    immutable_trait_name(mode),
                );
                quote_spanned! {field.span()=>
                    .field(
                        #field_name,
                        &#runtime::__qubit_redact_json!(#helper(#identifier, session)),
                    )
                }
            }
            FieldMode::Skip => TokenStream::new(),
        }
    });
    quote! {
        Self::#variant_name { #(#patterns),* } => formatter
            .debug_struct(stringify!(#variant_name))
            #(#field_calls)*
            .finish(),
    }
}

/// Generates one tuple enum variant formatter arm.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated implementation.
/// * `variant_index` - Zero-based declaration index of the owning variant.
/// * `variant_name` - Variant name shown in formatter output.
/// * `fields` - Parsed positional fields in source order.
///
/// # Returns
///
/// A match arm using `DebugTuple` semantics.
fn enum_unnamed_format_arm(
    type_name: &Ident,
    variant_index: u32,
    variant_name: &Ident,
    fields: &[UnnamedField<'_>],
    runtime: &Path,
) -> TokenStream {
    let bindings = fields
        .iter()
        .map(|parsed| {
            format_ident!(
                "__qubit_redact_field_{}",
                parsed.index().index,
                span = parsed.field().span(),
            )
        })
        .collect::<Vec<_>>();
    let patterns = fields.iter().zip(&bindings).map(|(parsed, binding)| {
        if matches!(parsed.attributes().mode(), FieldMode::Skip) {
            quote!(_)
        } else {
            quote!(#binding)
        }
    });
    let field_calls = fields.iter().zip(&bindings).map(|(parsed, binding)| {
        let field = parsed.field();
        let mode = parsed.attributes().mode();
        match mode {
            FieldMode::Plain => quote_spanned! {field.span()=>
                .field(#binding)
            },
            FieldMode::Level(_) | FieldMode::Nested | FieldMode::Map => {
                let field_name = parsed.index().index.to_string();
                let context = variant_field_context(variant_index, variant_name, &field_name);
                let helper = field_assertion::helper_name(
                    type_name,
                    field,
                    &context,
                    immutable_trait_name(mode),
                );
                quote_spanned! {field.span()=>
                    .field(&#helper(#binding, session))
                }
            }
            FieldMode::Json => {
                let field_name = parsed.index().index.to_string();
                let context = variant_field_context(variant_index, variant_name, &field_name);
                let helper = field_assertion::helper_name(
                    type_name,
                    field,
                    &context,
                    immutable_trait_name(mode),
                );
                quote_spanned! {field.span()=>
                    .field(
                        &#runtime::__qubit_redact_json!(#helper(#binding, session)),
                    )
                }
            }
            FieldMode::Skip => TokenStream::new(),
        }
    });
    quote! {
        Self::#variant_name(#(#patterns),*) => formatter
            .debug_tuple(stringify!(#variant_name))
            #(#field_calls)*
            .finish(),
    }
}

/// Creates a helper-name fragment unique within one enum.
///
/// # Parameters
///
/// * `variant_name` - Owning enum variant.
/// * `variant_index` - Zero-based declaration index of the owning variant.
/// * `field_name` - Field identifier or positional index.
///
/// # Returns
///
/// A stable variant-qualified field context.
#[inline]
fn variant_field_context(
    variant_index: u32,
    variant_name: &Ident,
    field_name: &str,
) -> String {
    format!("{variant_name}_{variant_index}_{field_name}")
}
