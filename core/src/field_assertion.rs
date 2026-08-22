// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Field-scoped capability assertions for generated implementations.

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote_spanned;
use syn::Field;
use syn::GenericArgument;
use syn::GenericParam;
use syn::Ident;
use syn::LifetimeParam;
use syn::Path;
use syn::PathArguments;
use syn::Type;
use syn::spanned::Spanned;

use crate::field_mode::FieldMode;
use crate::generic_bounds;
use crate::immutable_trait_name::ImmutableTraitName;

/// Returns whether `field` has a direct `Option<T>` type.
///
/// # Parameters
///
/// * `field` - Field whose declared type is inspected.
///
/// # Returns
///
/// `true` only when the field type is syntactically `Option<T>`.
pub(crate) fn is_direct_option(field: &Field) -> bool {
    let Type::Path(type_path) = &field.ty else {
        return false;
    };
    let Some(segment) = type_path.path.segments.last() else {
        return false;
    };
    if segment.ident != "Option" {
        return false;
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return false;
    };
    matches!(arguments.args.first(), Some(GenericArgument::Type(_)))
}

/// Generates the immutable capability assertion for one field.
///
/// The helper name carries the owning type, field, and required trait so that
/// rustc trait-bound diagnostics retain actionable domain context.
///
/// # Parameters
///
/// * `type_name` - Type receiving the generated `Redact` implementation.
/// * `field` - Source field supplying the diagnostic span.
/// * `field_name` - Field name or positional index included in the helper name.
/// * `mode` - Explicit redaction mode selecting the required capability.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// A zero-cost local assertion, or no tokens for plain and skipped fields.
pub(crate) fn immutable(
    type_name: &Ident,
    field: &Field,
    field_name: &str,
    mode: &FieldMode,
    runtime: &Path,
) -> TokenStream {
    let helper = helper_name(type_name, field, field_name, mode.immutable_trait_name());
    match mode {
        FieldMode::Plain | FieldMode::Skip => TokenStream::new(),
        FieldMode::Level(sensitivity) => {
            let level = sensitivity.runtime_tokens(runtime);
            quote_spanned! {field.span()=>
                #[allow(non_snake_case)]
                #[allow(clippy::ptr_arg)]
                #[inline(always)]
                fn #helper<'a, 's, 'p, __QubitRedactField>(
                    value: &'a __QubitRedactField,
                    writer: &'s mut #runtime::domain::RedactionWriter<'_, 'p>,
                ) -> #runtime::domain::RedactedValue<'a>
                where
                    __QubitRedactField: #runtime::domain::RedactValue + ?Sized,
                {
                    #runtime::domain::RedactValue::redact_value(
                        value,
                        #level,
                        writer.policy().masking(),
                    )
                }
            }
        }
        FieldMode::Nested => quote_spanned! {field.span()=>
            #[allow(non_snake_case)]
            #[inline(always)]
            fn #helper<'a, 's, 'p, __QubitRedactField>(
                value: &'a __QubitRedactField,
                writer: &'s mut #runtime::domain::RedactionWriter<'_, 'p>,
            ) -> #runtime::domain::RedactedResult<'a, __QubitRedactField>
            where
                __QubitRedactField: #runtime::domain::Redact,
            {
                writer.redacted(value)
            }
        },
        FieldMode::Map => quote_spanned! {field.span()=>
            #[allow(non_snake_case)]
            #[inline(always)]
            fn #helper<
                'a,
                's,
                'p,
                __QubitRedactField,
                __QubitRedactKey: ?Sized,
                __QubitRedactValue: ?Sized,
            >(
                value: &'a __QubitRedactField,
                writer: &'s mut #runtime::domain::RedactionWriter<'_, 'p>,
            ) -> #runtime::domain::RedactedMapResult<
                'a,
                __QubitRedactField,
                __QubitRedactKey,
                __QubitRedactValue,
            >
            where
                __QubitRedactField:
                    #runtime::domain::RedactMapValue<
                        __QubitRedactKey,
                        __QubitRedactValue,
                    > + ?Sized,
            {
                writer.redacted_map(value)
            }
        },
        FieldMode::Json => quote_spanned! {field.span()=>
            #runtime::__qubit_redact_json! {
                #[allow(non_snake_case)]
                #[allow(clippy::ptr_arg)]
                #[inline(always)]
                fn #helper<'a, 's, 'p>(
                    value: &'a ::std::string::String,
                    writer: &'s mut #runtime::domain::RedactionWriter<'_, 'p>,
                ) -> #runtime::RedactedText {
                    writer.redact_json_text(value)
                }
            }
        },
    }
}

/// Generates the destructive capability assertion for one field.
///
/// # Parameters
///
/// * `type_name` - Type receiving the generated `RedactMut` implementation.
/// * `field` - Source field supplying the diagnostic span.
/// * `field_name` - Field name or positional index included in the helper name.
/// * `mode` - Explicit redaction mode selecting the required capability.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// A zero-cost local assertion, or no tokens for plain and skipped fields.
pub(crate) fn mutable(
    type_name: &Ident,
    field: &Field,
    field_name: &str,
    mode: &FieldMode,
    runtime: &Path,
) -> TokenStream {
    let helper = helper_name(type_name, field, field_name, mode.mutable_trait_name());
    match mode {
        FieldMode::Plain | FieldMode::Skip => TokenStream::new(),
        FieldMode::Level(sensitivity) => {
            let level = sensitivity.runtime_tokens(runtime);
            let capability = helper_name(type_name, field, field_name, "RedactValueMutCapability");
            quote_spanned! {field.span()=>
                #[allow(non_camel_case_types)]
                #[diagnostic::on_unimplemented(
                    message = "mutable redaction capability is not implemented for {Self}",
                    label = "this field cannot be redacted in place",
                    note = "if this type only needs immutable redaction, add #[redact(no_mut)] to the derived type",
                )]
                trait #capability: #runtime::RedactValueMut {}

                impl<__QubitRedactField> #capability for __QubitRedactField
                where
                    __QubitRedactField: #runtime::RedactValueMut + ?Sized,
                {}

                #[allow(non_snake_case)]
                #[inline(always)]
                fn #helper<__QubitRedactField>(
                    value: &mut __QubitRedactField,
                    policy: &#runtime::RedactionPolicy,
                )
                where
                    __QubitRedactField: #capability + ?Sized,
                {
                    #runtime::RedactValueMut::redact_value_in_place(
                        value,
                        #level,
                        policy.masking(),
                    );
                }
            }
        }
        FieldMode::Nested => {
            let capability = helper_name(type_name, field, field_name, "RedactMutCapability");
            quote_spanned! {field.span()=>
                #[allow(non_camel_case_types)]
                #[diagnostic::on_unimplemented(
                    message = "mutable redaction capability is not implemented for {Self}",
                    label = "this field cannot be redacted in place",
                    note = "if this type only needs immutable redaction, add #[redact(no_mut)] to the derived type",
                )]
                trait #capability: #runtime::RedactMut {}

                impl<__QubitRedactField> #capability for __QubitRedactField
                where
                    __QubitRedactField: #runtime::RedactMut + ?Sized,
                {}

                #[allow(non_snake_case)]
                #[inline(always)]
                fn #helper<__QubitRedactField>(
                    value: &mut __QubitRedactField,
                    policy: &#runtime::RedactionPolicy,
                )
                where
                    __QubitRedactField: #capability + ?Sized,
                {
                    #runtime::RedactMut::redact_in_place_with(value, policy);
                }
            }
        }
        FieldMode::Map => {
            let capability =
                helper_name(type_name, field, field_name, "RedactMapValueMutCapability");
            quote_spanned! {field.span()=>
                #[allow(non_camel_case_types)]
                #[diagnostic::on_unimplemented(
                    message = "mutable map redaction capability is not implemented for {Self}",
                    label = "this field cannot be redacted in place",
                    note = "if this type only needs immutable redaction, add #[redact(no_mut)] to the derived type",
                )]
                trait #capability<
                    __QubitRedactKey: ?Sized,
                    __QubitRedactValue: ?Sized,
                >: #runtime::RedactMapValueMut<
                    __QubitRedactKey,
                    __QubitRedactValue,
                > {}

                impl<
                    __QubitRedactField,
                    __QubitRedactKey: ?Sized,
                    __QubitRedactValue: ?Sized,
                > #capability<__QubitRedactKey, __QubitRedactValue>
                    for __QubitRedactField
                where
                    __QubitRedactField:
                        #runtime::RedactMapValueMut<
                            __QubitRedactKey,
                            __QubitRedactValue,
                        > + ?Sized,
                {}

                #[allow(non_snake_case)]
                #[inline(always)]
                fn #helper<
                    __QubitRedactField,
                    __QubitRedactKey: ?Sized,
                    __QubitRedactValue: ?Sized,
                >(
                    value: &mut __QubitRedactField,
                    policy: &#runtime::RedactionPolicy,
                )
                where
                    __QubitRedactField:
                        #capability<
                            __QubitRedactKey,
                            __QubitRedactValue,
                        > + ?Sized,
                {
                    #runtime::RedactMapValueMut::redact_map_in_place(value, policy);
                }
            }
        }
        FieldMode::Json => TokenStream::new(),
    }
}

/// Generates the serialization capability assertion for one field.
///
/// The context groups paths and generic metadata shared by all fields in one
/// generated implementation, keeping this field-level API small enough for
/// strict Clippy configurations.
///
/// # Parameters
///
/// * `type_name` - Type receiving the hidden serialization implementation.
/// * `field` - Source field supplying the diagnostic span.
/// * `field_name` - Field name or positional index included in the helper name.
/// * `mode` - Explicit redaction mode selecting the required capability.
/// * `serialize_with` - Optional adapter used by a plain field.
/// * `context` - Shared paths and generics for the owning item.
///
/// # Returns
///
/// A zero-cost local assertion for nested and map fields. Other field modes
/// rely on their ordinary serialization expression.
pub(crate) fn serialization(
    type_name: &Ident,
    field: &Field,
    field_name: &str,
    mode: &FieldMode,
    serialize_with: Option<&Path>,
    context: &crate::serialization_context::SerializationContext<'_>,
) -> TokenStream {
    let runtime = context.runtime;
    let serde = context.serde;
    let generics = context.generics;
    let required_trait = if matches!(mode, FieldMode::Plain) && serialize_with.is_some() {
        "SerializeWith"
    } else {
        mode.serialization_trait_name()
    };
    let helper = helper_name(type_name, field, field_name, required_trait);
    match mode {
        FieldMode::Nested => quote_spanned! {field.span()=>
            #[allow(non_snake_case)]
            #[inline(always)]
            fn #helper<'a, __QubitRedactField>(
                value: &'a __QubitRedactField,
                policy: &'a #runtime::RedactionPolicy,
            ) -> #runtime::internal::RedactedSerialize<'a, __QubitRedactField>
            where
                __QubitRedactField:
                    #runtime::internal::RedactSerialize + ?Sized,
            {
                #runtime::internal::RedactedSerialize::new(value, policy)
            }
        },
        FieldMode::Map => quote_spanned! {field.span()=>
            #[allow(non_snake_case)]
            #[inline(always)]
            fn #helper<
                'a,
                __QubitRedactField,
                __QubitRedactKey: ?Sized,
                __QubitRedactValue: ?Sized,
            >(
                value: &'a __QubitRedactField,
                policy: &'a #runtime::RedactionPolicy,
            ) -> #runtime::domain::RedactedMap<
                'a,
                __QubitRedactField,
                __QubitRedactKey,
                __QubitRedactValue,
            >
            where
                __QubitRedactField:
                    #runtime::internal::RedactMapSerialize<
                        __QubitRedactKey,
                        __QubitRedactValue,
                    > + ?Sized,
            {
                #runtime::domain::RedactedMap::new(value, policy.clone())
            }
        },
        FieldMode::Json => quote_spanned! {field.span()=>
            #runtime::__qubit_redact_json! {
                #[allow(non_snake_case)]
                #[allow(clippy::ptr_arg)]
                #[inline(always)]
                fn #helper<'a>(
                    value: &'a ::std::string::String,
                    policy: &'a #runtime::RedactionPolicy,
                ) -> #runtime::formats::json::RedactedJsonText<'a, 'a> {
                    #runtime::formats::json::RedactedJsonText::new(value, policy)
                }
            }
        },
        FieldMode::Plain => serialize_with.map_or_else(TokenStream::new, |path| {
            let wrapper = format_ident!("{}_carrier", helper, span = field.span(),);
            let field_type = &field.ty;
            let carrier_lifetime = generic_bounds::fresh_lifetime(generics);
            let mut carrier_generics = generic_bounds::generics_for_field(generics, field_type);
            carrier_generics.params.insert(
                0,
                GenericParam::Lifetime(LifetimeParam::new(carrier_lifetime.clone())),
            );
            let serializer =
                generic_bounds::fresh_identifier(&carrier_generics, "__QubitRedactSerializer");
            let carrier_params = &carrier_generics.params;
            let (impl_generics, type_generics, where_clause) = carrier_generics.split_for_impl();
            quote_spanned! {field.span()=>
                #[allow(non_camel_case_types)]
                struct #wrapper<#carrier_params>(
                    &#carrier_lifetime #field_type,
                ) #where_clause;

                impl #impl_generics #serde::Serialize for #wrapper #type_generics #where_clause
                {
                    fn serialize<#serializer>(
                        &self,
                        serializer: #serializer,
                    ) -> ::core::result::Result<
                        #serializer::Ok,
                        #serializer::Error,
                    >
                    where
                        #serializer: #serde::Serializer,
                    {
                        #path(self.0, serializer)
                    }
                }

                #[allow(non_snake_case)]
                #[inline(always)]
                fn #helper #impl_generics(
                    value: &#carrier_lifetime #field_type,
                ) -> #wrapper #type_generics {
                    #wrapper(value)
                }
            }
        }),
        FieldMode::Level(_) | FieldMode::Skip => TokenStream::new(),
    }
}

/// Creates the stable field-context helper identifier for one capability.
///
/// # Parameters
///
/// * `type_name` - Owning type identifier.
/// * `field` - Source field supplying the identifier span.
/// * `field_name` - Field name or positional index.
/// * `required_trait` - Capability name encoded into the helper identifier.
///
/// # Returns
///
/// A normalized identifier suitable for generated local functions.
pub(crate) fn helper_name(
    type_name: &Ident,
    field: &Field,
    field_name: &str,
    required_trait: &str,
) -> Ident {
    let type_fragment = type_name.to_string().replace("r#", "");
    let field_fragment = field_name.replace("r#", "");
    format_ident!(
        "__qubit_redact_{}_{}_requires_{}",
        type_fragment,
        field_fragment,
        required_trait,
        span = field.span(),
    )
}
