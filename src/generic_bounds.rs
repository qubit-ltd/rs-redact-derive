// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Generic capability bounds inferred from selected field modes.

use proc_macro2::{
    TokenStream,
    TokenTree,
};
use quote::{
    ToTokens,
    quote,
};
use syn::{
    Field,
    GenericParam,
    Generics,
    Path,
    WherePredicate,
    parse_quote,
};

use crate::{
    field_mode::FieldMode,
    internal::{
        ContainerData,
        FieldsData,
    },
};

/// Adds capability bounds needed by immutable formatting.
///
/// Bounds are added only when a field type refers to one of the input's type
/// parameters. Concrete fields retain the compact impl that existed before
/// bound inference was introduced. Map and JSON modes keep their local
/// capability diagnostics because their required type parameters are not
/// expressible from the field type alone.
///
/// # Parameters
///
/// * `generics` - Input generics plus bounds required by the redaction impl.
/// * `model` - Parsed fields and their selected redaction modes.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Errors
///
/// This helper does not return errors; invalid capability implementations are
/// reported by rustc at the generated impl's field type.
pub(crate) fn add_immutable_bounds(
    generics: &mut Generics,
    model: &ContainerData<'_>,
    runtime: &Path,
) {
    for_each_field(model, &mut |field, mode| match mode {
        FieldMode::Plain => {
            add_trait_bound(generics, field, quote!(::core::fmt::Debug));
        }
        FieldMode::Level(_) => {
            add_trait_bound(generics, field, quote!(#runtime::RedactValue));
        }
        FieldMode::Nested => {
            add_trait_bound(generics, field, quote!(#runtime::Redact));
        }
        FieldMode::Skip | FieldMode::Map | FieldMode::Json => {}
    });
}

/// Adds capability bounds needed by mutable redaction.
///
/// # Parameters
///
/// * `generics` - Input generics plus bounds required by the redaction impl.
/// * `model` - Parsed fields and their selected redaction modes.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Errors
///
/// This helper does not return errors; invalid capability implementations are
/// reported by rustc at the generated impl's field type.
pub(crate) fn add_mutable_bounds(
    generics: &mut Generics,
    model: &ContainerData<'_>,
    runtime: &Path,
) {
    for_each_field(model, &mut |field, mode| match mode {
        FieldMode::Level(_) => {
            add_trait_bound(generics, field, quote!(#runtime::RedactValueMut));
        }
        FieldMode::Nested => {
            add_trait_bound(generics, field, quote!(#runtime::RedactMut));
        }
        FieldMode::Plain
        | FieldMode::Skip
        | FieldMode::Map
        | FieldMode::Json => {}
    });
}

/// Adds capability bounds needed by redacted serialization.
///
/// # Parameters
///
/// * `generics` - Input generics plus bounds required by the serialization
///   impl.
/// * `model` - Parsed fields and their selected redaction modes.
/// * `runtime` - Resolved path to the runtime crate.
/// * `serde` - Resolved direct Serde dependency path.
///
/// # Errors
///
/// This helper does not return errors; invalid capability implementations are
/// reported by rustc at the generated impl's field type.
pub(crate) fn add_serialization_bounds(
    generics: &mut Generics,
    model: &ContainerData<'_>,
    runtime: &Path,
    serde: &Path,
) {
    for_each_field(model, &mut |field, mode| match mode {
        FieldMode::Plain => {
            add_trait_bound(generics, field, quote!(#serde::Serialize));
        }
        FieldMode::Level(_) => {
            add_trait_bound(generics, field, quote!(#runtime::RedactValue));
        }
        FieldMode::Nested => {
            add_trait_bound(
                generics,
                field,
                quote!(#runtime::__private::RedactSerialize),
            );
        }
        FieldMode::Skip | FieldMode::Map | FieldMode::Json => {}
    });
}

/// Visits every parsed field without exposing the container representation to
/// each bound-inference caller.
fn for_each_field(
    model: &ContainerData<'_>,
    callback: &mut impl FnMut(&Field, &FieldMode),
) {
    match model {
        ContainerData::Struct(fields) => for_each_fields(fields, callback),
        ContainerData::Enum(variants) => {
            for variant in variants {
                for_each_fields(variant.fields(), callback);
            }
        }
    }
}

/// Visits one parsed field collection.
fn for_each_fields(
    fields: &FieldsData<'_>,
    callback: &mut impl FnMut(&Field, &FieldMode),
) {
    match fields {
        FieldsData::Named(fields) => {
            for field in fields {
                callback(field.field(), field.attributes().mode());
            }
        }
        FieldsData::Unnamed(fields) => {
            for field in fields {
                callback(field.field(), field.attributes().mode());
            }
        }
        FieldsData::Unit => {}
    }
}

/// Adds one trait predicate when the field type uses an input type parameter.
fn add_trait_bound(
    generics: &mut Generics,
    field: &Field,
    trait_path: TokenStream,
) {
    if !uses_type_parameter(generics, &field.ty) {
        return;
    }
    let field_type = &field.ty;
    let predicate: WherePredicate = parse_quote!(#field_type: #trait_path);
    let candidate = predicate.to_token_stream().to_string();
    let where_clause = generics.make_where_clause();
    if where_clause
        .predicates
        .iter()
        .any(|item| item.to_token_stream().to_string() == candidate)
    {
        return;
    }
    where_clause.predicates.push(predicate);
}

/// Returns whether a field type contains an input type parameter identifier.
fn uses_type_parameter(
    generics: &Generics,
    field_type: &impl ToTokens,
) -> bool {
    let parameters: Vec<String> = generics
        .params
        .iter()
        .filter_map(|parameter| {
            let GenericParam::Type(parameter) = parameter else {
                return None;
            };
            Some(parameter.ident.to_string())
        })
        .collect();
    token_stream_uses_parameter(field_type.to_token_stream(), &parameters)
}

/// Searches a field type's token stream for an input type parameter.
fn token_stream_uses_parameter(
    tokens: TokenStream,
    parameters: &[String],
) -> bool {
    tokens.into_iter().any(|token| {
        let TokenTree::Ident(identifier) = token else {
            return false;
        };
        let name = identifier.to_string();
        parameters.iter().any(|parameter| parameter == &name)
    })
}
