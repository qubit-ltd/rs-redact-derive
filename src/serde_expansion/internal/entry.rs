use proc_macro2::TokenStream;
use quote::quote;
use syn::DeriveInput;
use syn::Path;
use syn::Result;

use super::enum_expansion::enum_body;
use super::struct_expansion::struct_body;
use crate::generic_bounds;
use crate::internal::ContainerData;
use crate::serde_container_attributes::SerdeContainerAttributes;

pub(crate) fn expand(
    input: &DeriveInput,
    runtime: &Path,
    serde: Option<&Path>,
    container_attributes: &SerdeContainerAttributes,
    model: &ContainerData<'_>,
) -> Result<TokenStream> {
    let Some(serde) = serde else {
        return Ok(TokenStream::new());
    };

    let serializer = generic_bounds::fresh_identifier(&input.generics, "__QubitRedactSerializer");
    let mut serialization_generics = input.generics.clone();
    generic_bounds::add_serialization_bounds(&mut serialization_generics, model, runtime, serde);
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = serialization_generics.split_for_impl();
    let body = match model {
        ContainerData::Struct(fields) => struct_body(name, fields, runtime, serde, container_attributes),
        ContainerData::Enum(variants) => enum_body(name, variants, runtime, serde, container_attributes, &serializer)?,
    };

    Ok(quote! {
        impl #impl_generics #runtime::domain::internal::RedactSerialize
            for #name #type_generics #where_clause
        {
            fn serialize_redacted<__QubitRedactSerializer>(
                &self,
                serializer: __QubitRedactSerializer,
                policy: &#runtime::RedactionPolicy,
            ) -> ::core::result::Result<__QubitRedactSerializer::Ok, __QubitRedactSerializer::Error>
            where
                __QubitRedactSerializer: #serde::Serializer,
            {
                #runtime::domain::internal::serialize_structured(
                    serializer,
                    policy,
                    |serializer| {
                        #body
                    },
                )
            }
        }
        #runtime::__qubit_redact_serde! {
            impl #impl_generics #serde::Serialize
                for #name #type_generics #where_clause
            {
                fn serialize<#serializer>(
                    &self,
                    serializer: #serializer,
                ) -> ::core::result::Result<#serializer::Ok, #serializer::Error>
                where
                    #serializer: #serde::Serializer,
                {
                    let redactor = #runtime::Redactor::application_default();
                    let policy = redactor.policy();
                    let _scope = #runtime::domain::internal::RedactSerializeScope::new(policy);
                    <Self as #runtime::domain::internal::RedactSerialize>::serialize_redacted(
                        self, serializer, policy,
                    )
                }
            }
        }
    })
}
