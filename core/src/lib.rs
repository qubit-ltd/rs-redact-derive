// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

//! Shared expansion implementation for redaction procedural macros.

mod container_attributes;
mod expansion;
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
mod redact_options;
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

pub use expansion::expand;
pub use expansion::expand_with_options;
pub use redact_options::RedactOptions;
