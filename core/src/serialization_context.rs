// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared paths and generic metadata for serialization assertions.

// qubit-style: allow source-test-pair
use syn::Generics;
use syn::Path;

/// Context shared by serialization capability assertions for one item.
pub(crate) struct SerializationContext<'a> {
    /// Resolved path to the runtime crate.
    pub(crate) runtime: &'a Path,
    /// Resolved path to the direct Serde dependency.
    pub(crate) serde: &'a Path,
    /// Generics declared by the owning item.
    pub(crate) generics: &'a Generics,
}
