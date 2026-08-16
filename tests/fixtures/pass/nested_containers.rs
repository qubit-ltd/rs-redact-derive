// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Pass fixture for supported nested containers.

use qubit_redact::domain::Redact as RedactTrait;
use qubit_redact::domain::RedactMut;
use qubit_redact::policy::DomainRedactionLimits;
use qubit_redact::RedactionPolicy;
use qubit_redact_derive::Redact;

/// Nested leaf.
#[derive(Redact)]
struct Leaf {
    /// Sensitive value.
    #[redact(level = "secret")]
    value: String,
}

/// Container combinations supported by nested redaction.
#[derive(Redact)]
struct Tree {
    /// Optional nested leaf.
    #[redact(nested)]
    selected: Option<Leaf>,
    /// List of leaves.
    #[redact(nested)]
    leaves: Vec<Leaf>,
}

/// Exercises generated recursive formatting.
fn main() {
    let tree = Tree {
        selected: None,
        leaves: Vec::new(),
    };
    assert_eq!(
        format!("{:?}", tree.redacted()),
        "Tree { selected: None, leaves: [] }",
    );

    let mut selected = Tree {
        selected: Some(Leaf {
            value: "raw-secret".to_owned(),
        }),
        leaves: Vec::new(),
    };
    assert_eq!(
        format!("{:?}", selected.redacted()),
        r#"Tree { selected: Some(Leaf { value: "<redacted>" }), leaves: [] }"#,
    );
    selected.redact_in_place();
    assert_eq!(
        selected
            .selected
            .as_ref()
            .expect("selected leaf should remain present")
            .value,
        "<redacted>",
    );

    let limited = Tree {
        selected: Some(Leaf {
            value: "raw-secret".to_owned(),
        }),
        leaves: Vec::new(),
    };
    let mut builder = RedactionPolicy::builder();
    builder.limits().domain(
        DomainRedactionLimits::builder().max_nodes(2).max_collection_items(1).max_depth(1).build()
            .expect("the fixture domain limits should be valid"),
    );
    let policy = builder
        .build()
        .expect("the fixture redaction policy should be valid");
    assert_eq!(
        format!("{:?}", limited.redacted_with(&policy)),
        "Tree { selected: <truncated>, ...: <truncated> }",
    );
}
