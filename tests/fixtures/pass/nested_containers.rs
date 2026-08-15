// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Pass fixture for supported nested containers.

use qubit_redact::domain::Redact as RedactTrait;
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
    /// Optional boxed leaf.
    #[redact(nested)]
    selected: Option<Box<Leaf>>,
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

    let limited = Tree {
        selected: Some(Box::new(Leaf {
            value: "raw-secret".to_owned(),
        })),
        leaves: Vec::new(),
    };
    let mut builder = RedactionPolicy::builder();
    builder.limits().domain(
        DomainRedactionLimits::new(2, 1, 1)
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
