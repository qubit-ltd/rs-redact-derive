// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Pass fixture for string-valued map fields.

use std::collections::BTreeMap;
use std::collections::HashMap;

use qubit_redact::Redact as RedactTrait;
use qubit_redact::RedactMut;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

/// Supported standard map types.
#[derive(Redact)]
#[redact(serde)]
struct Maps {
    /// Hash map redacted by runtime keys.
    #[redact(map)]
    hash: HashMap<String, String>,
    /// Ordered map redacted by runtime keys.
    #[redact(map)]
    tree: BTreeMap<String, String>,
    /// Optional ordered map redacted by runtime keys when present.
    #[redact(map)]
    optional_tree: Option<BTreeMap<String, String>>,
}

/// Formats both supported maps.
fn main() {
    let maps = Maps {
        hash: HashMap::new(),
        tree: BTreeMap::new(),
        optional_tree: None,
    };
    assert!(!maps.redacted().text().as_str().contains("raw"));

    let mut optional = Maps {
        hash: HashMap::new(),
        tree: BTreeMap::new(),
        optional_tree: Some(BTreeMap::from([(
            "password".to_owned(),
            "raw".to_owned(),
        )])),
    };
    assert!(!optional.redacted().text().as_str().contains("raw"));
    assert!(serde_json::to_value(optional.redacted())
        .expect("optional map should serialize through redaction")
        .is_string());
    optional.redact_in_place();
    assert_eq!(
        optional
            .optional_tree
            .as_ref()
            .expect("optional map should remain present")["password"],
        "<redacted>",
    );

    let limited = Maps {
        hash: HashMap::from([("token".to_owned(), "raw".to_owned())]),
        tree: BTreeMap::new(),
        optional_tree: Some(BTreeMap::from([(
            "password".to_owned(),
            "raw".to_owned(),
        )])),
    };
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(2).max_collection_items(1).max_depth(1);
        })
        .expect("the fixture redaction policy limits should be valid")
        .build()
        .expect("the fixture redaction policy should be valid");
    assert!(!limited
        .redacted_with(&Redactor::new(policy))
        .text()
        .as_str()
        .contains("raw"));
}
