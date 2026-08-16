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

use qubit_redact::domain::Redact as RedactTrait;
use qubit_redact::domain::RedactMut;
use qubit_redact::policy::DomainRedactionLimits;
use qubit_redact::RedactionPolicy;
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
    assert_eq!(
        format!("{:?}", maps.redacted()),
        "Maps { hash: {}, tree: {}, optional_tree: None }",
    );

    let mut optional = Maps {
        hash: HashMap::new(),
        tree: BTreeMap::new(),
        optional_tree: Some(BTreeMap::from([(
            "password".to_owned(),
            "raw".to_owned(),
        )])),
    };
    assert_eq!(
        format!("{:?}", optional.redacted()),
        r#"Maps { hash: {}, tree: {}, optional_tree: Some({"password": "<redacted>"}) }"#,
    );
    assert_eq!(
        serde_json::to_value(optional.redacted())
            .expect("optional map should serialize through redaction"),
        serde_json::json!({
            "hash": {},
            "tree": {},
            "optional_tree": {
                "password": "<redacted>",
            },
        }),
    );
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
        "Maps { hash: <truncated>, ...: <truncated> }",
    );
}
