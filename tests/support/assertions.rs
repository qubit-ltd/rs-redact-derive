// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared black-box behavior assertions for mirrored derive tests.

#![allow(dead_code)]

use std::collections::BTreeMap;

use qubit_redact::Redact as _;
use qubit_redact::RedactMut as _;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact_derive::Redact;
/// Named record covering plain, sensitive, skipped, and map fields.
#[derive(Redact)]
struct NamedRecord {
    /// Plain field.
    visible: &'static str,
    /// Sensitive field.
    #[redact(level = "secret")]
    secret: String,
    /// Skipped field.
    #[redact(skip)]
    skipped: String,
    /// Key-classified values.
    #[redact(map)]
    metadata: BTreeMap<String, String>,
}

/// Tuple record covering positional parsing.
#[derive(Redact)]
struct TupleRecord(#[redact(level = "secret")] String, #[redact(skip)] String);

/// Enum covering every variant shape.
#[derive(Redact)]
enum Event {
    /// Named variant.
    Named {
        /// Sensitive payload.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Tuple variant.
    Tuple(#[redact(level = "secret")] String),
    /// Unit variant.
    Ready,
}

/// Mutable tuple used by destructive expansion assertions.
#[derive(Redact)]
struct MutableRecord(#[redact(level = "secret")] String);

/// Type receiving generated formatting traits.
#[derive(Redact)]
#[redact(debug, display)]
struct FormattedRecord {
    /// Secret payload.
    #[redact(level = "secret")]
    secret: String,
}

/// Serializable adjacently tagged enum.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind", content = "payload")]
enum SerializableEvent {
    /// Tuple payload.
    Tuple(#[redact(level = "secret")] String),
    /// Unit payload.
    Ready,
}

/// Plain field using a Serde serialization adapter.
#[derive(Redact)]
#[redact(serde)]
struct SerdeAdapterRecord {
    /// Field serialized through a module adapter.
    #[redact(plain)]
    #[serde(with = "serde_adapter")]
    with_value: String,
    /// Field serialized through a direct function adapter.
    #[redact(plain)]
    #[serde(serialize_with = "serde_adapter::serialize")]
    function_value: String,
}

/// Serde adapter used to prove plain-field compatibility.
mod serde_adapter {
    use serde::Serializer;

    /// Serializes one string with an observable adapter prefix.
    pub fn serialize<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("adapted:{value}"))
    }
}

/// Record exercising JSON redaction for formatting, mutation, and Serde.
#[cfg(feature = "test-json")]
#[derive(Redact)]
#[redact(serde)]
struct JsonRecord {
    /// JSON text classified by object keys.
    #[redact(json)]
    document: String,
}

/// Verifies named-field parsing and immutable expansion.
pub fn assert_named_redaction() {
    let value = NamedRecord {
        visible: "shown",
        secret: String::from("raw-secret"),
        skipped: String::from("raw-skipped"),
        metadata: BTreeMap::from([(
            String::from("token"),
            String::from("raw-map"),
        )]),
    };
    let _ = &value.skipped;

    assert_eq!(
        format!("{:?}", value.redacted()),
        r#"NamedRecord { visible: "shown", secret: "<redacted>", metadata: {"token": "****"} }"#,
    );
}

/// Verifies positional input modeling and expansion.
pub fn assert_tuple_redaction() {
    let value =
        TupleRecord(String::from("raw-secret"), String::from("raw-skipped"));
    let TupleRecord(_, skipped) = &value;
    let _ = skipped;

    assert_eq!(
        format!("{:?}", value.redacted()),
        r#"TupleRecord("<redacted>")"#,
    );
}

/// Verifies enum input modeling and shape preservation.
pub fn assert_enum_redaction() {
    let named = Event::Named {
        secret: String::from("raw-secret"),
    };
    let tuple = Event::Tuple(String::from("raw-tuple"));

    assert_eq!(
        format!("{:?}", named.redacted()),
        r#"Named { secret: "<redacted>" }"#,
    );
    assert_eq!(format!("{:?}", tuple.redacted()), r#"Tuple("<redacted>")"#,);
    assert_eq!(format!("{:?}", Event::Ready.redacted()), "Ready");
}

/// Verifies destructive expansion uses the requested sensitivity.
pub fn assert_mutable_redaction() {
    let policy = RedactionPolicy::builder()
        .build()
        .expect("the empty assertion policy is valid");
    let mut value = MutableRecord(String::from("raw-secret"));

    value.redact_in_place_with(&policy);

    let MutableRecord(redacted) = &value;
    assert_eq!(redacted, "<redacted>");
}

/// Verifies generated `Debug` and `Display` delegate to redaction.
pub fn assert_format_expansion() {
    let value = FormattedRecord {
        secret: String::from("raw-secret"),
    };

    assert_eq!(
        format!("{value:?}"),
        r#"FormattedRecord { secret: "<redacted>" }"#,
    );
    assert_eq!(
        format!("{value}"),
        r#"FormattedRecord { secret: "<redacted>" }"#,
    );
}

/// Verifies every accepted sensitivity literal reaches the runtime model.
pub fn assert_sensitivity_expansion() {
    let policy = RedactionPolicy::builder()
        .raise("field", Sensitivity::Secret)
        .expect("the sensitivity assertion field must be valid")
        .build()
        .expect("the sensitivity assertion policy is valid");

    assert_eq!(policy.sensitivity_for("field"), Some(Sensitivity::Secret));
    assert_named_redaction();
}

/// Verifies Serde container, variant, field, and representation expansion.
pub fn assert_serde_expansion() {
    let value = SerializableEvent::Tuple(String::from("raw-secret"));
    let json = serde_json::to_value(value.redacted())
        .expect("redacted adjacent serialization succeeds");

    assert_eq!(
        json,
        serde_json::json!({"kind": "Tuple", "payload": "<redacted>"}),
    );
    assert_eq!(
        serde_json::to_value(SerializableEvent::Ready.redacted())
            .expect("redacted unit serialization succeeds"),
        serde_json::json!({"kind": "Ready"}),
    );
}

/// Verifies plain-field Serde adapters remain active in redacted serialization.
pub fn assert_serde_adapter_expansion() {
    let value = SerdeAdapterRecord {
        with_value: String::from("with"),
        function_value: String::from("function"),
    };
    let json = serde_json::to_value(value.redacted())
        .expect("plain field serde adapters should serialize");

    assert_eq!(
        json,
        serde_json::json!({
            "with_value": "adapted:with",
            "function_value": "adapted:function",
        }),
    );
}

/// Verifies JSON redaction reaches every generated integration boundary.
#[cfg(feature = "test-json")]
pub fn assert_json_expansion() {
    let policy = RedactionPolicy::builder()
        .raise("password", Sensitivity::Secret)
        .expect("the JSON policy field should be valid")
        .build()
        .expect("the JSON policy should build");
    let raw = r#"{"password":"raw-password","name":"Ada"}"#;
    let mut value = JsonRecord {
        document: raw.to_owned(),
    };

    let formatted = format!("{:?}", value.redacted_with(&policy));
    assert!(!formatted.contains("raw-password"));
    assert!(formatted.contains("Ada"));

    let serialized = serde_json::to_value(value.redacted_with(&policy))
        .expect("JSON redacted view should serialize");
    let serialized_text = serialized["document"]
        .as_str()
        .expect("JSON text should retain its outer string shape");
    assert!(!serialized_text.contains("raw-password"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(serialized_text)
            .expect("serialized JSON text should remain valid JSON")["name"],
        "Ada",
    );

    value.redact_in_place_with(&policy);
    assert!(!value.document.contains("raw-password"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&value.document)
            .expect("mutated JSON text should remain valid JSON")["name"],
        "Ada",
    );
}

/// Verifies one fixture is rejected by the public proc-macro boundary.
pub fn assert_compile_fail(fixture: &str) {
    let tests = trybuild::TestCases::new();
    tests.compile_fail(fixture);
}
