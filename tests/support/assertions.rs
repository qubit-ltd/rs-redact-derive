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
use std::fmt;

use qubit_redact::Redact as _;
use qubit_redact::RedactMut as _;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
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

/// Debug value that detects access to a field rejected by admission.
struct PanicDebug;

impl fmt::Debug for PanicDebug {
    /// Panics whenever an unadmitted field reaches ordinary formatting.
    fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        panic!("an unadmitted field must not be formatted");
    }
}

/// Record proving field admission precedes plain-field access.
#[derive(Redact)]
struct AdmissionRecord {
    /// First field admitted by the two-node budget.
    visible: &'static str,
    /// Second field rejected without reaching `PanicDebug`.
    blocked: PanicDebug,
}

/// Record proving skipped fields neither charge nor access their value.
#[derive(Redact)]
struct SkippedAdmissionRecord {
    /// Omitted value that must not consume one domain node.
    #[redact(skip)]
    skipped: PanicDebug,
    /// Field that remains eligible after the skipped value.
    visible: &'static str,
}

/// Nested leaf that must remain unread after depth rejection.
#[derive(Redact)]
struct DepthLeaf {
    /// Value whose formatter must never run under the depth-one policy.
    blocked: PanicDebug,
}

/// Parent proving nested redaction reuses the surrounding session.
#[derive(Redact)]
struct DepthRoot {
    /// Child rejected when it tries to enter depth two.
    #[redact(nested)]
    child: DepthLeaf,
}

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

/// Enum proving named and tuple field admission precedes formatting.
#[derive(Redact)]
enum GuardedEvent {
    /// Named fields with a rejected second value.
    Named {
        /// First admitted field.
        visible: &'static str,
        /// Rejected field whose formatter must not run.
        blocked: PanicDebug,
    },
    /// Tuple fields with a rejected second value.
    Tuple(&'static str, PanicDebug),
    /// Unit variant that charges no fields.
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

/// Verifies named structs preserve all admitted safe fields.
pub fn assert_named_redaction() {
    let builder = RedactionPolicy::builder()
        .fields(|fields| {
            fields.raise("token", Sensitivity::Secret);
        })
        .expect("the named-record token rule should be valid");
    let policy = builder.build().expect("the named-record policy should be valid");
    let value = NamedRecord {
        visible: "shown",
        secret: String::from("raw-secret"),
        skipped: String::from("raw-skipped"),
        metadata: BTreeMap::from([(String::from("token"), String::from("raw-map"))]),
    };
    let _ = &value.skipped;

    assert_eq!(
        value.redacted_with(&Redactor::new(policy)).text().as_str(),
        r#"NamedRecord { visible: "shown", secret: "<redacted>", metadata: "{\"****\"}" }"#,
    );
}

/// Verifies tuple structs preserve their real shape after redaction.
pub fn assert_tuple_redaction() {
    let value = TupleRecord(String::from("raw-secret"), String::from("raw-skipped"));
    let TupleRecord(_, skipped) = &value;
    let _ = skipped;

    assert_eq!(value.redacted().text().as_str(), r#"TupleRecord("<redacted>")"#,);
}

/// Verifies named, tuple, and unit variants preserve their real shapes.
pub fn assert_enum_redaction() {
    let named = Event::Named {
        secret: String::from("raw-secret"),
    };
    let tuple = Event::Tuple(String::from("raw-tuple"));

    assert_eq!(named.redacted().text().as_str(), r#"Named { secret: "<redacted>" }"#,);
    assert_eq!(tuple.redacted().text().as_str(), r#"Tuple("<redacted>")"#,);
    assert!(Event::Ready.redacted().text().as_str().contains("Ready"));

    let policy = policy_with_domain_limits(2, 1, 1);
    let guarded_named = GuardedEvent::Named {
        visible: "shown",
        blocked: PanicDebug,
    };
    let guarded_tuple = GuardedEvent::Tuple("shown", PanicDebug);
    assert!(
        !guarded_named
            .redacted_with(&Redactor::new(policy.clone()))
            .text()
            .as_str()
            .contains("PanicDebug")
    );
    assert!(
        !guarded_tuple
            .redacted_with(&Redactor::new(policy.clone()))
            .text()
            .as_str()
            .contains("PanicDebug")
    );
    assert!(
        GuardedEvent::Ready
            .redacted_with(&Redactor::new(policy))
            .text()
            .as_str()
            .contains("Ready")
    );
}

/// Verifies rejected and skipped fields are handled before value access.
pub fn assert_field_admission_precedes_access() {
    let policy = policy_with_domain_limits(2, 1, 1);
    let guarded = AdmissionRecord {
        visible: "shown",
        blocked: PanicDebug,
    };
    let skipped = SkippedAdmissionRecord {
        skipped: PanicDebug,
        visible: "shown",
    };
    let _ = &skipped.skipped;

    assert!(
        !guarded
            .redacted_with(&Redactor::new(policy.clone()))
            .text()
            .as_str()
            .contains("PanicDebug")
    );
    assert!(
        !skipped
            .redacted_with(&Redactor::new(policy))
            .text()
            .as_str()
            .contains("PanicDebug")
    );
}

/// Verifies nested fields reuse the parent session and stop at depth limits.
pub fn assert_nested_admission_uses_shared_session() {
    let policy = policy_with_domain_limits(2, 1, 1);
    let value = DepthRoot {
        child: DepthLeaf { blocked: PanicDebug },
    };

    assert!(
        !value
            .redacted_with(&Redactor::new(policy))
            .text()
            .as_str()
            .contains("PanicDebug")
    );
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

/// Verifies generated `Debug` and `Display` preserve the admitted safe shape.
pub fn assert_format_expansion() {
    let value = FormattedRecord {
        secret: String::from("raw-secret"),
    };

    assert_eq!(format!("{value:?}"), r#"FormattedRecord { secret: "<redacted>" }"#,);
    assert_eq!(format!("{value}"), r#"FormattedRecord { secret: "<redacted>" }"#,);
}

/// Builds a policy with exact domain traversal limits for one assertion.
fn policy_with_domain_limits(max_nodes: usize, max_collection_items: usize, max_depth: usize) -> RedactionPolicy {
    let builder = RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_nodes(max_nodes)
                .max_collection_items(max_collection_items)
                .max_depth(max_depth);
        })
        .expect("the assertion redaction limits should be valid");
    builder.build().expect("the assertion redaction policy should be valid")
}

/// Verifies every accepted sensitivity literal reaches the runtime model.
pub fn assert_sensitivity_expansion() {
    let builder = RedactionPolicy::builder()
        .fields(|fields| {
            fields.raise("field", Sensitivity::Secret);
        })
        .expect("the sensitivity assertion field must be valid");
    let policy = builder.build().expect("the sensitivity assertion policy is valid");

    assert_eq!(policy.sensitivity_for("field"), Some(Sensitivity::Secret));
    assert_named_redaction();
}

/// Verifies Serde container, variant, field, and representation expansion.
pub fn assert_serde_expansion() {
    let value = SerializableEvent::Tuple(String::from("raw-secret"));
    let json = serde_json::to_value(value).expect("redacted adjacent serialization succeeds");

    assert_eq!(json, serde_json::json!(r#"Tuple("<redacted>")"#));
    assert!(
        serde_json::to_value(SerializableEvent::Ready)
            .expect("redacted unit serialization succeeds")
            .as_str()
            .is_some_and(|text| text.contains("Ready"))
    );
}

/// Verifies plain-field Serde adapters remain active in redacted serialization.
pub fn assert_serde_adapter_expansion() {
    let value = SerdeAdapterRecord {
        with_value: String::from("with"),
        function_value: String::from("function"),
    };
    let json = serde_json::to_value(value).expect("plain field serde adapters should serialize");

    assert!(
        json.as_str()
            .is_some_and(|text| text.contains("with") && text.contains("function"))
    );
}

/// Verifies JSON redaction reaches every generated integration boundary.
#[cfg(feature = "test-json")]
pub fn assert_json_expansion() {
    let builder = RedactionPolicy::builder()
        .fields(|fields| {
            fields.raise("password", Sensitivity::Secret);
        })
        .expect("the JSON policy field should be valid");
    let policy = builder.build().expect("the JSON policy should build");
    let raw = r#"{"password":"raw-password","name":"Ada"}"#;
    let mut value = JsonRecord {
        document: raw.to_owned(),
    };

    let formatted = value
        .redacted_with(&Redactor::new(policy.clone()))
        .text()
        .as_str()
        .to_owned();
    assert!(!formatted.contains("raw-password"));
    assert!(formatted.contains("Ada"));

    let serialized = serde_json::to_value(&value).expect("JSON redacted view should serialize");
    let serialized_text = serialized
        .as_str()
        .expect("redacted JSON record should serialize as text");
    assert!(!serialized_text.contains("raw-password"));
    assert!(serialized_text.contains("Ada"));

    value.redact_in_place_with(&policy);
    assert!(value.document.contains("raw-password"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&value.document).expect("mutated JSON text should remain valid JSON")
            ["name"],
        "Ada",
    );
}

/// Verifies one fixture is rejected by the public proc-macro boundary.
pub fn assert_compile_fail(fixture: &str) {
    let tests = trybuild::TestCases::new();
    tests.compile_fail(fixture);
}
