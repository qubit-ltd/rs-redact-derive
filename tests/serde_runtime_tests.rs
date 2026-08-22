use std::collections::BTreeMap;
use std::sync::Mutex;

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact_derive::Redact;

static APPLICATION_DEFAULT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Redact)]
#[redact(serde)]
struct Child {
    #[redact(level = "secret")]
    token: String,
}

#[derive(Redact)]
#[redact(serde)]
struct Envelope {
    #[redact(nested)]
    child: Child,
    #[redact(nested)]
    children: Option<Vec<Child>>,
    #[redact(map)]
    headers: BTreeMap<String, String>,
    #[redact(skip)]
    hidden: String,
    #[redact(level = "secret")]
    levels: Vec<String>,
}

#[test]
fn serde_nested_and_map_modes_redact_structured_values() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("token");
            fields.secret_sensitive("authorization");
        })
        .expect("field policy")
        .build()
        .expect("redaction policy");
    let previous = Redactor::replace_application_default(Redactor::new(policy));

    let mut headers = BTreeMap::new();
    headers.insert("authorization".to_owned(), "raw-header".to_owned());
    headers.insert("public".to_owned(), "visible".to_owned());
    let value = Envelope {
        child: Child {
            token: "raw-token".to_owned(),
        },
        children: Some(vec![Child {
            token: "raw-token-2".to_owned(),
        }]),
        headers,
        hidden: "hidden-value".to_owned(),
        levels: vec!["first".to_owned(), "second".to_owned()],
    };

    let encoded = serde_json::to_value(&value).expect("structured serialization");
    assert_ne!(encoded["child"]["token"], "raw-token");
    assert_ne!(encoded["children"][0]["token"], "raw-token-2");
    assert_ne!(encoded["headers"]["authorization"], "raw-header");
    assert_eq!(encoded["headers"]["public"], "visible");
    assert!(encoded.get("hidden").is_none());
    assert_ne!(encoded["levels"][0], "first");
    assert_ne!(encoded["levels"][1], "second");

    let _ = Redactor::replace_application_default(previous);
}

#[test]
fn serde_disabled_mode_restores_level_map_and_skip_values() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let previous = Redactor::replace_application_default(Redactor::new(RedactionPolicy::disabled()));
    assert!(Redactor::application_default().policy().is_disabled());
    let mut headers = BTreeMap::new();
    headers.insert("authorization".to_owned(), "raw-header".to_owned());
    let value = Envelope {
        child: Child {
            token: "raw-token".to_owned(),
        },
        children: Some(vec![Child {
            token: "raw-token-2".to_owned(),
        }]),
        headers,
        hidden: "hidden-value".to_owned(),
        levels: vec!["first".to_owned(), "second".to_owned()],
    };

    let encoded = serde_json::to_value(&value).expect("structured serialization");
    assert_eq!(encoded["child"]["token"], "raw-token");
    assert_eq!(encoded["headers"]["authorization"], "raw-header");
    assert_eq!(encoded["hidden"], "hidden-value");
    assert_eq!(encoded["levels"][0], "first");
    assert_eq!(encoded["levels"][1], "second");

    let _ = Redactor::replace_application_default(previous);
}

#[cfg(feature = "test-json")]
#[derive(Redact)]
#[redact(serde)]
struct JsonEnvelope {
    #[redact(json)]
    payload: String,
}

#[cfg(feature = "test-json")]
#[test]
fn serde_json_mode_redacts_keyed_values_and_preserves_shape() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("token");
        })
        .expect("field policy")
        .build()
        .expect("redaction policy");
    let previous = Redactor::replace_application_default(Redactor::new(policy));

    let value = JsonEnvelope {
        payload: r#"{"token":"raw-token","public":"visible"}"#.to_owned(),
    };
    let encoded = serde_json::to_value(&value).expect("structured JSON serialization");
    assert_ne!(encoded["payload"]["token"], "raw-token");
    assert_eq!(encoded["payload"]["public"], "visible");

    let _ = Redactor::replace_application_default(previous);
}
