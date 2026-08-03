//! The Komms implementation consumes the committed language-neutral kit.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

fn kit_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/v1")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read public conformance JSON"))
        .expect("parse public conformance JSON")
}

fn resolve(value: &Value, completed: &BTreeMap<String, Value>) -> Value {
    let Some(object) = value.as_object() else {
        return match value {
            Value::Array(items) => {
                Value::Array(items.iter().map(|item| resolve(item, completed)).collect())
            }
            _ => value.clone(),
        };
    };
    if object.len() == 1 {
        if let Some(text) = object.get("$utf8_hex").and_then(Value::as_str) {
            return Value::String(hex::encode(text.as_bytes()));
        }
        if let Some(expression) = object.get("$repeat_hex").and_then(Value::as_object) {
            let byte = expression["byte_hex"]
                .as_str()
                .expect("repeat byte is a string");
            let count = expression["bytes"]
                .as_u64()
                .expect("repeat count is an integer") as usize;
            return Value::String(byte.repeat(count));
        }
        if let Some(parts) = object.get("$concat_hex").and_then(Value::as_array) {
            let joined = parts
                .iter()
                .map(|part| {
                    resolve(part, completed)
                        .as_str()
                        .expect("concat part resolves to hex")
                        .to_owned()
                })
                .collect::<String>();
            return Value::String(joined);
        }
        if let Some(expression) = object.get("$pad_hex").and_then(Value::as_object) {
            let prefix = resolve(&expression["prefix_hex"], completed)
                .as_str()
                .expect("pad prefix resolves to hex")
                .to_owned();
            let length = expression["length"]
                .as_u64()
                .expect("pad length is an integer") as usize;
            let byte = expression["byte_hex"]
                .as_str()
                .expect("pad byte is a string");
            let prefix_bytes = prefix.len() / 2;
            return Value::String(prefix + &byte.repeat(length - prefix_bytes));
        }
        if let Some(expression) = object.get("$xor_hex").and_then(Value::as_object) {
            let source = resolve(&expression["value"], completed);
            let mut bytes =
                hex::decode(source.as_str().expect("xor source resolves to hex")).expect("hex");
            let offset = expression["offset"]
                .as_u64()
                .expect("xor offset is an integer") as usize;
            let mask = u8::from_str_radix(
                expression["byte_hex"]
                    .as_str()
                    .expect("xor mask is a string"),
                16,
            )
            .expect("xor mask is hex");
            bytes[offset] ^= mask;
            return Value::String(hex::encode(bytes));
        }
        if let Some(expression) = object.get("$case").and_then(Value::as_object) {
            let case_id = expression["id"].as_str().expect("case id is a string");
            let pointer = expression["pointer"]
                .as_str()
                .expect("case pointer is a string");
            return completed[case_id]
                .pointer(pointer)
                .expect("case pointer resolves")
                .clone();
        }
    }
    Value::Object(
        object
            .iter()
            .map(|(key, item)| (key.clone(), resolve(item, completed)))
            .collect::<Map<_, _>>(),
    )
}

#[test]
fn implementation_matches_every_public_stable_v1_case() {
    let root = kit_root();
    let metadata = read_json(&root.join("kit.json"));
    let files = metadata["case_files"]
        .as_array()
        .expect("case_files is an array");
    let mut completed = BTreeMap::new();
    let mut count = 0usize;

    for relative in files {
        let document = read_json(&root.join(relative.as_str().expect("case path is a string")));
        for case in document["cases"].as_array().expect("cases is an array") {
            let id = case["id"].as_str().expect("case id is a string");
            let expected = case["expected"].clone();
            assert_ne!(expected, Value::Null, "{id} has no committed answer");
            let request = json!({
                "id": id,
                "operation": case["operation"],
                "arguments": resolve(&case["arguments"], &completed)
            });
            let encoded = serde_json::to_vec(&request).expect("encode adapter request");
            let mut actual = kult_conformance::process_request_bytes(&encoded);
            assert_eq!(actual["id"], id, "{id} returned the wrong correlation id");
            actual
                .as_object_mut()
                .expect("adapter response is an object")
                .remove("id");
            assert_eq!(actual, expected, "{id} drifted from the public fixture");
            completed.insert(id.to_owned(), expected);
            count += 1;
        }
    }
    assert_eq!(
        count, 51,
        "case additions must update the explicit kit count"
    );
}
