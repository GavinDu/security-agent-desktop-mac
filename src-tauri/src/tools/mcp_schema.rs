//! Deliberately small fail-closed JSON Schema subset for staged MCP tools.
//! Unsupported assertions are rejected, never silently ignored.
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_ARGUMENT_BYTES: usize = 8192;
const MAX_NODES: usize = 1024;
const MAX_DEPTH: usize = 16;

pub(super) enum Schema {
    Object {
        properties: BTreeMap<String, Schema>,
        required: BTreeSet<String>,
    },
    Array(Box<Schema>, usize),
    String(usize),
    Boolean,
    Null,
    Integer,
    Number,
}

impl Schema {
    // Only called after the catalog's bounded metadata traversal.
    pub(super) fn compile(value: &Value) -> Option<Self> {
        let map = value.as_object()?;
        let kind = map.get("type")?.as_str()?;
        let allowed: &[&str] = match kind {
            "object" => &["properties", "required", "additionalProperties"],
            "array" => &["items", "maxItems"],
            "string" => &["maxLength"],
            "boolean" | "null" | "integer" | "number" => &[],
            _ => return None,
        };
        for (key, val) in map {
            match key.as_str() {
                "type" => {}
                "description" | "title" if val.is_string() => {}
                other if allowed.contains(&other) => {}
                _ => return None,
            }
        }
        match kind {
            "object" => {
                if map.get("additionalProperties") != Some(&Value::Bool(false)) {
                    return None;
                }
                let mut properties = BTreeMap::new();
                if let Some(raw) = map.get("properties") {
                    for (name, child) in raw.as_object()? {
                        properties.insert(name.clone(), Self::compile(child)?);
                    }
                }
                let mut required = BTreeSet::new();
                if let Some(raw) = map.get("required") {
                    for name in raw.as_array()? {
                        let name = name.as_str()?;
                        if !properties.contains_key(name) || !required.insert(name.to_owned()) {
                            return None;
                        }
                    }
                }
                Some(Self::Object {
                    properties,
                    required,
                })
            }
            "array" => Some(Self::Array(
                Box::new(Self::compile(map.get("items")?)?),
                optional_max(map.get("maxItems"), MAX_NODES)?,
            )),
            "string" => Some(Self::String(optional_max(
                map.get("maxLength"),
                MAX_ARGUMENT_BYTES,
            )?)),
            "boolean" => Some(Self::Boolean),
            "null" => Some(Self::Null),
            "integer" => Some(Self::Integer),
            "number" => Some(Self::Number),
            _ => None,
        }
    }

    pub(super) fn accepts(&self, arguments: &Value) -> bool {
        let mut nodes = MAX_NODES;
        let mut bytes = MAX_ARGUMENT_BYTES;
        if !bounded(arguments, 0, &mut nodes, &mut bytes) {
            return false;
        }
        // Preflight bounds allocation before accounting for JSON escaping.
        if !serde_json::to_vec(arguments).is_ok_and(|v| v.len() <= MAX_ARGUMENT_BYTES) {
            return false;
        }
        self.matches(arguments)
    }

    fn matches(&self, value: &Value) -> bool {
        match self {
            Self::Object {
                properties,
                required,
            } => value.as_object().is_some_and(|map| {
                required.iter().all(|name| map.contains_key(name))
                    && map.iter().all(|(key, child)| {
                        properties.get(key).is_some_and(|spec| spec.matches(child))
                    })
            }),
            Self::Array(item, max) => value
                .as_array()
                .is_some_and(|items| items.len() <= *max && items.iter().all(|v| item.matches(v))),
            Self::String(max) => value.as_str().is_some_and(|v| v.chars().count() <= *max),
            Self::Boolean => value.is_boolean(),
            Self::Null => value.is_null(),
            // Conservative: do not accept float representations such as 1.0.
            Self::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
            Self::Number => value.is_number(),
        }
    }
}

fn optional_max(value: Option<&Value>, ceiling: usize) -> Option<usize> {
    match value {
        None => Some(ceiling),
        Some(v) => {
            let n = usize::try_from(v.as_u64()?).ok()?;
            Some(n.min(ceiling))
        }
    }
}

fn spend(left: &mut usize, amount: usize) -> bool {
    match left.checked_sub(amount) {
        Some(next) => {
            *left = next;
            true
        }
        None => false,
    }
}

fn bounded(value: &Value, depth: usize, nodes: &mut usize, bytes: &mut usize) -> bool {
    if depth > MAX_DEPTH || !spend(nodes, 1) {
        return false;
    }
    match value {
        Value::Object(map) => map.iter().all(|(key, child)| {
            spend(bytes, key.len()) && bounded(child, depth + 1, nodes, bytes)
        }),
        Value::Array(items) => items
            .iter()
            .all(|child| bounded(child, depth + 1, nodes, bytes)),
        Value::String(text) => spend(bytes, text.len()),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nested_object_and_array_constraints_are_enforced() {
        let schema = Schema::compile(&json!({
            "type":"object", "additionalProperties":false,
            "required":["query","items"],
            "properties":{
                "query":{"type":"string","maxLength":2},
                "items":{"type":"array","maxItems":2,"items":{
                    "type":"object","additionalProperties":false,
                    "required":["count"],
                    "properties":{"count":{"type":"integer"}}
                }},
                "flag":{"type":"boolean"}, "none":{"type":"null"},
                "ratio":{"type":"number"}
            }
        }))
        .unwrap();
        assert!(schema.accepts(&json!({
            "query":"éa","items":[{"count":2}],"flag":true,"none":null,"ratio":1.25
        })));
        for invalid in [
            json!([]),
            json!({"query":"a"}),
            json!({"query":"abc","items":[]}),
            json!({"query":"a","items":[{"count":1.0}]}),
            json!({"query":"a","items":[{"count":1,"extra":0}]}),
            json!({"query":"a","items":[{}, {}, {}]}),
            json!({"query":"a","items":[],"extra":true}),
            json!({"query":"a","items":[],"flag":"true"}),
        ] {
            assert!(!schema.accepts(&invalid));
        }
    }

    #[test]
    fn unsupported_or_malformed_keywords_are_never_ignored() {
        for schema in [
            json!({"type":"object"}),
            json!({"type":"object","additionalProperties":true}),
            json!({"type":"object","additionalProperties":false,"required":["missing"]}),
            json!({"type":"object","additionalProperties":false,"properties":{"x":{"type":"string"}},"required":["x","x"]}),
            json!({"type":"string","pattern":"a"}),
            json!({"type":"string","maxLength":-1}),
            json!({"type":"number","minimum":0}),
            json!({"type":"array","items":[{"type":"string"}]}),
            json!({"type":"object","additionalProperties":false,"oneOf":[]}),
        ] {
            assert!(Schema::compile(&schema).is_none());
        }
    }

    #[test]
    fn aggregate_bounds_apply_before_matching() {
        let schema = Schema::compile(&json!({"type":"string"})).unwrap();
        assert!(!schema.accepts(&json!("x".repeat(MAX_ARGUMENT_BYTES))));
        assert!(!schema.accepts(&json!("\n".repeat(MAX_ARGUMENT_BYTES / 2))));
        let array = Schema::compile(&json!({"type":"array","items":{"type":"null"}})).unwrap();
        assert!(!array.accepts(&json!(vec![Value::Null; MAX_NODES])));
        let mut value = Value::Null;
        for _ in 0..=MAX_DEPTH {
            value = json!([value]);
        }
        assert!(!array.accepts(&value));
    }
}
