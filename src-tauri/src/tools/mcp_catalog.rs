//! Staged MCP catalog contract. No transport, registry registration, model
//! disclosure, policy mutation or execution is enabled by this module.

use super::mcp_schema::Schema;
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Mutex};
use uuid::Uuid;

const MAX_CONNECTORS: usize = 16;
const MAX_TOOLS_PER_CONNECTOR: usize = 32;
const MAX_TOTAL_TOOLS: usize = 128;
const MAX_FUNCTION_NAME: usize = 64;
const MAX_DESCRIPTION_BYTES: usize = 1024;
const MAX_SCHEMA_BYTES: usize = 16 * 1024;
const MAX_SCHEMA_DEPTH: usize = 16;
const MAX_SCHEMA_NODES: usize = 2048;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CatalogError {
    #[error("Invalid MCP connector identity")]
    InvalidConnector,
    #[error("Invalid MCP tool name")]
    InvalidName,
    #[error("Duplicate MCP tool name")]
    Duplicate,
    #[error("MCP catalog capacity exceeded")]
    Capacity,
    #[error("Invalid MCP tool description")]
    InvalidDescription,
    #[error("Unsupported MCP input schema")]
    InvalidSchema,
    #[error("Unknown MCP tool or invalid arguments")]
    InvalidArguments,
}

pub(crate) struct McpDescriptor {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Value,
}

struct RegisteredTool {
    connector: String,
    remote_name: String,
    function_name: String,
    description: Option<String>,
    input_schema: Value,
    validator: Schema,
}

#[derive(Default)]
pub(crate) struct McpCatalog {
    connectors: BTreeMap<String, BTreeMap<String, RegisteredTool>>,
}

impl McpCatalog {
    /// The caller must supply the trusted connector ID, not a remote-provided
    /// identity. A malformed refresh leaves the entire prior catalog intact.
    pub(crate) fn replace_connector(
        &mut self,
        connector: &str,
        advertised: Vec<McpDescriptor>,
    ) -> Result<(), CatalogError> {
        if !valid_connector(connector) {
            return Err(CatalogError::InvalidConnector);
        }
        let previous = self.connectors.get(connector);
        let prior_count = previous.map_or(0, BTreeMap::len);
        let total: usize = self.connectors.values().map(BTreeMap::len).sum();
        if (previous.is_none() && self.connectors.len() >= MAX_CONNECTORS)
            || advertised.len() > MAX_TOOLS_PER_CONNECTOR
            || total - prior_count + advertised.len() > MAX_TOTAL_TOOLS
        {
            return Err(CatalogError::Capacity);
        }

        let mut replacement = BTreeMap::new();
        for tool in advertised {
            if !valid_tool_name(&tool.name)
                || connector.len() + 2 + tool.name.len() > MAX_FUNCTION_NAME
            {
                return Err(CatalogError::InvalidName);
            }
            if tool
                .description
                .as_ref()
                .is_some_and(|text| text.len() > MAX_DESCRIPTION_BYTES)
            {
                return Err(CatalogError::InvalidDescription);
            }
            validate_schema_metadata(&tool.input_schema)?;
            let validator =
                Schema::compile(&tool.input_schema).ok_or(CatalogError::InvalidSchema)?;
            // Connector IDs cannot contain underscores, so split_once is
            // unambiguous even when the exact remote tool name contains "__".
            let name = format!("{connector}__{}", tool.name);
            let entry = RegisteredTool {
                connector: connector.to_owned(),
                remote_name: tool.name,
                function_name: name.clone(),
                description: tool.description,
                input_schema: tool.input_schema,
                validator,
            };
            if replacement.insert(name, entry).is_some() {
                return Err(CatalogError::Duplicate);
            }
        }
        self.connectors.insert(connector.to_owned(), replacement);
        Ok(())
    }

    /// Merge disjoint, already validated snapshots without granting policy.
    /// Validate capacity and duplicate ownership before mutating the target.
    pub(super) fn merge_disjoint(&mut self, other: Self) -> Result<(), CatalogError> {
        if other.connectors.keys().any(|id| self.connectors.contains_key(id)) {
            return Err(CatalogError::Duplicate);
        }
        if self.connectors.len() + other.connectors.len() > MAX_CONNECTORS
            || self.connectors.values().chain(other.connectors.values()).map(BTreeMap::len).sum::<usize>() > MAX_TOTAL_TOOLS
        {
            return Err(CatalogError::Capacity);
        }
        self.connectors.extend(other.connectors);
        Ok(())
    }

    pub(crate) fn remove_connector(&mut self, connector: &str) -> bool {
        self.connectors.remove(connector).is_some()
    }

    /// Return exact names for a subsequent separately authorized transport
    /// dispatch. A catalog entry is never an approval or a credential.
    pub(crate) fn resolve(&self, function_name: &str) -> Option<(&str, &str)> {
        let (connector, _) = function_name.split_once("__")?;
        let tool = self.connectors.get(connector)?.get(function_name)?;
        Some((&tool.connector, &tool.remote_name))
    }

    /// Validate against the current exact catalog. No authorization is
    /// conveyed by this mapping; a live adapter must fence refresh/removal
    /// and account generation at invocation time.
    pub(crate) fn validate_call(
        &self,
        function_name: &str,
        arguments: &Value,
    ) -> Result<(&str, &str), CatalogError> {
        let (connector, _) = function_name
            .split_once("__")
            .ok_or(CatalogError::InvalidArguments)?;
        let tool = self
            .connectors
            .get(connector)
            .and_then(|tools| tools.get(function_name))
            .ok_or(CatalogError::InvalidArguments)?;
        if !tool.validator.accepts(arguments) {
            return Err(CatalogError::InvalidArguments);
        }
        Ok((&tool.connector, &tool.remote_name))
    }

    /// Stable across refresh order; not automatically exposed to any model.
    pub(crate) fn openai_functions(&self) -> Vec<Value> {
        self.connectors
            .values()
            .flat_map(BTreeMap::values)
            .map(|tool| {
                let mut function = json!({
                    "name": tool.function_name,
                    "parameters": tool.input_schema
                });
                if let Some(description) = &tool.description {
                    function["description"] = json!(description);
                }
                json!({"type": "function", "function": function})
            })
            .collect()
    }
}

// Staged registry authority: connector identity is supplied by a trusted
// host, not model input. No raw transport send is exposed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum McpPolicy {
    Disable,
    Ask,
    Auto,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum AdmissionError {
    #[error("MCP authority unavailable")]
    Unavailable,
    #[error("MCP call denied")]
    Denied,
    #[error("MCP call stale")]
    Stale,
    #[error("MCP catalog rejected")]
    Catalog,
}

struct ConnectorAuthority {
    incarnation: Uuid,
    policies: BTreeMap<String, (McpPolicy, Uuid)>,
}

#[derive(Default)]
struct AuthorityState {
    catalog: McpCatalog,
    connectors: BTreeMap<String, ConnectorAuthority>,
}

#[derive(Default)]
pub(crate) struct McpAuthority {
    state: Mutex<AuthorityState>,
}

// Immutable private fields: caller cannot substitute args after admission.
// This is a proposal, not execution authorization; Ask must be answered
// separately, and a future transport owner must fence the actual handoff.
pub(crate) struct CallPlan {
    connector: String,
    incarnation: Uuid,
    function: String,
    remote: String,
    arguments: Value,
    policy: McpPolicy,
    policy_revision: Uuid,
}

impl CallPlan {
    pub(crate) fn policy(&self) -> McpPolicy {
        self.policy
    }

    pub(crate) fn arguments(&self) -> &Value {
        &self.arguments
    }

    pub(crate) fn function(&self) -> &str {
        &self.function
    }
}

impl McpAuthority {
    /// Metadata snapshot only, filtered to currently enabled exact tools.
    /// The owned connector still revalidates every actual call.
    pub(crate) fn planning_catalog(&self, connector: &str) -> Result<McpCatalog, AdmissionError> {
        let state = self.state.lock().map_err(|_| AdmissionError::Unavailable)?;
        let authority = state
            .connectors
            .get(connector)
            .ok_or(AdmissionError::Denied)?;
        let tools = state
            .catalog
            .connectors
            .get(connector)
            .ok_or(AdmissionError::Denied)?;
        let descriptors = tools
            .values()
            .filter(|tool| {
                authority
                    .policies
                    .get(&tool.function_name)
                    .is_some_and(|(policy, _)| *policy != McpPolicy::Disable)
            })
            .map(|tool| McpDescriptor {
                name: tool.remote_name.clone(),
                description: tool.description.clone(),
                input_schema: tool.input_schema.clone(),
            })
            .collect();
        let mut catalog = McpCatalog::default();
        catalog
            .replace_connector(connector, descriptors)
            .map_err(|_| AdmissionError::Catalog)?;
        Ok(catalog)
    }

    pub(crate) fn replace(
        &self,
        connector: &str,
        tools: Vec<McpDescriptor>,
    ) -> Result<(), AdmissionError> {
        let mut state = self.state.lock().map_err(|_| AdmissionError::Unavailable)?;
        state
            .catalog
            .replace_connector(connector, tools)
            .map_err(|_| AdmissionError::Catalog)?;
        // Even an identical refresh invalidates prior policy and plans.
        state.connectors.insert(
            connector.to_owned(),
            ConnectorAuthority {
                incarnation: Uuid::new_v4(),
                policies: BTreeMap::new(),
            },
        );
        Ok(())
    }

    pub(crate) fn remove(&self, connector: &str) -> Result<(), AdmissionError> {
        let mut state = self.state.lock().map_err(|_| AdmissionError::Unavailable)?;
        state.catalog.remove_connector(connector);
        state.connectors.remove(connector);
        Ok(())
    }

    pub(crate) fn set_policy(
        &self,
        function: &str,
        policy: McpPolicy,
    ) -> Result<(), AdmissionError> {
        let mut state = self.state.lock().map_err(|_| AdmissionError::Unavailable)?;
        let (connector, _) = state
            .catalog
            .resolve(function)
            .ok_or(AdmissionError::Denied)?;
        let connector = connector.to_owned();
        let authority = state
            .connectors
            .get_mut(&connector)
            .ok_or(AdmissionError::Denied)?;
        authority
            .policies
            .insert(function.to_owned(), (policy, Uuid::new_v4()));
        Ok(())
    }

    pub(crate) fn prepare(
        &self,
        function: &str,
        arguments: Value,
    ) -> Result<CallPlan, AdmissionError> {
        let state = self.state.lock().map_err(|_| AdmissionError::Unavailable)?;
        let (connector, remote) = state
            .catalog
            .validate_call(function, &arguments)
            .map_err(|_| AdmissionError::Denied)?;
        let authority = state
            .connectors
            .get(connector)
            .ok_or(AdmissionError::Denied)?;
        let &(policy, policy_revision) = authority
            .policies
            .get(function)
            .ok_or(AdmissionError::Denied)?;
        if policy == McpPolicy::Disable {
            return Err(AdmissionError::Denied);
        }
        Ok(CallPlan {
            connector: connector.to_owned(),
            incarnation: authority.incarnation,
            function: function.to_owned(),
            remote: remote.to_owned(),
            arguments,
            policy,
            policy_revision,
        })
    }

    /// Revalidate at the admission boundary. The result does not grant
    /// execution or disclosure and does not retain the mutex across I/O.
    pub(crate) fn recheck(&self, plan: &CallPlan) -> Result<(), AdmissionError> {
        let state = self.state.lock().map_err(|_| AdmissionError::Unavailable)?;
        let authority = state
            .connectors
            .get(&plan.connector)
            .ok_or(AdmissionError::Stale)?;
        if authority.incarnation != plan.incarnation
            || authority.policies.get(&plan.function) != Some(&(plan.policy, plan.policy_revision))
        {
            return Err(AdmissionError::Stale);
        }
        let mapping = state
            .catalog
            .validate_call(&plan.function, &plan.arguments)
            .map_err(|_| AdmissionError::Stale)?;
        if mapping != (plan.connector.as_str(), plan.remote.as_str()) {
            return Err(AdmissionError::Stale);
        }
        Ok(())
    }
}

pub(super) fn valid_connector(id: &str) -> bool {
    // Lowercase ASCII IDs with no underscores cannot collide with the "__"
    // separator. Reserve both existing builtin connector namespaces.
    !matches!(id, "filesystem" | "bash" | "agent")
        && (1..=32).contains(&id.len())
        && id.as_bytes()[0].is_ascii_lowercase()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_tool_name(name: &str) -> bool {
    (1..=MAX_FUNCTION_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// This checks bounded metadata and the required object root only, NOT
/// general JSON Schema semantics or arguments. Reject schema references
/// conservatively even in nested metadata rather than resolve/fetch them.
fn validate_schema_metadata(schema: &Value) -> Result<(), CatalogError> {
    if !schema.is_object() || schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err(CatalogError::InvalidSchema);
    }
    let mut nodes = MAX_SCHEMA_NODES;
    let mut bytes = MAX_SCHEMA_BYTES;
    walk_schema(schema, 0, &mut nodes, &mut bytes)?;
    // Escapes and JSON structural overhead may expand the encoded form.
    if serde_json::to_vec(schema)
        .map_err(|_| CatalogError::InvalidSchema)?
        .len()
        > MAX_SCHEMA_BYTES
    {
        return Err(CatalogError::InvalidSchema);
    }
    Ok(())
}

fn spend(budget: &mut usize, amount: usize) -> Result<(), CatalogError> {
    *budget = budget
        .checked_sub(amount)
        .ok_or(CatalogError::InvalidSchema)?;
    Ok(())
}

fn walk_schema(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
    bytes: &mut usize,
) -> Result<(), CatalogError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(CatalogError::InvalidSchema);
    }
    spend(nodes, 1)?;
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if matches!(
                    key.as_str(),
                    "$ref" | "$dynamicRef" | "$recursiveRef" | "$schema" | "$id"
                ) {
                    return Err(CatalogError::InvalidSchema);
                }
                spend(bytes, key.len())?;
                walk_schema(child, depth + 1, nodes, bytes)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                walk_schema(child, depth + 1, nodes, bytes)?;
            }
        }
        Value::String(text) => spend(bytes, text.len())?,
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str) -> McpDescriptor {
        McpDescriptor {
            name: name.into(),
            description: Some("fixture description".into()),
            input_schema: json!({
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": false
            }),
        }
    }

    #[test]
    fn namespaces_are_exact_stable_and_do_not_collide_with_builtins() {
        let mut catalog = McpCatalog::default();
        catalog
            .replace_connector("second", vec![tool("Search"), tool("read__file")])
            .unwrap();
        catalog
            .replace_connector("first", vec![tool("Search")])
            .unwrap();
        assert_eq!(catalog.resolve("first__Search"), Some(("first", "Search")));
        assert_eq!(
            catalog.resolve("second__read__file"),
            Some(("second", "read__file"))
        );
        assert_eq!(catalog.resolve("first__search"), None);
        assert_eq!(catalog.resolve("bash__run"), None);
        let functions = catalog.openai_functions();
        assert_eq!(functions[0]["function"]["name"], "first__Search");
        assert_eq!(functions[1]["function"]["name"], "second__Search");
        assert_eq!(functions[2]["function"]["name"], "second__read__file");
        assert_eq!(
            functions[0]["function"]["parameters"],
            tool("Search").input_schema
        );
        for id in ["filesystem", "bash", "First", "a__b", "", "../x", "é"] {
            assert_eq!(
                catalog.replace_connector(id, vec![tool("search")]),
                Err(CatalogError::InvalidConnector)
            );
        }
    }

    #[test]
    fn bad_refresh_rolls_back_and_removal_is_exact() {
        let mut catalog = McpCatalog::default();
        catalog
            .replace_connector("alpha", vec![tool("original")])
            .unwrap();
        catalog
            .replace_connector("beta", vec![tool("original")])
            .unwrap();
        assert_eq!(
            catalog.replace_connector("alpha", vec![tool("new"), tool("new")]),
            Err(CatalogError::Duplicate)
        );
        assert_eq!(catalog.resolve("alpha__new"), None);
        assert!(catalog.resolve("alpha__original").is_some());
        assert_eq!(
            catalog.replace_connector("alpha", vec![tool("bad.name")]),
            Err(CatalogError::InvalidName)
        );
        assert_eq!(
            catalog.replace_connector("alpha", vec![tool(&"x".repeat(64))]),
            Err(CatalogError::InvalidName)
        );
        assert!(catalog.resolve("alpha__original").is_some());
        catalog
            .replace_connector("alpha", vec![tool("replacement")])
            .unwrap();
        assert_eq!(catalog.resolve("alpha__original"), None);
        assert!(catalog.resolve("alpha__replacement").is_some());
        assert!(catalog.remove_connector("alpha"));
        assert!(!catalog.remove_connector("alpha"));
        assert_eq!(catalog.resolve("alpha__replacement"), None);
        assert!(catalog.resolve("beta__original").is_some());
    }

    #[test]
    fn unsafe_or_unbounded_metadata_is_rejected_before_publication() {
        let mut catalog = McpCatalog::default();
        let mut deep = json!("leaf");
        for _ in 0..=MAX_SCHEMA_DEPTH {
            deep = json!([deep]);
        }
        for schema in [
            json!([]),
            json!({"type": "string"}),
            json!({"type": "object", "properties": {"x": {"$ref": "https://invalid.test"}}}),
            json!({"type": "object", "description": "x".repeat(MAX_SCHEMA_BYTES + 1)}),
            json!({"type": "object", "examples": deep}),
            json!({"type": "object", "examples": vec![Value::Null; MAX_SCHEMA_NODES + 1]}),
        ] {
            let mut descriptor = tool("x");
            descriptor.input_schema = schema;
            assert_eq!(
                catalog.replace_connector("alpha", vec![descriptor]),
                Err(CatalogError::InvalidSchema)
            );
        }
        let mut descriptor = tool("x");
        descriptor.description = Some("x".repeat(MAX_DESCRIPTION_BYTES + 1));
        assert_eq!(
            catalog.replace_connector("alpha", vec![descriptor]),
            Err(CatalogError::InvalidDescription)
        );
        assert!(catalog.openai_functions().is_empty());
    }

    #[test]
    fn validated_mapping_tracks_current_catalog_and_bad_refresh_rolls_back() {
        let mut catalog = McpCatalog::default();
        catalog
            .replace_connector("alpha", vec![tool("query")])
            .unwrap();
        assert_eq!(
            catalog.validate_call("alpha__query", &json!({"query":"ok"})),
            Ok(("alpha", "query"))
        );
        for arguments in [
            json!([]),
            json!({}),
            json!({"query":1}),
            json!({"query":"ok","extra":1}),
        ] {
            assert_eq!(
                catalog.validate_call("alpha__query", &arguments),
                Err(CatalogError::InvalidArguments)
            );
        }
        let mut bad = tool("query");
        bad.input_schema["properties"]["query"]["pattern"] = json!("a");
        assert_eq!(
            catalog.replace_connector("alpha", vec![bad]),
            Err(CatalogError::InvalidSchema)
        );
        assert!(catalog
            .validate_call("alpha__query", &json!({"query":"ok"}))
            .is_ok());
        assert!(catalog.remove_connector("alpha"));
        assert_eq!(
            catalog.validate_call("alpha__query", &json!({"query":"ok"})),
            Err(CatalogError::InvalidArguments)
        );
    }

    #[test]
    fn connector_and_total_tool_caps_include_replacements() {
        let mut catalog = McpCatalog::default();
        let tools = |n: usize| (0..n).map(|i| tool(&format!("tool{i}"))).collect();
        assert_eq!(
            catalog.replace_connector("alpha", tools(MAX_TOOLS_PER_CONNECTOR + 1)),
            Err(CatalogError::Capacity)
        );
        for i in 0..4 {
            catalog
                .replace_connector(&format!("connector{i}"), tools(MAX_TOOLS_PER_CONNECTOR))
                .unwrap();
        }
        assert_eq!(catalog.openai_functions().len(), MAX_TOTAL_TOOLS);
        assert_eq!(
            catalog.replace_connector("alpha", vec![tool("x")]),
            Err(CatalogError::Capacity)
        );
        // Replacing at full capacity must not double-count the old catalog.
        catalog
            .replace_connector("connector0", tools(MAX_TOOLS_PER_CONNECTOR))
            .unwrap();
        assert!(catalog.remove_connector("connector0"));
        catalog.replace_connector("alpha", vec![tool("x")]).unwrap();

        let mut empty = McpCatalog::default();
        for i in 0..MAX_CONNECTORS {
            empty
                .replace_connector(&format!("connector{i}"), Vec::new())
                .unwrap();
        }
        assert_eq!(
            empty.replace_connector("overflow", Vec::new()),
            Err(CatalogError::Capacity)
        );
    }

    #[test]
    fn authority_defaults_to_deny_and_invalidates_policy_aba() {
        let authority = McpAuthority::default();
        authority.replace("fixture", vec![tool("search")]).unwrap();
        let name = "fixture__search";
        assert_eq!(
            authority.prepare(name, json!({"query":"x"})).err(),
            Some(AdmissionError::Denied)
        );
        authority.set_policy(name, McpPolicy::Ask).unwrap();
        let plan = authority.prepare(name, json!({"query":"x"})).unwrap();
        assert_eq!(plan.policy(), McpPolicy::Ask);
        assert_eq!(plan.function(), name);
        assert_eq!(plan.arguments(), &json!({"query":"x"}));
        assert_eq!(authority.recheck(&plan), Ok(()));
        assert_eq!(
            authority.prepare(name, json!({"unknown":"x"})).err(),
            Some(AdmissionError::Denied)
        );
        authority.set_policy(name, McpPolicy::Disable).unwrap();
        authority.set_policy(name, McpPolicy::Ask).unwrap();
        assert_eq!(authority.recheck(&plan), Err(AdmissionError::Stale));
    }

    #[test]
    fn refresh_rollback_and_same_name_replacement_are_distinct() {
        let authority = McpAuthority::default();
        let name = "fixture__search";
        authority.replace("fixture", vec![tool("search")]).unwrap();
        authority.set_policy(name, McpPolicy::Auto).unwrap();
        let plan = authority.prepare(name, json!({"query":"x"})).unwrap();
        assert_eq!(
            authority.replace("fixture", vec![tool("search"), tool("search")]),
            Err(AdmissionError::Catalog)
        );
        assert_eq!(authority.recheck(&plan), Ok(()));
        authority.replace("fixture", vec![tool("search")]).unwrap();
        assert_eq!(authority.recheck(&plan), Err(AdmissionError::Stale));
        assert_eq!(
            authority.prepare(name, json!({"query":"x"})).err(),
            Some(AdmissionError::Denied)
        );
        authority.set_policy(name, McpPolicy::Auto).unwrap();
        let next = authority.prepare(name, json!({"query":"x"})).unwrap();
        authority.remove("fixture").unwrap();
        assert_eq!(authority.recheck(&next), Err(AdmissionError::Stale));
    }

    #[test]
    fn poisoned_authority_never_admits_or_rechecks() {
        let authority = McpAuthority::default();
        authority.replace("fixture", vec![tool("search")]).unwrap();
        authority
            .set_policy("fixture__search", McpPolicy::Ask)
            .unwrap();
        let plan = authority
            .prepare("fixture__search", json!({"query":"x"}))
            .unwrap();
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                let _guard = authority.state.lock().unwrap();
                panic!("fixture poison");
            });
            assert!(worker.join().is_err());
        });
        assert_eq!(authority.recheck(&plan), Err(AdmissionError::Unavailable));
        assert_eq!(
            authority
                .prepare("fixture__search", json!({"query":"x"}))
                .err(),
            Some(AdmissionError::Unavailable)
        );
    }
}
