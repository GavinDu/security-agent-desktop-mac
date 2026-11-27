//! Real local HTTP planner for the staged bounded loop. No production route:
//! the executor must establish active identity, execution and disclosure
//! authority; replay of previously released observations needs an egress fence.
use super::{
    local_model::LocalModelProvider,
    tool_loop::{ModelStep, Observation, Planner, ProviderCall},
};
use crate::tools::{mcp_catalog::McpCatalog, mcp_wire::decode_unique};
use serde_json::{json, Value};
use std::collections::BTreeSet;

const MAX_CALLS: usize = 4;
const MAX_ARGUMENT_BYTES: usize = 8192;
const MAX_OBSERVATION_BYTES: usize = 8192;
const MAX_PROMPT_BYTES: usize = 16 * 1024;
const MAX_ANSWER_BYTES: usize = 32 * 1024;

pub(crate) struct StructuredPlanner<'a> {
    provider: &'a LocalModelProvider,
    catalog: &'a McpCatalog,
    calls: Vec<ProviderCall>,
    ended: bool,
}

impl<'a> StructuredPlanner<'a> {
    pub(crate) fn new(provider: &'a LocalModelProvider, catalog: &'a McpCatalog) -> Self {
        Self {
            provider,
            catalog,
            calls: Vec::new(),
            ended: false,
        }
    }
}

impl Planner for StructuredPlanner<'_> {
    async fn next(
        &mut self,
        prompt: &str,
        allowed_names: &BTreeSet<String>,
        observations: &[Observation],
    ) -> Result<ModelStep, ()> {
        if self.ended
            || prompt.trim().is_empty()
            || prompt.len() > MAX_PROMPT_BYTES
            || self.calls.len() != observations.len()
            || self.calls.len() > MAX_CALLS
            || allowed_names.len() > 128
        {
            return Err(());
        }
        let tools: Vec<_> = self
            .catalog
            .openai_functions()
            .into_iter()
            .filter(|tool| {
                tool["function"]["name"]
                    .as_str()
                    .is_some_and(|name| allowed_names.contains(name))
            })
            .collect();
        if tools.len() != allowed_names.len() {
            return Err(());
        }

        // The caller supplies only observations accepted by the loop's
        // independent release check. Never append an undisclosed result.
        let mut messages = vec![json!({"role":"user","content":prompt})];
        for (call, observation) in self.calls.iter().zip(observations) {
            if call.id != observation.id
                || call.name != observation.name
                || !allowed_names.contains(&call.name)
                || observation.text.len() > MAX_OBSERVATION_BYTES
            {
                return Err(());
            }
            messages.push(json!({
                "role":"assistant", "content":null,
                "tool_calls":[{
                    "id":call.id, "type":"function",
                    "function":{"name":call.name,"arguments":call.arguments.to_string()}
                }]
            }));
            messages.push(json!({
                "role":"tool", "tool_call_id":call.id, "content":observation.text
            }));
        }
        let mut payload = json!({
            "model":self.provider.model_name(),
            "messages":messages, "stream":false, "max_tokens":1024
        });
        if !tools.is_empty() {
            payload["tools"] = json!(tools);
            payload["tool_choice"] = json!("auto");
        }
        // Fail permanently on any failed/canceled exchange; no replay.
        self.ended = true;
        let bytes = self
            .provider
            .structured_request(&payload)
            .await
            .map_err(|_| ())?;
        let step = parse_step(&bytes)?;
        match &step {
            ModelStep::Answer(_) => {}
            ModelStep::Call(call) => {
                if self.calls.len() == MAX_CALLS
                    || !allowed_names.contains(&call.name)
                    || self.calls.iter().any(|old| old.id == call.id)
                    || self
                        .catalog
                        .validate_call(&call.name, &call.arguments)
                        .is_err()
                {
                    return Err(());
                }
                self.calls.push(ProviderCall {
                    id: call.id.clone(),
                    name: call.name.clone(),
                    arguments: call.arguments.clone(),
                });
                self.ended = false;
            }
        }
        Ok(step)
    }
}

fn parse_step(bytes: &[u8]) -> Result<ModelStep, ()> {
    let value = decode_unique(bytes).map_err(|_| ())?;
    let choices = value.get("choices").and_then(Value::as_array).ok_or(())?;
    let [choice] = choices.as_slice() else {
        return Err(());
    };
    let message = choice.get("message").and_then(Value::as_object).ok_or(())?;
    if message.get("role").and_then(Value::as_str) != Some("assistant")
        || message.get("function_call").is_some_and(|v| !v.is_null())
    {
        return Err(());
    }
    match choice.get("finish_reason").and_then(Value::as_str) {
        Some("stop") => {
            if message
                .get("tool_calls")
                .is_some_and(|v| !v.is_null() && !v.as_array().is_some_and(Vec::is_empty))
            {
                return Err(());
            }
            let text = message.get("content").and_then(Value::as_str).ok_or(())?;
            if text.trim().is_empty() || text.len() > MAX_ANSWER_BYTES {
                return Err(());
            }
            Ok(ModelStep::Answer(text.to_owned()))
        }
        Some("tool_calls") => {
            if message
                .get("content")
                .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
            {
                return Err(());
            }
            let calls = message
                .get("tool_calls")
                .and_then(Value::as_array)
                .ok_or(())?;
            let [call] = calls.as_slice() else {
                return Err(());
            };
            if call.get("type").and_then(Value::as_str) != Some("function") {
                return Err(());
            }
            let id = call.get("id").and_then(Value::as_str).ok_or(())?;
            let function = call.get("function").and_then(Value::as_object).ok_or(())?;
            let name = function.get("name").and_then(Value::as_str).ok_or(())?;
            let raw = function
                .get("arguments")
                .and_then(Value::as_str)
                .ok_or(())?;
            if !token(id, 128) || !token(name, 64) || raw.len() > MAX_ARGUMENT_BYTES {
                return Err(());
            }
            let arguments = decode_unique(raw.as_bytes()).map_err(|_| ())?;
            if !arguments.is_object() {
                return Err(());
            }
            Ok(ModelStep::Call(ProviderCall {
                id: id.to_owned(),
                name: name.to_owned(),
                arguments,
            }))
        }
        _ => Err(()),
    }
}

fn token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent::tool_loop::{self, AuthorizedExecutor, LoopError},
        tools::mcp_catalog::McpDescriptor,
    };
    use axum::{routing::post, Json, Router};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::net::TcpListener;

    fn catalog() -> McpCatalog {
        let mut catalog = McpCatalog::default();
        catalog
            .replace_connector(
                "fixture",
                vec![McpDescriptor {
                    name: "read".into(),
                    description: None,
                    input_schema: json!({"type":"object","properties":{"query":{"type":"string"}},
                                "required":["query"],"additionalProperties":false}),
                }],
            )
            .unwrap();
        catalog
    }

    fn reply(raw: &str) -> Value {
        json!({"choices":[{"finish_reason":"tool_calls","message":{
            "role":"assistant","content":null,"tool_calls":[{
                "id":"call1","type":"function",
                "function":{"name":"fixture__read","arguments":raw}
            }]
        }}]})
    }

    #[test]
    fn malformed_and_duplicate_calls_never_parse_as_execution() {
        for raw in [r#"{"query":"a","query":"b"}"#, "[]", "null", "{}{}"] {
            assert!(parse_step(reply(raw).to_string().as_bytes()).is_err());
        }
        let mut bad = reply(r#"{"query":"x"}"#);
        let duplicate = bad["choices"][0]["message"]["tool_calls"][0].clone();
        bad["choices"][0]["message"]["tool_calls"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(parse_step(bad.to_string().as_bytes()).is_err());
        assert!(parse_step(br#"{"choices":[],"choices":[]}"#).is_err());
        let answer = json!({"choices":[{"finish_reason":"stop","message":{
            "role":"assistant","content":"I ran a tool"
        }}]});
        assert!(matches!(
            parse_step(answer.to_string().as_bytes()),
            Ok(ModelStep::Answer(_))
        ));
    }

    struct FixtureExecutor {
        release: bool,
        calls: usize,
    }

    impl AuthorizedExecutor for FixtureExecutor {
        async fn authorize_and_execute(&mut self, call: &ProviderCall) -> Result<String, ()> {
            assert_eq!(call.name, "fixture__read");
            assert_eq!(call.arguments, json!({"query":"x"}));
            self.calls += 1;
            Ok("PRIVATE_FIXTURE".into())
        }

        async fn authorize_disclosure(&mut self, _: &ProviderCall, _: &str) -> bool {
            self.release
        }
    }

    #[tokio::test]
    async fn real_http_loop_replays_only_explicitly_released_observations() {
        for release in [true, false] {
            let requests = Arc::new(AtomicUsize::new(0));
            let seen = requests.clone();
            let router = Router::new().route("/v1/chat/completions", post(
                move |headers: axum::http::HeaderMap, Json(body): Json<Value>| {
                    let seen = seen.clone();
                    async move {
                        assert!(!headers.contains_key("authorization"));
                        assert!(!headers.contains_key("cookie"));
                        assert_eq!(body["tools"][0]["function"]["name"], "fixture__read");
                        let index = seen.fetch_add(1, Ordering::SeqCst);
                        if index == 0 {
                            assert_eq!(body["messages"], json!([{"role":"user","content":"question"}]));
                            Json(reply(r#"{"query":"x"}"#))
                        } else {
                            assert_eq!(body["messages"][1]["tool_calls"][0]["id"], "call1");
                            assert_eq!(body["messages"][2], json!({
                                "role":"tool","tool_call_id":"call1","content":"PRIVATE_FIXTURE"
                            }));
                            Json(json!({"choices":[{"finish_reason":"stop","message":{
                                "role":"assistant","content":"done"
                            }}]}))
                        }
                    }
                }
            ));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let std::net::SocketAddr::V4(address) = listener.local_addr().unwrap() else {
                panic!("IPv4 fixture");
            };
            let server = tokio::spawn(async move {
                axum::serve(listener, router).await.unwrap();
            });
            let provider = LocalModelProvider::for_test(address);
            let catalog = catalog();
            let mut planner = StructuredPlanner::new(&provider, &catalog);
            let mut executor = FixtureExecutor { release, calls: 0 };
            let result = tool_loop::run(
                &mut planner,
                &mut executor,
                "question",
                &BTreeSet::from(["fixture__read".into()]),
            )
            .await;
            assert_eq!(executor.calls, 1);
            if release {
                assert_eq!(result.unwrap().text, "done");
                assert_eq!(requests.load(Ordering::SeqCst), 2);
            } else {
                assert_eq!(result.unwrap_err().reason, LoopError::DisclosureDenied);
                assert_eq!(requests.load(Ordering::SeqCst), 1);
            }
            server.abort();
        }
    }
}
