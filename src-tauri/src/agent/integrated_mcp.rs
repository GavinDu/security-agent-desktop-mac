//! Trusted Rust-only integration of actual local HTTP planning and owned MCP
//! execution. No production route or global account transition authority.
//! An exclusive connector borrow covers the whole run. Every provider
//! handoff containing observations requires an independent, complete Ask.
use super::{
    local_model::LocalModelProvider,
    structured_planner::StructuredPlanner,
    tool_loop::{
        self, AuthorizedExecutor, LoopAnswer, LoopError, LoopFailure, ModelStep, Observation,
        Planner, ProviderCall,
    },
};
use crate::tools::{
    approvals::{ApprovalEpoch, ApprovalGate},
    mcp_stdio_discovery::OwnedConnector,
};
use serde_json::{json, Value};
use std::{collections::BTreeSet, sync::Arc};

pub(crate) async fn run(
    provider: &LocalModelProvider,
    connector: &mut OwnedConnector,
    prompt: &str,
    allowed_names: &BTreeSet<String>,
) -> Result<LoopAnswer, LoopFailure> {
    let invalid = || LoopFailure {
        reason: LoopError::InvalidAuthority,
        confirmed_executions: 0,
    };
    let catalog = connector.planning_catalog().map_err(|_| invalid())?;
    let available: BTreeSet<String> = catalog
        .openai_functions()
        .iter()
        .filter_map(|tool| tool["function"]["name"].as_str().map(str::to_owned))
        .collect();
    if !allowed_names.is_subset(&available) {
        return Err(invalid());
    }
    let gate = connector.approval_gate();
    let epoch = connector.epoch().map_err(|_| invalid())?;
    let mut planner = ReleasePlanner {
        inner: StructuredPlanner::new(provider, &catalog),
        gate: gate.clone(),
        epoch,
        model: provider.model_name(),
        calls: Vec::new(),
    };
    let mut executor = ConnectorExecutor {
        connector,
        gate: gate.clone(),
        epoch,
    };
    let answer = tool_loop::run(&mut planner, &mut executor, prompt, allowed_names).await?;
    let _lease = gate
        .dispatch_for_epoch(epoch)
        .await
        .map_err(|_| LoopFailure {
            reason: LoopError::InvalidAuthority,
            confirmed_executions: answer.confirmed_executions,
        })?;
    Ok(answer)
}

fn preview(value: &Value) -> Result<String, ()> {
    let bytes = serde_json::to_vec(value).map_err(|_| ())?;
    // Gate also checks the exact escaped size; never truncate a preview.
    if bytes.len() > 8192 {
        return Err(());
    }
    let text: String = bytes
        .iter()
        .flat_map(|&byte| std::ascii::escape_default(byte))
        .map(char::from)
        .collect();
    if text.len() > 8192 {
        return Err(());
    }
    Ok(text)
}

struct ConnectorExecutor<'a> {
    connector: &'a mut OwnedConnector,
    gate: Arc<ApprovalGate>,
    epoch: ApprovalEpoch,
}

impl AuthorizedExecutor for ConnectorExecutor<'_> {
    async fn authorize_and_execute(&mut self, call: &ProviderCall) -> Result<String, ()> {
        let result = self
            .connector
            .call_for_epoch(self.epoch, &call.name, call.arguments.clone())
            .await
            .map_err(|_| ())?;
        serde_json::to_string(&result).map_err(|_| ())
    }

    async fn authorize_disclosure(&mut self, call: &ProviderCall, result: &str) -> bool {
        // A separate release decision, even when execution was Auto.
        let Ok(text) = preview(&json!({
            "decision":"stage result for local model; transmission requires separate approval",
            "id":call.id,"tool":call.name,"result":result
        })) else {
            return false;
        };
        self.gate
            .require_explicit_ask_for_epoch(self.epoch, "agent__stage_result", &text)
            .await
            .is_ok()
    }
}

struct ReleasePlanner<'a> {
    inner: StructuredPlanner<'a>,
    gate: Arc<ApprovalGate>,
    epoch: ApprovalEpoch,
    model: &'a str,
    calls: Vec<ProviderCall>,
}

impl Planner for ReleasePlanner<'_> {
    async fn next(
        &mut self,
        prompt: &str,
        names: &BTreeSet<String>,
        observations: &[Observation],
    ) -> Result<ModelStep, ()> {
        if observations.len() != self.calls.len() || observations.len() > 4 {
            return Err(());
        }
        if !observations.is_empty() {
            let mut transcript = Vec::new();
            for (call, observation) in self.calls.iter().zip(observations) {
                if call.id != observation.id || call.name != observation.name {
                    return Err(());
                }
                transcript.push(json!({"id":call.id,"tool":call.name,
                    "arguments":call.arguments,"result":observation.text}));
            }
            // Approve the exact complete replay batch for this destination,
            // not just the newest result. A denial never invokes HTTP.
            let text = preview(&json!({
                "destination":"configured loopback OpenAI-compatible provider",
                "model":self.model,"tool_transcript":transcript
            }))?;
            self.gate
                .require_explicit_ask_for_epoch(self.epoch, "agent__send_results", &text)
                .await
                .map_err(|_| ())?;
        }
        let _lease = self
            .gate
            .dispatch_for_epoch(self.epoch)
            .await
            .map_err(|_| ())?;
        let step = self.inner.next(prompt, names, observations).await?;
        if let ModelStep::Call(call) = &step {
            self.calls.push(ProviderCall {
                id: call.id.clone(),
                name: call.name.clone(),
                arguments: call.arguments.clone(),
            });
        }
        Ok(step)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::tools::mcp_catalog::McpPolicy;
    use axum::{routing::post, Json, Router};
    use std::{
        path::Path,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use tokio::net::TcpListener;

    const SERVER: &str = r#"
IFS= read -r line || exit 1
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}'
IFS= read -r line || exit 2
IFS= read -r line || exit 3
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read","inputSchema":{"type":"object","additionalProperties":false}},{"name":"hidden","inputSchema":{"type":"object","additionalProperties":false}}]}}'
IFS= read -r line || exit 4
case "$line" in *'"method":"tools/call"'*'"name":"read"'*) ;; *) exit 5 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"FIRST_PRIVATE"}]}}'
IFS= read -r line || exit 6
case "$line" in *'"method":"tools/call"'*'"name":"read"'*) ;; *) exit 7 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"SECOND_PRIVATE"}]}}'
IFS= read -r line
"#;

    #[tokio::test]
    async fn real_http_and_stdio_only_send_approved_batches_including_replay() {
        for (deny_replay, rotate_before_send) in [(true, false), (false, false), (false, true)] {
            let gate = ApprovalGate::new(Default::default());
            let mut events = gate.subscribe();
            let mut connector = OwnedConnector::connect(
                "fixture".into(),
                Path::new("/bin/sh"),
                &["-c".into(), SERVER.into()],
                Path::new("/"),
                gate.clone(),
            )
            .await
            .unwrap();
            connector
                .set_policy("fixture__read", McpPolicy::Auto)
                .unwrap();
            let requests = Arc::new(AtomicUsize::new(0));
            let seen = requests.clone();
            let router = Router::new().route("/v1/chat/completions", post(
                move |Json(body): Json<Value>| {
                    let seen = seen.clone();
                    async move {
                        assert_eq!(body["tools"].as_array().unwrap().len(), 1);
                        assert_eq!(body["tools"][0]["function"]["name"],"fixture__read");
                        let index = seen.fetch_add(1, Ordering::SeqCst);
                        if index > 0 {
                            assert!(body["messages"][2]["content"].as_str().unwrap().contains("FIRST_PRIVATE"));
                        }
                        if index == 2 {
                            assert!(body["messages"][4]["content"].as_str().unwrap().contains("SECOND_PRIVATE"));
                            Json(json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"done"}}]}))
                        } else {
                            Json(json!({"choices":[{"finish_reason":"tool_calls","message":{
                                "role":"assistant","content":null,"tool_calls":[{"id":format!("call{index}"),"type":"function","function":{"name":"fixture__read","arguments":"{}"}}]
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
            let names = BTreeSet::from(["fixture__read".into()]);
            let decisions = async {
                for index in 0..4 {
                    let request =
                        tokio::time::timeout(std::time::Duration::from_secs(5), events.recv())
                            .await
                            .expect("approval fixture timed out")
                            .unwrap();
                    assert_eq!(
                        request.tool,
                        if index % 2 == 0 {
                            "agent__stage_result"
                        } else {
                            "agent__send_results"
                        }
                    );
                    if rotate_before_send && index == 1 {
                        gate.rotate_after_dispatch().await.unwrap();
                        assert!(
                            !gate
                                .resolve(uuid::Uuid::parse_str(&request.id).unwrap(), true)
                                .await
                        );
                        break;
                    }
                    if index == 3 {
                        assert!(request.preview.contains("FIRST_PRIVATE"));
                        assert!(request.preview.contains("SECOND_PRIVATE"));
                    }
                    assert!(
                        gate.resolve(
                            uuid::Uuid::parse_str(&request.id).unwrap(),
                            !(deny_replay && index == 3)
                        )
                        .await
                    );
                }
            };
            let (result, ()) = tokio::join!(
                run(&provider, &mut connector, "question", &names),
                decisions
            );
            if rotate_before_send {
                let error = result.unwrap_err();
                assert_eq!(error.confirmed_executions, 1);
                assert_eq!(requests.load(Ordering::SeqCst), 1);
            } else if deny_replay {
                let error = result.unwrap_err();
                assert_eq!(error.confirmed_executions, 2);
                assert_eq!(error.reason, LoopError::ProviderFailed);
                assert_eq!(requests.load(Ordering::SeqCst), 2);
            } else {
                assert_eq!(result.unwrap().text, "done");
                assert_eq!(requests.load(Ordering::SeqCst), 3);
            }
            connector.shutdown().await.unwrap();
            server.abort();
        }
    }

    #[test]
    fn oversized_escaped_preview_is_denied_not_truncated() {
        assert!(preview(&json!({"result":"x".repeat(8192)})).is_err());
        assert!(preview(&json!({"result":"\\n".repeat(2048)})).is_err());
    }
}
