//! Staged provider-neutral loop. No production route or registry adapter is
//! wired here: callers must establish trusted session authority and a separate
//! data-release boundary before exposing this contract to real tools.

use serde_json::Value;
use std::{collections::BTreeSet, io, time::Duration};

const MAX_PROMPT: usize = 16 * 1024;
const MAX_ANSWER: usize = 32 * 1024;
const MAX_ARGUMENTS: usize = 8 * 1024;
const MAX_OBSERVATION: usize = 8 * 1024;
const MAX_NAMES: usize = 128;
const MAX_CALLS: usize = 4;
const MAX_TURNS: usize = 5;
const MAX_DEPTH: usize = 16;
const MAX_NODES: usize = 1024;
const DEADLINE: Duration = Duration::from_secs(30);

pub(crate) struct ProviderCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

pub(crate) enum ModelStep {
    Answer(String),
    Call(ProviderCall),
}

pub(crate) struct Observation {
    pub id: String,
    pub name: String,
    pub text: String,
}

pub(crate) trait Planner {
    async fn next(
        &mut self,
        prompt: &str,
        allowed_names: &BTreeSet<String>,
        observations: &[Observation],
    ) -> Result<ModelStep, ()>;
}

pub(crate) trait AuthorizedExecutor {
    /// Must recheck the current trusted session, schema and approval before
    /// performing any action. A model's request is never authorization.
    async fn authorize_and_execute(&mut self, call: &ProviderCall) -> Result<String, ()>;

    /// Separate explicit release decision, NOT inferred from execution
    /// approval. Future adapter must also fence stale/revoked results at
    /// actual provider handoff; this staged contract alone cannot do that.
    async fn authorize_disclosure(&mut self, call: &ProviderCall, result: &str) -> bool;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LoopError {
    InvalidPrompt,
    InvalidAuthority,
    InvalidModelStep,
    ProviderFailed,
    ExecutionFailedOrDenied,
    DisclosureDenied,
    BudgetExceeded,
    DeadlineExceeded,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LoopFailure {
    pub reason: LoopError,
    /// Only acknowledged successful tool returns. An interrupted or failed
    /// operation may still have side effects; this is NOT a rollback promise.
    pub confirmed_executions: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LoopAnswer {
    pub text: String,
    pub confirmed_executions: usize,
}

pub(crate) async fn run<P: Planner, E: AuthorizedExecutor>(
    planner: &mut P,
    executor: &mut E,
    prompt: &str,
    allowed_names: &BTreeSet<String>,
) -> Result<LoopAnswer, LoopFailure> {
    run_with_deadline(planner, executor, prompt, allowed_names, DEADLINE).await
}

async fn run_with_deadline<P: Planner, E: AuthorizedExecutor>(
    planner: &mut P,
    executor: &mut E,
    prompt: &str,
    allowed_names: &BTreeSet<String>,
    deadline: Duration,
) -> Result<LoopAnswer, LoopFailure> {
    let mut confirmed = 0;
    let result = tokio::time::timeout(
        deadline,
        run_inner(planner, executor, prompt, allowed_names, &mut confirmed),
    )
    .await
    .unwrap_or(Err(LoopError::DeadlineExceeded));
    match result {
        Ok(text) => Ok(LoopAnswer {
            text,
            confirmed_executions: confirmed,
        }),
        Err(reason) => Err(LoopFailure {
            reason,
            confirmed_executions: confirmed,
        }),
    }
}

async fn run_inner<P: Planner, E: AuthorizedExecutor>(
    planner: &mut P,
    executor: &mut E,
    prompt: &str,
    allowed_names: &BTreeSet<String>,
    confirmed: &mut usize,
) -> Result<String, LoopError> {
    if prompt.trim().is_empty() || prompt.len() > MAX_PROMPT {
        return Err(LoopError::InvalidPrompt);
    }
    if allowed_names.len() > MAX_NAMES || !allowed_names.iter().all(|name| valid_name(name)) {
        return Err(LoopError::InvalidAuthority);
    }

    let mut ids = BTreeSet::new();
    let mut observations = Vec::new();
    for _ in 0..MAX_TURNS {
        let step = planner
            .next(prompt, allowed_names, &observations)
            .await
            .map_err(|_| LoopError::ProviderFailed)?;
        match step {
            ModelStep::Answer(text) => {
                if text.trim().is_empty() || text.len() > MAX_ANSWER {
                    return Err(LoopError::InvalidModelStep);
                }
                return Ok(text);
            }
            ModelStep::Call(call) => {
                if ids.len() >= MAX_CALLS {
                    return Err(LoopError::BudgetExceeded);
                }
                if !valid_token(&call.id, 128)
                    || !valid_name(&call.name)
                    || !allowed_names.contains(&call.name)
                    || !bounded_arguments(&call.arguments)
                    || !ids.insert(call.id.clone())
                {
                    return Err(LoopError::InvalidModelStep);
                }
                let result = executor
                    .authorize_and_execute(&call)
                    .await
                    .map_err(|_| LoopError::ExecutionFailedOrDenied)?;
                *confirmed += 1;
                // Do not call the provider with oversized or unauthorized
                // output, even as an error string. Stop the entire loop.
                if result.len() > MAX_OBSERVATION {
                    return Err(LoopError::BudgetExceeded);
                }
                if !executor.authorize_disclosure(&call, &result).await {
                    return Err(LoopError::DisclosureDenied);
                }
                observations.push(Observation {
                    id: call.id,
                    name: call.name,
                    text: result,
                });
            }
        }
    }
    Err(LoopError::BudgetExceeded)
}

fn valid_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn valid_name(value: &str) -> bool {
    valid_token(value, 64)
        && value
            .split_once("__")
            .is_some_and(|(left, right)| !left.is_empty() && !right.is_empty())
}

fn bounded_arguments(value: &Value) -> bool {
    if !value.is_object() {
        return false;
    }
    let mut nodes = MAX_NODES;
    if !bounded_shape(value, 0, &mut nodes) {
        return false;
    }
    // Stream serialization to a byte-counting sink, not an allocated Vec.
    // Exact schema semantics remain the authorized executor's responsibility.
    serde_json::to_writer(ByteBudget(MAX_ARGUMENTS), value).is_ok()
}

fn bounded_shape(value: &Value, depth: usize, nodes: &mut usize) -> bool {
    if depth > MAX_DEPTH || *nodes == 0 {
        return false;
    }
    *nodes -= 1;
    match value {
        Value::Array(items) => items
            .iter()
            .all(|child| bounded_shape(child, depth + 1, nodes)),
        Value::Object(fields) => fields.iter().all(|(key, child)| {
            key.len() <= MAX_ARGUMENTS && bounded_shape(child, depth + 1, nodes)
        }),
        Value::String(text) => text.len() <= MAX_ARGUMENTS,
        _ => true,
    }
}

struct ByteBudget(usize);

impl io::Write for ByteBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("argument byte budget"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::VecDeque;

    struct FakePlanner {
        steps: VecDeque<ModelStep>,
        seen: Vec<Vec<String>>,
    }

    impl FakePlanner {
        fn new(steps: Vec<ModelStep>) -> Self {
            Self {
                steps: steps.into(),
                seen: Vec::new(),
            }
        }
    }

    impl Planner for FakePlanner {
        async fn next(
            &mut self,
            _prompt: &str,
            _names: &BTreeSet<String>,
            observations: &[Observation],
        ) -> Result<ModelStep, ()> {
            self.seen.push(
                observations
                    .iter()
                    .map(|item| format!("{}:{}:{}", item.id, item.name, item.text))
                    .collect(),
            );
            self.steps.pop_front().ok_or(())
        }
    }

    struct FakeExecutor {
        calls: usize,
        releases: usize,
        execute: bool,
        disclose: bool,
        text: String,
    }

    impl Default for FakeExecutor {
        fn default() -> Self {
            Self {
                calls: 0,
                releases: 0,
                execute: true,
                disclose: true,
                text: "fixture result".into(),
            }
        }
    }

    impl AuthorizedExecutor for FakeExecutor {
        async fn authorize_and_execute(&mut self, _call: &ProviderCall) -> Result<String, ()> {
            self.calls += 1;
            if self.execute {
                Ok(self.text.clone())
            } else {
                Err(())
            }
        }

        async fn authorize_disclosure(&mut self, _call: &ProviderCall, _result: &str) -> bool {
            self.releases += 1;
            self.disclose
        }
    }

    fn call(id: &str, name: &str, arguments: Value) -> ModelStep {
        ModelStep::Call(ProviderCall {
            id: id.into(),
            name: name.into(),
            arguments,
        })
    }

    fn names() -> BTreeSet<String> {
        BTreeSet::from(["fixture__read".into()])
    }

    #[tokio::test]
    async fn provider_receives_only_explicitly_disclosed_result() {
        let mut planner = FakePlanner::new(vec![
            call("one", "fixture__read", json!({"query":"safe"})),
            ModelStep::Answer("answer".into()),
        ]);
        let mut executor = FakeExecutor::default();
        let answer = run(&mut planner, &mut executor, "question", &names())
            .await
            .unwrap();
        assert_eq!(answer.confirmed_executions, 1);
        assert_eq!(answer.text, "answer");
        assert_eq!(executor.calls, 1);
        assert_eq!(executor.releases, 1);
        assert!(planner.seen[0].is_empty());
        assert_eq!(planner.seen[1], vec!["one:fixture__read:fixture result"]);
    }

    #[tokio::test]
    async fn denial_stops_before_provider_can_observe_private_output() {
        for execute in [false, true] {
            let mut planner =
                FakePlanner::new(vec![call("one", "fixture__read", json!({}))]);
            let mut executor = FakeExecutor {
                execute,
                disclose: false,
                text: "PRIVATE_CANARY".into(),
                ..FakeExecutor::default()
            };
            let failure = run(&mut planner, &mut executor, "question", &names())
                .await
                .unwrap_err();
            assert_eq!(
                failure.reason,
                if execute {
                    LoopError::DisclosureDenied
                } else {
                    LoopError::ExecutionFailedOrDenied
                }
            );
            assert_eq!(failure.confirmed_executions, usize::from(execute));
            assert_eq!(executor.releases, usize::from(execute));
            assert_eq!(planner.seen, vec![Vec::<String>::new()]);
        }
    }

    #[tokio::test]
    async fn invalid_names_ids_and_arguments_never_dispatch() {
        for step in [
            call("one", "unknown__read", json!({})),
            call("", "fixture__read", json!({})),
            call("one", "fixture__read", json!([])),
            call("one", "fixture__read", json!({"x":"a".repeat(MAX_ARGUMENTS)})),
        ] {
            let mut planner = FakePlanner::new(vec![step]);
            let mut executor = FakeExecutor::default();
            let failure = run(&mut planner, &mut executor, "question", &names())
                .await
                .unwrap_err();
            assert_eq!(failure.reason, LoopError::InvalidModelStep);
            assert_eq!(executor.calls, 0);
        }

        let mut planner = FakePlanner::new(vec![
            call("same", "fixture__read", json!({})),
            call("same", "fixture__read", json!({})),
        ]);
        let mut executor = FakeExecutor::default();
        let failure = run(&mut planner, &mut executor, "question", &names())
            .await
            .unwrap_err();
        assert_eq!(failure.reason, LoopError::InvalidModelStep);
        assert_eq!(failure.confirmed_executions, 1);
        assert_eq!(executor.calls, 1);
    }

    #[tokio::test]
    async fn tool_budget_and_oversized_results_stop_fail_closed() {
        let mut planner = FakePlanner::new(
            (0..=MAX_CALLS)
                .map(|i| call(&format!("id{i}"), "fixture__read", json!({})))
                .collect(),
        );
        let mut executor = FakeExecutor::default();
        let failure = run(&mut planner, &mut executor, "question", &names())
            .await
            .unwrap_err();
        assert_eq!(failure.reason, LoopError::BudgetExceeded);
        assert_eq!(failure.confirmed_executions, MAX_CALLS);
        assert_eq!(executor.calls, MAX_CALLS);

        let mut planner = FakePlanner::new(vec![call("one", "fixture__read", json!({}))]);
        let mut executor = FakeExecutor {
            text: "x".repeat(MAX_OBSERVATION + 1),
            ..FakeExecutor::default()
        };
        let failure = run(&mut planner, &mut executor, "question", &names())
            .await
            .unwrap_err();
        assert_eq!(failure.reason, LoopError::BudgetExceeded);
        assert_eq!(failure.confirmed_executions, 1);
        assert_eq!(executor.releases, 0);
        assert_eq!(planner.seen.len(), 1);
    }

    #[tokio::test]
    async fn prose_is_not_execution_and_empty_authority_never_dispatches() {
        let mut planner = FakePlanner::new(vec![ModelStep::Answer("I ran a tool".into())]);
        let mut executor = FakeExecutor::default();
        let answer = run(&mut planner, &mut executor, "question", &BTreeSet::new())
            .await
            .unwrap();
        assert_eq!(answer.confirmed_executions, 0);
        assert_eq!(executor.calls, 0);

        let mut planner = FakePlanner::new(vec![call("one", "fixture__read", json!({}))]);
        let failure = run(&mut planner, &mut executor, "question", &BTreeSet::new())
            .await
            .unwrap_err();
        assert_eq!(failure.reason, LoopError::InvalidModelStep);
        assert_eq!(executor.calls, 0);
    }

    struct StalledPlanner;

    impl Planner for StalledPlanner {
        async fn next(
            &mut self,
            _prompt: &str,
            _names: &BTreeSet<String>,
            _observations: &[Observation],
        ) -> Result<ModelStep, ()> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn total_deadline_cancels_wait_without_dispatch() {
        let mut executor = FakeExecutor::default();
        let failure = run_with_deadline(
            &mut StalledPlanner,
            &mut executor,
            "question",
            &names(),
            Duration::from_millis(5),
        )
        .await
        .unwrap_err();
        assert_eq!(failure.reason, LoopError::DeadlineExceeded);
        assert_eq!(failure.confirmed_executions, 0);
        assert_eq!(executor.calls, 0);
    }

    #[test]
    fn argument_shape_bounds_depth_nodes_and_encoded_bytes() {
        let mut deep = json!(null);
        for _ in 0..=MAX_DEPTH {
            deep = json!([deep]);
        }
        assert!(!bounded_arguments(&json!({"x": deep})));
        assert!(!bounded_arguments(&json!({"x": vec![Value::Null; MAX_NODES]})));
        assert!(!bounded_arguments(&json!({"x": "\n".repeat(MAX_ARGUMENTS / 2)})));
        assert!(bounded_arguments(&json!({"x": "valid", "nested": [1, 2]})));
    }
}
