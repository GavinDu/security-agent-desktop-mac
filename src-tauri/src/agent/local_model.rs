//! First provider slice: text-only inference against an operator-selected local
//! OpenAI-compatible server. Never forward agent credentials or tool results.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};
use tokio::sync::Semaphore;

const MAX_PROMPT_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_TEXT_BYTES: usize = 32 * 1024;
const DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ModelError {
    #[error("Invalid model prompt")]
    InvalidPrompt,
    #[error("Local inference capacity exceeded")]
    Busy,
    #[error("Local inference provider unavailable")]
    Unavailable,
    #[error("Local inference provider timed out")]
    Timeout,
    #[error("Invalid local inference response")]
    InvalidResponse,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Completion {
    pub message: String,
    pub finish_reason: String,
}

pub(crate) struct LocalModelProvider {
    client: reqwest::Client,
    endpoint: String,
    model: String,
    slots: Semaphore,
}

impl LocalModelProvider {
    /// Opt-in only at trusted application startup. No caller-supplied URL.
    pub(crate) fn from_env() -> Result<Option<Self>, String> {
        match std::env::var("SECURITY_AGENT_LOCAL_MODEL") {
            Ok(model) => Self::new(model, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 11434)).map(Some),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err("Invalid local model configuration".into()),
        }
    }

    fn new(model: String, address: SocketAddrV4) -> Result<Self, String> {
        if *address.ip() != Ipv4Addr::LOCALHOST
            || model.is_empty()
            || model.len() > 128
            || !model
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
        {
            return Err("Invalid local model configuration".into());
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(DEADLINE)
            .build()
            .map_err(|_| "Cannot initialize local inference client")?;
        Ok(Self {
            client,
            endpoint: format!("http://{address}/v1/chat/completions"),
            model,
            slots: Semaphore::new(2),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(address: SocketAddrV4) -> Self {
        Self::new("fixture-model".into(), address).unwrap()
    }

    pub(crate) async fn complete(&self, prompt: &str) -> Result<Completion, ModelError> {
        if prompt.trim().is_empty() || prompt.len() > MAX_PROMPT_BYTES {
            return Err(ModelError::InvalidPrompt);
        }
        let _slot = self.slots.try_acquire().map_err(|_| ModelError::Busy)?;
        tokio::time::timeout(DEADLINE, self.request(prompt))
            .await
            .map_err(|_| ModelError::Timeout)?
    }

    async fn request(&self, prompt: &str) -> Result<Completion, ModelError> {
        // No tools, chat history, bearer, Keychain data or caller headers.
        let payload = json!({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": false,
            "max_tokens": 1024
        });
        let mut response = self
            .client
            .post(&self.endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload.to_string())
            .send()
            .await
            .map_err(transport_error)?;
        if !response.status().is_success() {
            return Err(ModelError::Unavailable);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(ModelError::InvalidResponse);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
            if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(bytes.len()) {
                return Err(ModelError::InvalidResponse);
            }
            bytes.extend_from_slice(&chunk);
        }
        parse_completion(&bytes)
    }
}

fn transport_error(error: reqwest::Error) -> ModelError {
    if error.is_timeout() {
        ModelError::Timeout
    } else {
        ModelError::Unavailable
    }
}

#[derive(Deserialize)]
struct ProviderResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: Message,
    finish_reason: String,
}

#[derive(Deserialize)]
struct Message {
    role: String,
    content: Option<String>,
    tool_calls: Option<Vec<Value>>,
    function_call: Option<Value>,
}

fn parse_completion(bytes: &[u8]) -> Result<Completion, ModelError> {
    let response: ProviderResponse =
        serde_json::from_slice(bytes).map_err(|_| ModelError::InvalidResponse)?;
    let [choice] = response.choices.as_slice() else {
        return Err(ModelError::InvalidResponse);
    };
    if choice.message.role != "assistant"
        || choice
            .message
            .tool_calls
            .as_ref()
            .is_some_and(|calls| !calls.is_empty())
        || choice.message.function_call.is_some()
        || !matches!(choice.finish_reason.as_str(), "stop" | "length")
    {
        return Err(ModelError::InvalidResponse);
    }
    let message = choice
        .message
        .content
        .as_ref()
        .filter(|text| !text.trim().is_empty() && text.len() <= MAX_TEXT_BYTES)
        .ok_or(ModelError::InvalidResponse)?;
    Ok(Completion {
        message: message.clone(),
        finish_reason: choice.finish_reason.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, routing::post, Json, Router};
    use tokio::net::TcpListener;

    async fn fixture(router: Router) -> (LocalModelProvider, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let std::net::SocketAddr::V4(address) = listener.local_addr().unwrap() else {
            panic!("expected IPv4 fixture");
        };
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (LocalModelProvider::for_test(address), task)
    }

    #[tokio::test]
    async fn genuine_http_request_returns_only_assistant_text() {
        let router = Router::new().route(
            "/v1/chat/completions",
            post(
                |headers: axum::http::HeaderMap, Json(body): Json<Value>| async move {
                    assert!(!headers.contains_key("authorization"));
                    assert!(!headers.contains_key("cookie"));
                    assert_eq!(
                        body,
                        json!({
                            "model": "fixture-model",
                            "messages": [{"role": "user", "content": "hello"}],
                            "stream": false,
                            "max_tokens": 1024
                        })
                    );
                    Json(json!({"choices": [{
                        "message": {"role": "assistant", "content": "fixture answer"},
                        "finish_reason": "stop"
                    }]}))
                },
            ),
        );
        let (provider, task) = fixture(router).await;
        let answer = provider.complete("hello").await.unwrap();
        assert_eq!(answer.message, "fixture answer");
        assert_eq!(answer.finish_reason, "stop");
        task.abort();
    }

    #[tokio::test]
    async fn rejects_invalid_prompt_and_full_provider_budget() {
        let provider = LocalModelProvider::for_test(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        assert_eq!(provider.complete(" ").await, Err(ModelError::InvalidPrompt));
        assert_eq!(
            provider.complete(&"x".repeat(MAX_PROMPT_BYTES + 1)).await,
            Err(ModelError::InvalidPrompt)
        );
        let _slots = provider.slots.try_acquire_many(2).unwrap();
        assert_eq!(provider.complete("hello").await, Err(ModelError::Busy));
    }

    #[tokio::test]
    async fn rejects_oversized_body_and_redacts_provider_errors() {
        let router = Router::new().route(
            "/v1/chat/completions",
            post(|| async { "x".repeat(MAX_RESPONSE_BYTES + 1) }),
        );
        let (provider, task) = fixture(router).await;
        assert_eq!(
            provider.complete("hello").await,
            Err(ModelError::InvalidResponse)
        );
        task.abort();

        let router = Router::new().route(
            "/v1/chat/completions",
            post(|| async { (StatusCode::BAD_GATEWAY, "private provider diagnostic") }),
        );
        let (provider, task) = fixture(router).await;
        assert_eq!(
            provider.complete("hello").await,
            Err(ModelError::Unavailable)
        );
        task.abort();
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let router = Router::new().route(
            "/v1/chat/completions",
            post(|| async { (StatusCode::TEMPORARY_REDIRECT, [("location", "/other")]) }),
        );
        let (provider, task) = fixture(router).await;
        assert_eq!(
            provider.complete("hello").await,
            Err(ModelError::Unavailable)
        );
        task.abort();
    }

    #[test]
    fn model_output_cannot_request_execution_or_claim_multiple_choices() {
        let good = json!({"choices": [{
            "message": {"role": "assistant", "content": "answer"},
            "finish_reason": "stop"
        }]});
        assert!(parse_completion(good.to_string().as_bytes()).is_ok());
        let mut calls = good.clone();
        calls["choices"][0]["message"]["tool_calls"] = json!([{"id": "unexpected"}]);
        let mut legacy = good.clone();
        legacy["choices"][0]["message"]["function_call"] = json!({"name": "unexpected"});
        let mut wrong_role = good.clone();
        wrong_role["choices"][0]["message"]["role"] = json!("user");
        let mut multiple = good.clone();
        multiple["choices"]
            .as_array_mut()
            .unwrap()
            .push(good["choices"][0].clone());
        for bad in [calls, legacy, wrong_role, multiple, json!({})] {
            assert_eq!(
                parse_completion(bad.to_string().as_bytes()),
                Err(ModelError::InvalidResponse)
            );
        }
    }
}
