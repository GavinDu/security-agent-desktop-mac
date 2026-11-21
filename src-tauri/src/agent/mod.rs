pub mod rate_limit;
pub mod server;

use crate::{
    settings::AgentSettings,
    tools::{approvals::ApprovalGate, registry::ToolRegistry},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{atomic::AtomicBool, Arc},
};
use tokio::sync::{Mutex, RwLock, Semaphore};

/// Maximum number of simultaneously admitted authenticated tool requests.
pub const MAX_CONCURRENT_TOOL_REQUESTS: usize = 16;

pub struct AgentState {
    pub token: String,
    pub online: AtomicBool,
    pub bind: SocketAddr,
    pub registry: Arc<ToolRegistry>,
    pub gate: Arc<ApprovalGate>,
    pub dispatch_permits: Arc<Semaphore>,
    pub(crate) source_rate_limiter: rate_limit::SourceRateLimiter,
    pub settings: Mutex<AgentSettings>,
    listener_error: RwLock<Option<String>>,
}

impl AgentState {
    pub fn new(
        token: String,
        bind: SocketAddr,
        settings: AgentSettings,
    ) -> Result<Arc<Self>, String> {
        // Missing Authorization headers parse to empty, and direct callers
        // must not be able to construct an empty-token or LAN-bound server.
        if token.trim().is_empty() {
            return Err("Agent authentication token is unavailable".into());
        }
        if !allowed_agent_bind(bind) {
            return Err("Unsupported local agent bind address".into());
        }
        let roots = ToolRegistry::canonical_roots(&settings.allowed_roots)?;
        let gate = ApprovalGate::new(settings.policies.clone());
        let registry = Arc::new(ToolRegistry::new(roots, gate.clone()));
        Ok(Arc::new(Self {
            token,
            online: AtomicBool::new(false),
            bind,
            registry,
            gate,
            dispatch_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_TOOL_REQUESTS)),
            source_rate_limiter: rate_limit::SourceRateLimiter::default(),
            settings: Mutex::new(settings),
            listener_error: RwLock::new(None),
        }))
    }

    /// Export an operator-safe status, without credentials or OS paths.
    pub async fn status_snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "binding": self.bind.to_string(),
            "vpn_active": false,
            "online": self.online.load(std::sync::atomic::Ordering::SeqCst),
            "error": self.listener_error.read().await.clone(),
        })
    }

    pub async fn mark_listener_online(&self) {
        *self.listener_error.write().await = None;
        self.online.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub async fn mark_listener_failed(&self, error: &std::io::Error) {
        let message = match error.kind() {
            std::io::ErrorKind::AddrInUse => "Local agent port 8080 is already in use",
            std::io::ErrorKind::AddrNotAvailable => "Local agent interface is unavailable",
            _ => "Local agent listener failed; see redacted application logs",
        };
        self.online
            .store(false, std::sync::atomic::Ordering::SeqCst);
        *self.listener_error.write().await = Some(message.into());
    }

    pub async fn mark_listener_stopped(&self) {
        self.online
            .store(false, std::sync::atomic::Ordering::SeqCst);
        *self.listener_error.write().await = Some("Local agent listener stopped".into());
    }

    pub fn source_allowed(&self, source: IpAddr) -> bool {
        match (self.bind.ip(), source) {
            (IpAddr::V4(bind), IpAddr::V4(ip)) if bind == Ipv4Addr::LOCALHOST => {
                ip == Ipv4Addr::LOCALHOST
            }
            (IpAddr::V4(bind), IpAddr::V4(ip)) if bind == Ipv4Addr::new(10, 8, 0, 1) => {
                let parts = ip.octets();
                parts[0] == 10 && parts[1] == 8 && parts[2] == 0
            }
            _ => false,
        }
    }
}

/// A wildcard, LAN, IPv6 or unexpected port is forbidden in every entry path.
fn allowed_agent_bind(bind: SocketAddr) -> bool {
    bind.port() == 8080
        && matches!(
            bind.ip(),
            IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST || ip == Ipv4Addr::new(10, 8, 0, 1)
        )
}

/// A wildcard, LAN, or unexpected bind address is forbidden even in development.
pub fn bind_address() -> Result<SocketAddr, String> {
    let value = std::env::var("SECURITY_AGENT_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let bind: SocketAddr = value.parse().map_err(|_| "Invalid SECURITY_AGENT_BIND")?;
    if !allowed_agent_bind(bind) {
        return Err("Agent may bind only to 127.0.0.1:8080 or 10.8.0.1:8080".into());
    }
    Ok(bind)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unavailable_bearer_credentials_fail_closed_before_agent_setup() {
        let bind = "127.0.0.1:8080".parse().unwrap();
        for token in ["", " ", "\t\n", "\u{2003}"] {
            let error = AgentState::new(token.to_owned(), bind, AgentSettings::default())
                .err()
                .expect("missing or whitespace-only bearer credentials must fail");
            assert_eq!(error, "Agent authentication token is unavailable");
        }
        let state = AgentState::new(
            "nonempty-test-token".to_owned(),
            bind,
            AgentSettings::default(),
        )
        .expect("nonempty bearer credentials must remain supported");
        assert_eq!(state.token, "nonempty-test-token");
    }

    #[test]
    fn constructor_enforces_shared_loopback_and_tunnel_bind_allowlist() {
        for rejected in [
            "0.0.0.0:8080",
            "127.0.0.1:8081",
            "192.168.1.5:8080",
            "10.8.0.2:8080",
            "[::1]:8080",
            "[::ffff:127.0.0.1]:8080",
        ] {
            let bind = rejected.parse().unwrap();
            assert!(!allowed_agent_bind(bind));
            let result = AgentState::new("test-token".into(), bind, AgentSettings::default());
            let err = result.err().expect("unexpected bind must fail closed");
            assert_eq!(err, "Unsupported local agent bind address");
        }
        for allowed in ["127.0.0.1:8080", "10.8.0.1:8080"] {
            let bind = allowed.parse().unwrap();
            assert!(allowed_agent_bind(bind));
            let state = AgentState::new("test-token".into(), bind, AgentSettings::default())
                .expect("approved bind must remain usable");
            assert_eq!(state.bind, bind);
        }
    }

    #[test]
    fn checks_source_network() {
        let state = AgentState::new(
            "token".into(),
            "10.8.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        assert!(state.source_allowed("10.8.0.2".parse().unwrap()));
        assert!(state.source_allowed("10.8.0.1".parse().unwrap()));
        assert!(!state.source_allowed("192.168.1.2".parse().unwrap()));
        assert!(!state.source_allowed("10.8.1.2".parse().unwrap()));
        assert!(!state.source_allowed("127.0.0.1".parse().unwrap()));
        let local = AgentState::new(
            "token".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        assert!(local.source_allowed("127.0.0.1".parse().unwrap()));
        assert!(!local.source_allowed("10.8.0.2".parse().unwrap()));
    }
    #[tokio::test]
    async fn listener_status_tracks_failure_and_recovery_without_leaking_secrets() {
        let state = AgentState::new(
            "secret-token-must-never-leak".into(),
            "127.0.0.1:8080".parse().unwrap(),
            AgentSettings::default(),
        )
        .unwrap();
        let initial = state.status_snapshot().await;
        assert_eq!(initial["online"], false);
        assert!(initial["error"].is_null());

        state
            .mark_listener_failed(&std::io::Error::from(std::io::ErrorKind::AddrInUse))
            .await;
        let failed = state.status_snapshot().await;
        assert_eq!(failed["online"], false);
        assert_eq!(failed["error"], "Local agent port 8080 is already in use");
        assert!(!failed.to_string().contains("secret-token"));

        state.mark_listener_online().await;
        let recovered = state.status_snapshot().await;
        assert_eq!(recovered["online"], true);
        assert!(recovered["error"].is_null());

        state.mark_listener_stopped().await;
        let stopped = state.status_snapshot().await;
        assert_eq!(stopped["online"], false);
        assert_eq!(stopped["error"], "Local agent listener stopped");
    }
}
