pub mod server;

use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, sync::{Arc, atomic::AtomicBool}};
use tokio::sync::Mutex;
use crate::{settings::AgentSettings, tools::{approvals::ApprovalGate, registry::ToolRegistry}};

pub struct AgentState {
    pub token: String,
    pub online: AtomicBool,
    pub bind: SocketAddr,
    pub registry: Arc<ToolRegistry>,
    pub gate: Arc<ApprovalGate>,
    pub settings: Mutex<AgentSettings>,
}

impl AgentState {
    pub fn new(token: String, bind: SocketAddr, settings: AgentSettings) -> Result<Arc<Self>, String> {
        let roots = ToolRegistry::canonical_roots(&settings.allowed_roots)?;
        let gate = ApprovalGate::new(settings.policies.clone());
        let registry = Arc::new(ToolRegistry::new(roots, gate.clone()));
        Ok(Arc::new(Self { token, online: AtomicBool::new(false), bind, registry, gate, settings: Mutex::new(settings) }))
    }

    pub fn source_allowed(&self, source: IpAddr) -> bool {
        match (self.bind.ip(), source) {
            (IpAddr::V4(bind), IpAddr::V4(ip)) if bind == Ipv4Addr::LOCALHOST => ip == Ipv4Addr::LOCALHOST,
            (IpAddr::V4(bind), IpAddr::V4(ip)) if bind == Ipv4Addr::new(10, 8, 0, 1) =>
                {
                    let parts = ip.octets();
                    parts[0] == 10 && parts[1] == 8 && parts[2] == 0
                },
            _ => false,
        }
    }
}

/// A wildcard, LAN, or unexpected bind address is forbidden even in development.
pub fn bind_address() -> Result<SocketAddr, String> {
    let value = std::env::var("SECURITY_AGENT_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let bind: SocketAddr = value.parse().map_err(|_| "Invalid SECURITY_AGENT_BIND")?;
    if bind.port() != 8080 ||
        (bind.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) && bind.ip() != IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))) {
        return Err("Agent may bind only to 127.0.0.1:8080 or 10.8.0.1:8080".into());
    }
    Ok(bind)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checks_source_network() {
        let state = AgentState::new("token".into(), "10.8.0.1:8080".parse().unwrap(), AgentSettings::default()).unwrap();
        assert!(state.source_allowed("10.8.0.2".parse().unwrap()));
        assert!(state.source_allowed("10.8.0.1".parse().unwrap()));
        assert!(!state.source_allowed("192.168.1.2".parse().unwrap()));
        assert!(!state.source_allowed("10.8.1.2".parse().unwrap()));
        assert!(!state.source_allowed("127.0.0.1".parse().unwrap()));
        let local = AgentState::new("token".into(), "127.0.0.1:8080".parse().unwrap(), AgentSettings::default()).unwrap();
        assert!(local.source_allowed("127.0.0.1".parse().unwrap()));
        assert!(!local.source_allowed("10.8.0.2".parse().unwrap()));
    }
}
