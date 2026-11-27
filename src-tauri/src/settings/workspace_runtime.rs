//! Trusted, non-IPC account-runtime owner. Synchronous storage operations
//! belong to the host's blocking worker; async retirement drains transport
//! admission separately. No replacement of production AgentState here.
use super::{enrollment::EnrollmentStore, workspace::WorkspaceCoordinator, AgentSettings};
use crate::{
    account_credentials::{AccountId, ActiveSession, CredentialRef, Purpose, Secret, Store},
    agent::{
        integrated_mcp,
        local_model::LocalModelProvider,
        tool_loop::{LoopAnswer, LoopError, LoopFailure},
    },
    tools::{
        approvals::ApprovalGate,
        mcp_catalog::{McpCatalog, McpPolicy},
        mcp_session::SessionRegistry,
    },
};
use std::{collections::BTreeSet, net::SocketAddrV4, path::Path, sync::Arc};
use uuid::Uuid;

struct Running {
    session: ActiveSession,
    gate: Arc<ApprovalGate>,
    connectors: SessionRegistry,
}

pub(crate) struct WorkspaceRuntime<S> {
    enrollment: EnrollmentStore,
    workspace: WorkspaceCoordinator<S>,
    active: Option<Running>,
}

impl<S: Store> WorkspaceRuntime<S> {
    pub(crate) fn open(support: &Path, store: S) -> Result<Self, String> {
        Ok(Self {
            enrollment: EnrollmentStore::open(support)?,
            workspace: WorkspaceCoordinator::new(support, store),
            active: None,
        })
    }

    pub(crate) fn enroll(&mut self) -> Result<AccountId, String> {
        self.enrollment.enroll()
    }

    pub(crate) fn accounts(&self) -> Result<&[AccountId], String> {
        self.enrollment.accounts()
    }

    // No implicit switch: retirement must be acknowledged first. In
    // particular, a canceled retirement cannot be bypassed by activation.
    pub(crate) fn activate(&mut self, account: AccountId) -> Result<ActiveSession, String> {
        if self.active.is_some() {
            return Err("Retire previous workspace first".into());
        }
        let session = self
            .workspace
            .activate_enrolled(&self.enrollment, account)
            .map_err(|_| "Workspace activation failed")?;
        let settings = self
            .workspace
            .settings(&session)
            .map_err(|_| "Workspace unavailable")?;
        let gate = ApprovalGate::new(settings.policies.clone());
        let connectors = match SessionRegistry::new(gate.clone()) {
            Ok(connectors) => connectors,
            Err(_) => {
                let _ = gate.cancel_pending_for_shutdown();
                let _ = self.workspace.deactivate(&session);
                return Err("Workspace connector authority unavailable".into());
            }
        };
        self.active = Some(Running { session, gate, connectors });
        Ok(session)
    }

    fn current(&self, session: &ActiveSession) -> Result<&Running, String> {
        let active = self
            .active
            .as_ref()
            .filter(|active| active.session == *session)
            .ok_or("Workspace session unavailable")?;
        active.gate.ensure_running()?;
        Ok(active)
    }

    fn current_mut(&mut self, session: &ActiveSession) -> Result<&mut Running, String> {
        let active = self.active.as_mut()
            .filter(|active| active.session == *session)
            .ok_or("Workspace session unavailable")?;
        active.gate.ensure_running()?;
        Ok(active)
    }

    // Trusted host configuration only; neither an owner nor a mutable
    // registry reference escapes this session. All errors are fixed classes.
    pub(crate) async fn add_stdio(&mut self, session: &ActiveSession, id: String, executable: &Path, args: &[String], cwd: &Path) -> Result<(),String> {
        self.current_mut(session)?.connectors.add_stdio(id,executable,args,cwd).await
            .map_err(|_| "Workspace connector unavailable".into())
    }

    pub(crate) async fn add_http(&mut self, session: &ActiveSession, id: String, address: SocketAddrV4) -> Result<(),String> {
        self.current_mut(session)?.connectors.add_http(id,address).await
            .map_err(|_| "Workspace connector unavailable".into())
    }

    pub(crate) async fn remove_connector(&mut self, session: &ActiveSession, id: &str) -> Result<(),String> {
        self.current_mut(session)?.connectors.remove(id).await
            .map_err(|_| "Workspace connector retirement incomplete".into())
    }

    pub(crate) async fn refresh_connector(&mut self, session: &ActiveSession, id: &str) -> Result<(),String> {
        self.current_mut(session)?.connectors.refresh(id).await
            .map_err(|_| "Workspace connector unavailable".into())
    }

    pub(crate) fn set_connector_policy(&mut self, session: &ActiveSession, function: &str, policy: McpPolicy) -> Result<(),String> {
        self.current_mut(session)?.connectors.set_policy(function,policy)
            .map_err(|_| "Workspace connector policy unavailable".into())
    }

    pub(crate) fn planning_catalog(&self, session: &ActiveSession) -> Result<McpCatalog,String> {
        self.current(session)?.connectors.planning_catalog()
            .map_err(|_| "Workspace connector catalog unavailable".into())
    }

    pub(crate) async fn run_agent(&mut self, session: &ActiveSession, provider: &LocalModelProvider, prompt: &str, allowed: &BTreeSet<String>) -> Result<LoopAnswer,LoopFailure> {
        let active = self.current_mut(session).map_err(|_| LoopFailure {
            reason:LoopError::InvalidAuthority,confirmed_executions:0,
        })?;
        integrated_mcp::run(provider,&mut active.connectors,prompt,allowed).await
    }

    // Trusted host only: connector constructors receive this session's gate.
    // A retained Arc cannot acquire authority from the next session.
    pub(crate) fn gate(&self, session: &ActiveSession) -> Result<Arc<ApprovalGate>, String> {
        Ok(self.current(session)?.gate.clone())
    }

    pub(crate) fn settings(&self, session: &ActiveSession) -> Result<&AgentSettings, String> {
        self.current(session)?;
        self.workspace
            .settings(session)
            .map_err(|_| "Workspace unavailable".into())
    }

    pub(crate) fn install(
        &self,
        session: &ActiveSession,
        integration: Uuid,
        purpose: Purpose,
        secret: &Secret,
    ) -> Result<CredentialRef, String> {
        self.current(session)?;
        self.workspace
            .install(session, integration, purpose, secret)
            .map_err(|_| "Workspace credential unavailable".into())
    }

    pub(crate) fn read(
        &self,
        session: &ActiveSession,
        reference: &CredentialRef,
    ) -> Result<Secret, String> {
        self.current(session)?;
        self.workspace
            .read(session, reference)
            .map_err(|_| "Workspace credential unavailable".into())
    }

    pub(crate) fn revoke(
        &self,
        session: &ActiveSession,
        reference: &CredentialRef,
    ) -> Result<(), String> {
        self.current(session)?;
        self.workspace
            .revoke(session, reference)
            .map_err(|_| "Workspace credential unavailable".into())
    }

    pub(crate) async fn retire(&mut self, session: &ActiveSession) -> Result<(), String> {
        let active = self
            .active
            .as_mut()
            .filter(|active| active.session == *session)
            .ok_or("Workspace session unavailable")?;
        // Retain the closed session and any unreaped child on cancellation
        // or retirement failure. Activation is forbidden until success.
        active.gate.retire_after_dispatch().await?;
        active.connectors.retire_all().await
            .map_err(|_| "Workspace connector retirement incomplete")?;
        self.workspace
            .deactivate(session)
            .map_err(|_| "Workspace retirement failed")?;
        self.active = None;
        Ok(())
    }
}

impl<S> Drop for WorkspaceRuntime<S> {
    fn drop(&mut self) {
        if let Some(active) = &self.active {
            // Best effort terminal latch even on owner drop. This cannot
            // await or prove quiescence; already admitted transport may run.
            let _ = active.gate.cancel_pending_for_shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_credentials::CredentialError;
    use std::{cell::RefCell, collections::HashMap, time::Duration};

    #[derive(Default)]
    struct FixtureStore(RefCell<HashMap<(String, String), String>>);
    impl Store for FixtureStore {
        fn read(&self, service: &str, account: &str) -> Result<String, CredentialError> {
            self.0
                .borrow()
                .get(&(service.into(), account.into()))
                .cloned()
                .ok_or(CredentialError::Missing)
        }
        fn write(&self, service: &str, account: &str, value: &str) -> Result<(), CredentialError> {
            self.0
                .borrow_mut()
                .insert((service.into(), account.into()), value.into());
            Ok(())
        }
        fn delete(&self, service: &str, account: &str) -> Result<(), CredentialError> {
            self.0
                .borrow_mut()
                .remove(&(service.into(), account.into()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn retirement_cancels_ask_and_waits_for_dispatch_even_if_retry_required() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = WorkspaceRuntime::open(dir.path(), FixtureStore::default()).unwrap();
        let a = host.enroll().unwrap();
        let b = host.enroll().unwrap();
        let first = host.activate(a).unwrap();
        let gate = host.gate(&first).unwrap();
        let epoch = gate.current_epoch().unwrap();
        let lease = gate.dispatch_for_epoch(epoch).await.unwrap();
        let mut events = gate.subscribe();
        let reference = host
            .install(
                &first,
                Uuid::new_v4(),
                Purpose::Mcp,
                &Secret::new("fixture".into()).unwrap(),
            )
            .unwrap();
        let pending = {
            let gate = gate.clone();
            tokio::spawn(async move {
                gate.require_explicit_ask_for_epoch(epoch, "fixture__read", "fixture")
                    .await
            })
        };
        let request = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(5), host.retire(&first))
                .await
                .is_err()
        );
        assert!(pending.await.unwrap().is_err());
        assert!(
            !gate
                .resolve(Uuid::parse_str(&request.id).unwrap(), true)
                .await
        );
        assert!(host.gate(&first).is_err());
        assert!(host.settings(&first).is_err());
        assert!(host.read(&first, &reference).is_err());
        assert!(host.activate(b).is_err());
        drop(lease);
        host.retire(&first).await.unwrap();
        assert!(gate.current_epoch().is_err());
        let second = host.activate(b).unwrap();
        assert!(host.read(&second, &reference).is_err());
        assert!(host.gate(&first).is_err());
        let fresh = host.gate(&second).unwrap();
        assert!(!Arc::ptr_eq(&gate, &fresh));
        assert!(fresh.current_epoch().is_ok());
        assert!(fresh.ensure_epoch(epoch).is_err());
        host.retire(&second).await.unwrap();
        let third = host.activate(a).unwrap();
        assert!(host.read(&third, &reference).is_err());
        assert!(host.gate(&first).is_err());
    }

    #[test]
    fn unknown_identity_never_activates_and_drop_closes_retained_gate() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = WorkspaceRuntime::open(dir.path(), FixtureStore::default()).unwrap();
        assert!(host.activate(AccountId::issue()).is_err());
        let account = host.enroll().unwrap();
        let first = host.activate(account).unwrap();
        let gate = host.gate(&first).unwrap();
        drop(host);
        assert!(gate.current_epoch().is_err());
        let mut host = WorkspaceRuntime::open(dir.path(), FixtureStore::default()).unwrap();
        assert!(host.gate(&first).is_err());
        assert!(host.accounts().unwrap() == [account]);
        assert!(host.activate(account).is_ok());
    }

    #[tokio::test]
    async fn enrolled_account_owns_mixed_connector_catalog_until_retirement() {
        const CHILD: &str = r#"
IFS= read -r line || exit 1
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}'
IFS= read -r line || exit 2
IFS= read -r line || exit 3
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read","inputSchema":{"type":"object","additionalProperties":false}}]}}'
IFS= read -r line
"#;
        let dir = tempfile::tempdir().unwrap();
        let mut host = WorkspaceRuntime::open(dir.path(),FixtureStore::default()).unwrap();
        let a = host.enroll().unwrap();
        let b = host.enroll().unwrap();
        let first = host.activate(a).unwrap();
        let gate = host.gate(&first).unwrap();
        let args = ["-c".into(),CHILD.into()];
        host.add_stdio(&first,"fixture".into(),Path::new("/bin/sh"),&args,Path::new("/")).await.unwrap();
        assert!(host.add_stdio(&first,"fixture".into(),Path::new("/bin/sh"),&args,Path::new("/")).await.is_err());
        assert!(host.planning_catalog(&first).unwrap().openai_functions().is_empty());
        host.set_connector_policy(&first,"fixture__read",McpPolicy::Auto).unwrap();
        assert_eq!(host.planning_catalog(&first).unwrap().openai_functions().len(),1);
        let reference = host.install(&first,Uuid::new_v4(),Purpose::Mcp,&Secret::new("fixture".into()).unwrap()).unwrap();
        host.retire(&first).await.unwrap();
        assert!(gate.current_epoch().is_err());
        let second = host.activate(b).unwrap();
        assert!(host.planning_catalog(&second).unwrap().openai_functions().is_empty());
        assert!(host.planning_catalog(&first).is_err());
        assert!(host.set_connector_policy(&second,"fixture__read",McpPolicy::Auto).is_err());
        assert!(host.add_stdio(&first,"stale".into(),Path::new("/bin/sh"),&args,Path::new("/")).await.is_err());
        assert!(host.read(&second,&reference).is_err());
        host.add_stdio(&second,"fixture".into(),Path::new("/bin/sh"),&args,Path::new("/")).await.unwrap();
        assert!(host.planning_catalog(&second).unwrap().openai_functions().is_empty());
        host.retire(&second).await.unwrap();
    }
}
