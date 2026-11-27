//! Trusted, non-IPC account-runtime owner. Synchronous storage operations
//! belong to the host's blocking worker; async retirement drains transport
//! admission separately. No replacement of production AgentState here.
use super::{enrollment::EnrollmentStore, workspace::WorkspaceCoordinator, AgentSettings};
use crate::{
    account_credentials::{AccountId, ActiveSession, CredentialRef, Purpose, Secret, Store},
    tools::approvals::ApprovalGate,
};
use std::{path::Path, sync::Arc};
use uuid::Uuid;

struct Running {
    session: ActiveSession,
    gate: Arc<ApprovalGate>,
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
        let session = self.workspace.activate_enrolled(&self.enrollment, account)
            .map_err(|_| "Workspace activation failed")?;
        let settings = self.workspace.settings(&session).map_err(|_| "Workspace unavailable")?;
        let gate = ApprovalGate::new(settings.policies.clone());
        self.active = Some(Running { session, gate });
        Ok(session)
    }

    fn current(&self, session: &ActiveSession) -> Result<&Running, String> {
        let active = self.active.as_ref()
            .filter(|active| active.session == *session)
            .ok_or("Workspace session unavailable")?;
        active.gate.ensure_running()?;
        Ok(active)
    }

    // Trusted host only: connector constructors receive this session's gate.
    // A retained Arc cannot acquire authority from the next session.
    pub(crate) fn gate(&self, session: &ActiveSession) -> Result<Arc<ApprovalGate>, String> {
        Ok(self.current(session)?.gate.clone())
    }

    pub(crate) fn settings(&self, session: &ActiveSession) -> Result<&AgentSettings, String> {
        self.current(session)?;
        self.workspace.settings(session).map_err(|_| "Workspace unavailable".into())
    }

    pub(crate) fn install(&self, session: &ActiveSession, integration: Uuid, purpose: Purpose, secret: &Secret) -> Result<CredentialRef, String> {
        self.current(session)?;
        self.workspace.install(session,integration,purpose,secret)
            .map_err(|_| "Workspace credential unavailable".into())
    }

    pub(crate) fn read(&self, session: &ActiveSession, reference: &CredentialRef) -> Result<Secret, String> {
        self.current(session)?;
        self.workspace.read(session,reference)
            .map_err(|_| "Workspace credential unavailable".into())
    }

    pub(crate) fn revoke(&self, session: &ActiveSession, reference: &CredentialRef) -> Result<(), String> {
        self.current(session)?;
        self.workspace.revoke(session,reference)
            .map_err(|_| "Workspace credential unavailable".into())
    }

    pub(crate) async fn retire(&mut self, session: &ActiveSession) -> Result<(), String> {
        let active = self.active.as_ref()
            .filter(|active| active.session == *session)
            .ok_or("Workspace session unavailable")?;
        // Do not take active out until the terminal gate is drained and
        // workspace deactivation succeeds. Cancellation leaves a closed
        // gate and a retryable owner, not a new activation opportunity.
        active.gate.retire_after_dispatch().await?;
        self.workspace.deactivate(session).map_err(|_| "Workspace retirement failed")?;
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
    struct FixtureStore(RefCell<HashMap<(String,String),String>>);
    impl Store for FixtureStore {
        fn read(&self, service: &str, account: &str) -> Result<String,CredentialError> {
            self.0.borrow().get(&(service.into(),account.into())).cloned().ok_or(CredentialError::Missing)
        }
        fn write(&self, service: &str, account: &str, value: &str) -> Result<(),CredentialError> {
            self.0.borrow_mut().insert((service.into(),account.into()),value.into());
            Ok(())
        }
        fn delete(&self, service: &str, account: &str) -> Result<(),CredentialError> {
            self.0.borrow_mut().remove(&(service.into(),account.into()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn retirement_cancels_ask_and_waits_for_dispatch_even_if_retry_required() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = WorkspaceRuntime::open(dir.path(),FixtureStore::default()).unwrap();
        let a = host.enroll().unwrap();
        let b = host.enroll().unwrap();
        let first = host.activate(a).unwrap();
        let gate = host.gate(&first).unwrap();
        let epoch = gate.current_epoch().unwrap();
        let lease = gate.dispatch_for_epoch(epoch).await.unwrap();
        let mut events = gate.subscribe();
        let reference = host.install(&first,Uuid::new_v4(),Purpose::Mcp,&Secret::new("fixture".into()).unwrap()).unwrap();
        let pending = {
            let gate = gate.clone();
            tokio::spawn(async move {
                gate.require_explicit_ask_for_epoch(epoch,"fixture__read","fixture").await
            })
        };
        let request = tokio::time::timeout(Duration::from_secs(5),events.recv()).await.unwrap().unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(5),host.retire(&first)).await.is_err());
        assert!(pending.await.unwrap().is_err());
        assert!(!gate.resolve(Uuid::parse_str(&request.id).unwrap(),true).await);
        assert!(host.gate(&first).is_err());
        assert!(host.settings(&first).is_err());
        assert!(host.read(&first,&reference).is_err());
        assert!(host.activate(b).is_err());
        drop(lease);
        host.retire(&first).await.unwrap();
        assert!(gate.current_epoch().is_err());
        let second = host.activate(b).unwrap();
        assert!(host.read(&second,&reference).is_err());
        assert!(host.gate(&first).is_err());
        let fresh = host.gate(&second).unwrap();
        assert!(!Arc::ptr_eq(&gate,&fresh));
        assert!(fresh.current_epoch().is_ok());
        assert!(fresh.ensure_epoch(epoch).is_err());
        host.retire(&second).await.unwrap();
        let third = host.activate(a).unwrap();
        assert!(host.read(&third,&reference).is_err());
        assert!(host.gate(&first).is_err());
    }

    #[test]
    fn unknown_identity_never_activates_and_drop_closes_retained_gate() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = WorkspaceRuntime::open(dir.path(),FixtureStore::default()).unwrap();
        assert!(host.activate(AccountId::issue()).is_err());
        let account = host.enroll().unwrap();
        let first = host.activate(account).unwrap();
        let gate = host.gate(&first).unwrap();
        drop(host);
        assert!(gate.current_epoch().is_err());
        let mut host = WorkspaceRuntime::open(dir.path(),FixtureStore::default()).unwrap();
        assert!(host.gate(&first).is_err());
        assert!(host.accounts().unwrap() == [account]);
        assert!(host.activate(account).is_ok());
    }
}
