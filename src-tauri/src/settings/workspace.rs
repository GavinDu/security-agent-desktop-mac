//! Trusted-host workspace activation. No account identity from IPC/HTTP.
//! This coordinator owns the credential authority and pinned settings handle.
//! Production integration must first revoke old approval/root/peer authority.
use super::{scoped_settings::AccountSettingsDirectory, AgentSettings};
use crate::{
    account_credentials::{
        AccountAuthority, AccountId, ActiveSession, CredentialRef, Purpose, Secret, Store,
    },
    tools::registry::ToolRegistry,
};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum WorkspaceError {
    #[error("Account workspace unavailable")]
    Unavailable,
    #[error("Account settings unavailable")]
    Settings,
    #[error("Account credential unavailable")]
    Credential,
}

struct Workspace {
    session: ActiveSession,
    directory: AccountSettingsDirectory,
    settings: AgentSettings,
}

pub(crate) struct WorkspaceCoordinator<S> {
    support: PathBuf,
    credentials: AccountAuthority<S>,
    active: Option<Workspace>,
}

impl<S: Store> WorkspaceCoordinator<S> {
    pub(crate) fn new(support: &Path, store: S) -> Self {
        Self {
            support: support.to_owned(),
            credentials: AccountAuthority::new(store),
            active: None,
        }
    }

    /// A failed switch never restores the old workspace or authorizes a
    /// target from unvalidated disk state. Only a trusted host calls this.
    pub(crate) fn activate(
        &mut self,
        account: AccountId,
        create: bool,
    ) -> Result<ActiveSession, WorkspaceError> {
        if let Some(previous) = self.active.take() {
            self.credentials
                .deactivate(&previous.session)
                .map_err(|_| WorkspaceError::Unavailable)?;
        }
        let directory = AccountSettingsDirectory::open(&self.support, account.as_uuid(), create)
            .map_err(|_| WorkspaceError::Settings)?
            .ok_or(WorkspaceError::Settings)?;
        let settings = directory.load().map_err(|_| WorkspaceError::Settings)?;
        // Validate every stored root using the existing pinned-root checks.
        // Do not claim these temporary descriptors authorize actual I/O.
        ToolRegistry::canonical_roots(&settings.allowed_roots)
            .map_err(|_| WorkspaceError::Settings)?;
        let session = self
            .credentials
            .activate(account)
            .map_err(|_| WorkspaceError::Unavailable)?;
        self.active = Some(Workspace {
            session,
            directory,
            settings,
        });
        Ok(session)
    }

    pub(crate) fn deactivate(&mut self, session: &ActiveSession) -> Result<(), WorkspaceError> {
        self.current(session)?;
        self.active = None;
        self.credentials
            .deactivate(session)
            .map_err(|_| WorkspaceError::Unavailable)
    }

    fn current(&self, session: &ActiveSession) -> Result<&Workspace, WorkspaceError> {
        self.active
            .as_ref()
            .filter(|workspace| workspace.session == *session)
            .ok_or(WorkspaceError::Unavailable)
    }

    pub(crate) fn settings(
        &self,
        session: &ActiveSession,
    ) -> Result<&AgentSettings, WorkspaceError> {
        Ok(&self.current(session)?.settings)
    }

    /// Persist only after validating the exact current session and roots.
    /// Readback is the acknowledged snapshot, not a grant of live registry
    /// authority. Production root mutation must use its own revocation fence.
    pub(crate) fn replace_settings(
        &mut self,
        session: &ActiveSession,
        settings: AgentSettings,
    ) -> Result<(), WorkspaceError> {
        self.current(session)?;
        ToolRegistry::canonical_roots(&settings.allowed_roots)
            .map_err(|_| WorkspaceError::Settings)?;
        let workspace = self.active.as_mut().ok_or(WorkspaceError::Unavailable)?;
        workspace
            .directory
            .save(&settings)
            .map_err(|_| WorkspaceError::Settings)?;
        workspace.settings = settings;
        Ok(())
    }

    pub(crate) fn install(
        &self,
        session: &ActiveSession,
        integration: Uuid,
        purpose: Purpose,
        secret: &Secret,
    ) -> Result<CredentialRef, WorkspaceError> {
        self.current(session)?;
        self.credentials
            .install(session, integration, purpose, secret)
            .map_err(|_| WorkspaceError::Credential)
    }

    pub(crate) fn read(
        &self,
        session: &ActiveSession,
        reference: &CredentialRef,
    ) -> Result<Secret, WorkspaceError> {
        self.current(session)?;
        self.credentials
            .read(session, reference)
            .map_err(|_| WorkspaceError::Credential)
    }

    pub(crate) fn revoke(
        &self,
        session: &ActiveSession,
        reference: &CredentialRef,
    ) -> Result<(), WorkspaceError> {
        self.current(session)?;
        self.credentials
            .revoke(session, reference)
            .map_err(|_| WorkspaceError::Credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account_credentials::CredentialError, tools::approvals::Policy};
    use std::{cell::RefCell, collections::HashMap, fs, os::unix::fs::PermissionsExt};

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

    #[test]
    fn switching_accounts_fences_settings_and_credentials_and_never_inherits_legacy() {
        let base = tempfile::tempdir().unwrap();
        fs::write(base.path().join("settings.json"), b"legacy authority").unwrap();
        let mut host = WorkspaceCoordinator::new(base.path(), FixtureStore::default());
        let a = AccountId::issue();
        let b = AccountId::issue();
        let first = host.activate(a, true).unwrap();
        let mut settings = AgentSettings::default();
        settings
            .policies
            .insert("bash__run".into(), Policy::Disable);
        host.replace_settings(&first, settings).unwrap();
        let secret = Secret::new("fixture".into()).unwrap();
        let reference = host
            .install(&first, Uuid::new_v4(), Purpose::Mcp, &secret)
            .unwrap();
        assert_eq!(host.read(&first, &reference).unwrap().expose(), "fixture");
        let second = host.activate(b, true).unwrap();
        assert!(host.settings(&second).unwrap().policies.is_empty());
        assert_eq!(
            host.settings(&first).err(),
            Some(WorkspaceError::Unavailable)
        );
        assert_eq!(
            host.read(&second, &reference).err(),
            Some(WorkspaceError::Credential)
        );
        let again = host.activate(a, false).unwrap();
        assert_eq!(
            host.settings(&again).unwrap().policies.get("bash__run"),
            Some(&Policy::Disable)
        );
        assert_eq!(
            host.read(&again, &reference).err(),
            Some(WorkspaceError::Credential)
        );
        assert_eq!(host.deactivate(&first), Err(WorkspaceError::Unavailable));
        host.deactivate(&again).unwrap();
        assert!(host.settings(&again).is_err());
    }

    #[test]
    fn invalid_target_fails_inactive_and_missing_account_does_not_create() {
        let base = tempfile::tempdir().unwrap();
        let mut host = WorkspaceCoordinator::new(base.path(), FixtureStore::default());
        let a = AccountId::issue();
        let b = AccountId::issue();
        let first = host.activate(a, true).unwrap();
        assert_eq!(
            host.activate(b, false).err(),
            Some(WorkspaceError::Settings)
        );
        assert!(host.settings(&first).is_err());
        let next = host.activate(b, true).unwrap();
        let file = base
            .path()
            .join("accounts-v1")
            .join(b.as_uuid().to_string())
            .join("settings.json");
        fs::write(&file, b"{\"unknown\":true}").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            host.activate(b, false).err(),
            Some(WorkspaceError::Settings)
        );
        assert!(host.settings(&next).is_err());
        assert!(host.active.is_none());
    }
}
