//! Staged account-scoped credential contract. No production account switch,
//! IPC, HTTP, provider or connector reads this module yet. A trusted account
//! lifecycle must supply the current scope; persisted metadata is not authority.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;

const SERVICE: &str = "com.gavindu.securityagent.desktop.scoped-credential.v1";
const MAX_SECRET_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct AccountId(Uuid);

impl AccountId {
    pub(crate) fn issue() -> Self {
        Self(Uuid::new_v4())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Purpose {
    Model,
    Mcp,
    OAuthAccess,
    OAuthRefresh,
}

impl Purpose {
    fn label(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Mcp => "mcp",
            Self::OAuthAccess => "oauth-access",
            Self::OAuthRefresh => "oauth-refresh",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CredentialRef {
    account: AccountId,
    integration: Uuid,
    purpose: Purpose,
    generation: Uuid,
}

/// Rust-only context: never deserialize from an IPC/HTTP request. The
/// eventual account manager must check active identity and generation at
/// use time; the staged contract does not implement account activation.
pub(crate) struct TrustedScope(CredentialRef);

impl TrustedScope {
    pub(crate) fn issue(account: AccountId, integration: Uuid, purpose: Purpose) -> Self {
        Self(CredentialRef {
            account,
            integration,
            purpose,
            generation: Uuid::new_v4(),
        })
    }

    pub(crate) fn reference(&self) -> CredentialRef {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CredentialError {
    #[error("Credential scope unavailable")]
    ScopeMismatch,
    #[error("Invalid credential value")]
    InvalidSecret,
    #[error("Credential missing")]
    Missing,
    #[error("Credential store unavailable")]
    StoreUnavailable,
}

// No Debug, Serialize, or Display implementation for secret material.
pub(crate) struct Secret(String);

impl Secret {
    pub(crate) fn new(value: String) -> Result<Self, CredentialError> {
        if value.is_empty() || value.len() > MAX_SECRET_BYTES || value.contains('\0') {
            return Err(CredentialError::InvalidSecret);
        }
        Ok(Self(value))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

pub(crate) trait Store {
    fn read(&self, service: &str, account: &str) -> Result<String, CredentialError>;
    fn write(&self, service: &str, account: &str, value: &str) -> Result<(), CredentialError>;
    fn delete(&self, service: &str, account: &str) -> Result<(), CredentialError>;
}

fn locator(scope: &TrustedScope, reference: &CredentialRef) -> Result<String, CredentialError> {
    if scope.0 != *reference
        || reference.account.0.is_nil()
        || reference.integration.is_nil()
        || reference.generation.is_nil()
    {
        return Err(CredentialError::ScopeMismatch);
    }
    // Fixed typed fields and separators are injective; no user-supplied
    // strings, paths, service names or existing global bearer account.
    Ok(format!(
        "{}:{}:{}:{}",
        reference.account.0,
        reference.integration,
        reference.purpose.label(),
        reference.generation
    ))
}

fn read<S: Store>(
    store: &S,
    scope: &TrustedScope,
    reference: &CredentialRef,
) -> Result<Secret, CredentialError> {
    let name = locator(scope, reference)?;
    Secret::new(store.read(SERVICE, &name)?)
}

fn write<S: Store>(
    store: &S,
    scope: &TrustedScope,
    reference: &CredentialRef,
    secret: &Secret,
) -> Result<(), CredentialError> {
    let name = locator(scope, reference)?;
    store.write(SERVICE, &name, secret.expose())
}

fn delete<S: Store>(
    store: &S,
    scope: &TrustedScope,
    reference: &CredentialRef,
) -> Result<(), CredentialError> {
    let name = locator(scope, reference)?;
    store.delete(SERVICE, &name)
}


// Staged authority for one trusted active local account. Its lock serializes
// store operations and session transitions; do not run blocking Keychain
// operations on an async runtime worker, or hold this lock across an await.
const MAX_ACTIVE_CREDENTIALS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActiveSession {
    account: AccountId,
    incarnation: Uuid,
}

struct ActiveAccount {
    session: ActiveSession,
    slots: Vec<TrustedScope>,
}

struct AuthorityState<S> {
    store: S,
    active: Option<ActiveAccount>,
}

pub(crate) struct AccountAuthority<S> {
    state: Mutex<AuthorityState<S>>,
}

impl<S: Store> AccountAuthority<S> {
    pub(crate) fn new(store: S) -> Self {
        Self {
            state: Mutex::new(AuthorityState {
                store,
                active: None,
            }),
        }
    }

    /// Trusted host only. Re-activation creates a fresh incarnation even for
    /// the same account. No persisted references are implicitly re-authorized.
    pub(crate) fn activate(&self, account: AccountId) -> Result<ActiveSession, CredentialError> {
        if account.0.is_nil() {
            return Err(CredentialError::ScopeMismatch);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| CredentialError::StoreUnavailable)?;
        let session = ActiveSession {
            account,
            incarnation: Uuid::new_v4(),
        };
        state.active = Some(ActiveAccount {
            session,
            slots: Vec::new(),
        });
        Ok(session)
    }

    pub(crate) fn deactivate(&self, session: &ActiveSession) -> Result<(), CredentialError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CredentialError::StoreUnavailable)?;
        active_for(&state.active, session)?;
        state.active = None;
        Ok(())
    }

    /// Only the trusted host can install new credentials. Explicit revocation
    /// is required before replacing a live integration/purpose slot.
    pub(crate) fn install(
        &self,
        session: &ActiveSession,
        integration: Uuid,
        purpose: Purpose,
        secret: &Secret,
    ) -> Result<CredentialRef, CredentialError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CredentialError::StoreUnavailable)?;
        let AuthorityState { store, active } = &mut *state;
        let active = active_for_mut(active, session)?;
        if active.slots.len() >= MAX_ACTIVE_CREDENTIALS
            || active.slots.iter().any(|slot| {
                slot.0.integration == integration && slot.0.purpose == purpose
            })
        {
            return Err(CredentialError::ScopeMismatch);
        }
        let scope = TrustedScope::issue(session.account, integration, purpose);
        let reference = scope.reference();
        write(store, &scope, &reference, secret)?;
        active.slots.push(scope);
        Ok(reference)
    }

    pub(crate) fn read(
        &self,
        session: &ActiveSession,
        reference: &CredentialRef,
    ) -> Result<Secret, CredentialError> {
        let state = self
            .state
            .lock()
            .map_err(|_| CredentialError::StoreUnavailable)?;
        let active = active_for(&state.active, session)?;
        let scope = active
            .slots
            .iter()
            .find(|slot| slot.0 == *reference)
            .ok_or(CredentialError::ScopeMismatch)?;
        read(&state.store, scope, reference)
    }

    /// Revoke in-process authority before attempting deletion. Backend
    /// failure may leave an orphan item, but cannot restore its authority.
    pub(crate) fn revoke(
        &self,
        session: &ActiveSession,
        reference: &CredentialRef,
    ) -> Result<(), CredentialError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CredentialError::StoreUnavailable)?;
        let AuthorityState { store, active } = &mut *state;
        let active = active_for_mut(active, session)?;
        let index = active
            .slots
            .iter()
            .position(|slot| slot.0 == *reference)
            .ok_or(CredentialError::ScopeMismatch)?;
        let scope = active.slots.swap_remove(index);
        delete(store, &scope, reference)
    }
}

fn active_for<'a>(
    active: &'a Option<ActiveAccount>,
    session: &ActiveSession,
) -> Result<&'a ActiveAccount, CredentialError> {
    active
        .as_ref()
        .filter(|active| active.session == *session)
        .ok_or(CredentialError::ScopeMismatch)
}

fn active_for_mut<'a>(
    active: &'a mut Option<ActiveAccount>,
    session: &ActiveSession,
) -> Result<&'a mut ActiveAccount, CredentialError> {
    active
        .as_mut()
        .filter(|active| active.session == *session)
        .ok_or(CredentialError::ScopeMismatch)
}

// Separate from the global agent-api-token. No fallback or regeneration.
#[cfg(target_os = "macos")]
pub(crate) struct MacKeychain;

#[cfg(target_os = "macos")]
fn entry(service: &str, account: &str) -> Result<keyring::Entry, CredentialError> {
    keyring::Entry::new(service, account).map_err(|_| CredentialError::StoreUnavailable)
}

#[cfg(target_os = "macos")]
fn keychain_error(error: keyring::Error) -> CredentialError {
    match error {
        keyring::Error::NoEntry => CredentialError::Missing,
        _ => CredentialError::StoreUnavailable,
    }
}

#[cfg(target_os = "macos")]
impl Store for MacKeychain {
    fn read(&self, service: &str, account: &str) -> Result<String, CredentialError> {
        entry(service, account)?
            .get_password()
            .map_err(keychain_error)
    }

    fn write(&self, service: &str, account: &str, value: &str) -> Result<(), CredentialError> {
        entry(service, account)?
            .set_password(value)
            .map_err(keychain_error)
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), CredentialError> {
        entry(service, account)?
            .delete_credential()
            .map_err(keychain_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, cell::RefCell, collections::HashMap};

    #[derive(Default)]
    struct FakeStore {
        entries: RefCell<HashMap<(String, String), String>>,
        calls: Cell<usize>,
        unavailable: Cell<bool>,
    }

    impl FakeStore {
        fn touch(&self) -> Result<(), CredentialError> {
            self.calls.set(self.calls.get() + 1);
            if self.unavailable.get() {
                return Err(CredentialError::StoreUnavailable);
            }
            Ok(())
        }
    }

    impl Store for FakeStore {
        fn read(&self, service: &str, account: &str) -> Result<String, CredentialError> {
            self.touch()?;
            self.entries
                .borrow()
                .get(&(service.into(), account.into()))
                .cloned()
                .ok_or(CredentialError::Missing)
        }

        fn write(&self, service: &str, account: &str, value: &str) -> Result<(), CredentialError> {
            self.touch()?;
            self.entries
                .borrow_mut()
                .insert((service.into(), account.into()), value.into());
            Ok(())
        }

        fn delete(&self, service: &str, account: &str) -> Result<(), CredentialError> {
            self.touch()?;
            self.entries
                .borrow_mut()
                .remove(&(service.into(), account.into()))
                .map(|_| ())
                .ok_or(CredentialError::Missing)
        }
    }

    #[test]
    fn mismatched_account_purpose_integration_or_generation_never_touches_store() {
        let store = FakeStore::default();
        let account = AccountId::issue();
        let integration = Uuid::new_v4();
        let scope = TrustedScope::issue(account, integration, Purpose::Mcp);
        let reference = scope.reference();
        let secret = Secret::new("fixture-secret".into()).unwrap();
        write(&store, &scope, &reference, &secret).unwrap();
        let calls = store.calls.get();
        for other in [
            TrustedScope(CredentialRef {
                account: AccountId::issue(),
                ..reference
            }),
            TrustedScope(CredentialRef {
                integration: Uuid::new_v4(),
                ..reference
            }),
            TrustedScope(CredentialRef {
                purpose: Purpose::Model,
                ..reference
            }),
            TrustedScope(CredentialRef {
                generation: Uuid::new_v4(),
                ..reference
            }),
        ] {
            assert_eq!(
                read(&store, &other, &reference).err(),
                Some(CredentialError::ScopeMismatch)
            );
            assert_eq!(
                write(&store, &other, &reference, &secret),
                Err(CredentialError::ScopeMismatch)
            );
            assert_eq!(
                delete(&store, &other, &reference),
                Err(CredentialError::ScopeMismatch)
            );
        }
        assert_eq!(store.calls.get(), calls);
        assert_eq!(
            read(&store, &scope, &reference).unwrap().expose(),
            "fixture-secret"
        );
    }

    #[test]
    fn metadata_roundtrip_contains_no_secret_and_rotation_has_distinct_locator() {
        let store = FakeStore::default();
        let account = AccountId::issue();
        let integration = Uuid::new_v4();
        let old = TrustedScope::issue(account, integration, Purpose::OAuthAccess);
        let new = TrustedScope::issue(account, integration, Purpose::OAuthAccess);
        let refresh = TrustedScope::issue(account, integration, Purpose::OAuthRefresh);
        let reference = old.reference();
        let encoded = serde_json::to_string(&reference).unwrap();
        let decoded: CredentialRef = serde_json::from_str(&encoded).unwrap();
        let secret = Secret::new("PRIVATE_CANARY".into()).unwrap();
        write(&store, &old, &decoded, &secret).unwrap();
        assert!(!encoded.contains(secret.expose()));
        assert_ne!(
            locator(&old, &decoded).unwrap(),
            locator(&new, &new.reference()).unwrap()
        );
        assert_ne!(
            locator(&old, &decoded).unwrap(),
            locator(&refresh, &refresh.reference()).unwrap()
        );
        assert_eq!(
            read(&store, &new, &new.reference()).err(),
            Some(CredentialError::Missing)
        );
        delete(&store, &old, &decoded).unwrap();
        assert_eq!(
            read(&store, &old, &decoded).err(),
            Some(CredentialError::Missing)
        );
        assert_eq!(store.entries.borrow().len(), 0);
    }

    #[test]
    fn invalid_secret_and_backend_failure_are_redacted() {
        for value in [
            String::new(),
            "x".repeat(MAX_SECRET_BYTES + 1),
            "a\0b".into(),
        ] {
            assert_eq!(
                Secret::new(value).err(),
                Some(CredentialError::InvalidSecret)
            );
        }
        let store = FakeStore::default();
        let scope = TrustedScope::issue(AccountId::issue(), Uuid::new_v4(), Purpose::Model);
        let reference = scope.reference();
        store.unavailable.set(true);
        let error = read(&store, &scope, &reference).err().unwrap();
        assert_eq!(error.to_string(), "Credential store unavailable");
        assert_eq!(
            write(
                &store,
                &scope,
                &reference,
                &Secret::new("secret".into()).unwrap()
            ),
            Err(error)
        );
        assert_eq!(delete(&store, &scope, &reference), Err(error));
        let invalid = TrustedScope::issue(AccountId::issue(), Uuid::nil(), Purpose::Model);
        assert_eq!(
            read(&store, &invalid, &invalid.reference()).err(),
            Some(CredentialError::ScopeMismatch)
        );
    }

    #[test]
    fn active_session_fences_old_account_and_same_account_reactivation() {
        let authority = AccountAuthority::new(FakeStore::default());
        let account = AccountId::issue();
        let session = authority.activate(account).unwrap();
        let integration = Uuid::new_v4();
        let secret = Secret::new("fixture".into()).unwrap();
        let reference = authority
            .install(&session, integration, Purpose::Mcp, &secret)
            .unwrap();
        assert_eq!(
            authority.read(&session, &reference).unwrap().expose(),
            "fixture"
        );
        let other = authority.activate(AccountId::issue()).unwrap();
        assert_eq!(
            authority.read(&other, &reference).err(),
            Some(CredentialError::ScopeMismatch)
        );
        let again = authority.activate(account).unwrap();
        assert_eq!(
            authority.read(&again, &reference).err(),
            Some(CredentialError::ScopeMismatch)
        );
        assert_eq!(
            authority.install(&session, integration, Purpose::Mcp, &secret).err(),
            Some(CredentialError::ScopeMismatch)
        );
        assert_eq!(
            authority.deactivate(&session),
            Err(CredentialError::ScopeMismatch)
        );
        let replacement = authority
            .install(&again, integration, Purpose::Mcp, &secret)
            .unwrap();
        assert!(replacement != reference);
        authority.deactivate(&again).unwrap();
        assert_eq!(
            authority.read(&again, &replacement).err(),
            Some(CredentialError::ScopeMismatch)
        );
    }

    #[test]
    fn revocation_denies_even_if_store_delete_fails_and_rotation_uses_new_generation() {
        let authority = AccountAuthority::new(FakeStore::default());
        let session = authority.activate(AccountId::issue()).unwrap();
        let integration = Uuid::new_v4();
        let secret = Secret::new("fixture".into()).unwrap();
        let reference = authority
            .install(&session, integration, Purpose::Model, &secret)
            .unwrap();
        assert_eq!(
            authority.install(&session, integration, Purpose::Model, &secret).err(),
            Some(CredentialError::ScopeMismatch)
        );
        authority.state.lock().unwrap().store.unavailable.set(true);
        assert_eq!(
            authority.revoke(&session, &reference),
            Err(CredentialError::StoreUnavailable)
        );
        let calls = authority.state.lock().unwrap().store.calls.get();
        assert_eq!(
            authority.read(&session, &reference).err(),
            Some(CredentialError::ScopeMismatch)
        );
        assert_eq!(authority.state.lock().unwrap().store.calls.get(), calls);
        authority.state.lock().unwrap().store.unavailable.set(false);
        let replacement = authority
            .install(&session, integration, Purpose::Model, &secret)
            .unwrap();
        assert!(reference != replacement);
        assert_eq!(
            authority.read(&session, &reference).err(),
            Some(CredentialError::ScopeMismatch)
        );
        authority.revoke(&session, &replacement).unwrap();
    }

    #[test]
    fn authority_capacity_and_poison_fail_closed() {
        let authority = AccountAuthority::new(FakeStore::default());
        let session = authority.activate(AccountId::issue()).unwrap();
        let secret = Secret::new("fixture".into()).unwrap();
        for _ in 0..MAX_ACTIVE_CREDENTIALS {
            authority
                .install(&session, Uuid::new_v4(), Purpose::Mcp, &secret)
                .unwrap();
        }
        assert_eq!(
            authority.install(&session, Uuid::new_v4(), Purpose::Mcp, &secret).err(),
            Some(CredentialError::ScopeMismatch)
        );
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                let _guard = authority.state.lock().unwrap();
                panic!("fixture poison");
            });
            assert!(worker.join().is_err());
        });
        assert_eq!(
            authority.deactivate(&session),
            Err(CredentialError::StoreUnavailable)
        );
        assert_eq!(
            authority.activate(AccountId::issue()).err(),
            Some(CredentialError::StoreUnavailable)
        );
    }
}
