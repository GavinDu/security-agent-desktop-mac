//! Staged account-scoped credential contract. No production account switch,
//! IPC, HTTP, provider or connector reads this module yet. A trusted account
//! lifecycle must supply the current scope; persisted metadata is not authority.

use serde::{Deserialize, Serialize};
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

pub(crate) fn read<S: Store>(
    store: &S,
    scope: &TrustedScope,
    reference: &CredentialRef,
) -> Result<Secret, CredentialError> {
    let name = locator(scope, reference)?;
    Secret::new(store.read(SERVICE, &name)?)
}

pub(crate) fn write<S: Store>(
    store: &S,
    scope: &TrustedScope,
    reference: &CredentialRef,
    secret: &Secret,
) -> Result<(), CredentialError> {
    let name = locator(scope, reference)?;
    store.write(SERVICE, &name, secret.expose())
}

pub(crate) fn delete<S: Store>(
    store: &S,
    scope: &TrustedScope,
    reference: &CredentialRef,
) -> Result<(), CredentialError> {
    let name = locator(scope, reference)?;
    store.delete(SERVICE, &name)
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
}
