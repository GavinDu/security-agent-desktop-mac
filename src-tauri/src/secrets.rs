use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};

// Opaque macOS Security.framework/keyring diagnostics must not be echoed
// into app-startup logs or a user-facing Tauri error. Keep operation class
// for troubleshooting without printing account identifiers, paths or secrets.
#[cfg(any(test, target_os = "macos"))]
#[derive(Clone, Copy)]
enum KeychainFailureKind {
    Entry,
    Read,
    Write,
}

#[cfg(any(test, target_os = "macos"))]
fn redacted_keychain_failure(kind: KeychainFailureKind) -> String {
    match kind {
        KeychainFailureKind::Entry => "Keychain entry initialization failed",
        KeychainFailureKind::Read => "Keychain token read failed",
        KeychainFailureKind::Write => "Keychain token write failed",
    }
    .into()
}

/// No secrets are written to settings.json or logged.
pub fn get_or_create_api_token() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let entry = keyring::Entry::new("com.gavindu.securityagent.desktop", "agent-api-token")
            .map_err(|_| redacted_keychain_failure(KeychainFailureKind::Entry))?;
        match entry.get_password() {
            Ok(token) if token.len() >= 32 => return Ok(token),
            Ok(_) => return Err("Refusing a short existing API token in Keychain".into()),
            Err(keyring::Error::NoEntry) => {}
            Err(_) => return Err(redacted_keychain_failure(KeychainFailureKind::Read)),
        }
        let mut entropy = [0_u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let token = URL_SAFE_NO_PAD.encode(entropy);
        entry
            .set_password(&token)
            .map_err(|_| redacted_keychain_failure(KeychainFailureKind::Write))?;
        Ok(token)
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Fail closed on non-macOS machines; this application targets macOS.
        let _ = URL_SAFE_NO_PAD;
        let _ = OsRng;
        Err("macOS Keychain required".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keychain_backend_failure_messages_are_fixed_and_secret_free() {
        let expected = [
            (
                KeychainFailureKind::Entry,
                "Keychain entry initialization failed",
            ),
            (KeychainFailureKind::Read, "Keychain token read failed"),
            (KeychainFailureKind::Write, "Keychain token write failed"),
        ];
        for (kind, message) in expected {
            let sanitized = redacted_keychain_failure(kind);
            assert_eq!(sanitized, message);
            assert!(!sanitized.contains("agent-api-token"));
            assert!(!sanitized.contains("com.gavindu.securityagent.desktop"));
            assert!(!sanitized.contains("Security.framework"));
        }
    }
}
