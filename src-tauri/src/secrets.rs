use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};

const API_TOKEN_BYTES: usize = 32;
const API_TOKEN_TEXT_BYTES: usize = 43;

/// Readback of a generated OS-random bearer must use the exact stable format:
/// 32 binary bytes -> 43 unpadded URL-safe Base64 ASCII characters. This
/// catches truncated/corrupted/legacy Keychain entries without silently
/// replacing their credentials or claiming to measure stored-token entropy.
#[cfg(any(test, target_os = "macos"))]
fn canonical_api_token(token: &str) -> bool {
    if token.len() != API_TOKEN_TEXT_BYTES
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return false;
    }
    match URL_SAFE_NO_PAD.decode(token) {
        Ok(bytes) => bytes.len() == API_TOKEN_BYTES && URL_SAFE_NO_PAD.encode(bytes) == token,
        Err(_) => false,
    }
}

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
            Ok(token) if canonical_api_token(&token) => return Ok(token),
            // Never auto-regenerate a corrupted existing bearer: that could
            // silently invalidate another live client or obscure tampering.
            Ok(_) => return Err("Invalid existing API token in Keychain".into()),
            Err(keyring::Error::NoEntry) => {}
            Err(_) => return Err(redacted_keychain_failure(KeychainFailureKind::Read)),
        }
        let mut entropy = [0_u8; API_TOKEN_BYTES];
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
    fn canonical_api_token_requires_exact_generated_256_bit_encoding() {
        let valid = URL_SAFE_NO_PAD.encode([0xab_u8; API_TOKEN_BYTES]);
        assert_eq!(valid.len(), API_TOKEN_TEXT_BYTES);
        assert!(canonical_api_token(&valid));
        assert!(!canonical_api_token(""));
        assert!(!canonical_api_token("short"));
        assert!(!canonical_api_token(&"A".repeat(32)));
        assert!(!canonical_api_token(&URL_SAFE_NO_PAD.encode([0xab_u8; 31])));
        assert!(!canonical_api_token(&URL_SAFE_NO_PAD.encode([0xab_u8; 33])));
        assert!(!canonical_api_token(&(valid.clone() + "=")));
        assert!(!canonical_api_token(&(" ".to_owned() + &valid[1..])));
        assert!(!canonical_api_token(&("!".to_owned() + &valid[1..])));
        assert!(!canonical_api_token(&("é".to_owned() + &valid[2..])));
        // Trailing Base64 pad bits may not create a second spelling for the
        // same 32-byte value, even if a decoder chooses to accept them.
        let tail = valid.as_bytes()[API_TOKEN_TEXT_BYTES - 1];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let last_index = alphabet.iter().position(|symbol| *symbol == tail).unwrap();
        let noncanonical = format!(
            "{}{}",
            &valid[..API_TOKEN_TEXT_BYTES - 1],
            alphabet[last_index ^ 1] as char
        );
        assert!(!canonical_api_token(&noncanonical));
    }

    #[test]
    fn new_token_encoding_has_the_same_keychain_readback_shape() {
        let mut entropy = [0_u8; API_TOKEN_BYTES];
        OsRng.fill_bytes(&mut entropy);
        let token = URL_SAFE_NO_PAD.encode(entropy);
        assert!(canonical_api_token(&token));
    }

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
