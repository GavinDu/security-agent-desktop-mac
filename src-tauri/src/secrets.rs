use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};

/// No secrets are written to settings.json or logged.
pub fn get_or_create_api_token() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let entry = keyring::Entry::new("com.gavindu.securityagent.desktop", "agent-api-token")
            .map_err(|e| format!("Keychain unavailable: {e}"))?;
        match entry.get_password() {
            Ok(token) if token.len() >= 32 => return Ok(token),
            Ok(_) => return Err("Refusing a short existing API token in Keychain".into()),
            Err(keyring::Error::NoEntry) => {}
            Err(error) => return Err(format!("Keychain read failed: {error}")),
        }
        let mut entropy = [0_u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let token = URL_SAFE_NO_PAD.encode(entropy);
        entry.set_password(&token).map_err(|e| format!("Keychain write failed: {e}"))?;
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
