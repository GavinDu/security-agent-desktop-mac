# F04.9 / P0 #109 — Production macOS Keychain error redaction

Origin: Desktop Foundation Epic #8 and security Epic #6 / #37. New independently testable issue belongs to latest successor Epic #10 only; physical Mac authenticated smoke #55 remains separate.

## Before
`keyring::Entry::new`, `get_password` and `set_password` failures were formatted using the opaque `keyring::Error` Display implementation, which could propagate OSStatus, account identifiers, keychain paths or backend-specific details into app-startup logs or UI error messages.

## Implemented
The three failures now use a fixed, operation-specific `KeychainFailureKind` mapping. Each backend error is intentionally discarded via `map_err(|_| ...)`; a missing entry (`NoEntry`) still creates a new cryptographically random 32-byte token encoded as URL-safe base64, and any other read failure still fails closed. Existing shorter tokens remain rejected. No token is written to settings or logs, and the code introduces no API-key input.

## Verification and limitations
- Cross-platform Rust test checks the exact fixed messages without instance/service identifiers.
- Node foundation source test pins all three redacted mappings and the `NoEntry`/entropy failure-safe behavior.
- Principal Rust/macOS adversarial source review checks locked Keychain and OSStatus leakage; this is not independent human or physical Mac testing.
- Required CI: all four *current-head* jobs, including native macOS 15 signed-seal check of mounted unsigned developer DMG and artifact upload.
- This is NOT token rotation, device-specific Keychain ACL, offboarding, or a physical Mac post-login/persistence check. Broad #37 and physical #55 remain open.

Reference app: Proton Lumo Desktop is a design comparison only; no GPL code or keyring material is reused.
