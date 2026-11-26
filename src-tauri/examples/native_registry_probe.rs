//! Isolated synthetic fixture; no production state or credentials.
#[cfg(target_os = "macos")]
fn main() {
    let root = tempfile::tempdir().expect("Create isolated fixture root");
    std::fs::write(root.path().join("canary.txt"), "x".repeat(64 * 1024))
        .expect("Write synthetic fixture");
    let code = security_agent_desktop_mac::run_native_registry_probe(
        tauri::generate_context!(),
        root.path(),
    );
    drop(root);
    std::process::exit(code);
}

#[cfg(not(target_os = "macos"))]
fn main() {
    panic!("Registry-backed native WebKit probe requires macOS");
}
