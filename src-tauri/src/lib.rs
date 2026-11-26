#[allow(dead_code)]
mod account_credentials;
#[cfg(target_os = "macos")]
mod activation;
mod agent;
mod app;
mod navigation;
mod secrets;
mod settings;
mod single_instance;
mod tools;
mod tray;
mod vpn;

pub use app::run;

#[cfg(all(target_os = "macos", feature = "native-webkit-fixture"))]
pub use tools::native_probe::run as run_native_registry_probe;
