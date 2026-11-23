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
