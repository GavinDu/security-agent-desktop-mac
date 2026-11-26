pub mod approvals;
pub mod commands;
pub mod pinned_read;
pub mod registry;

// Staged native delivery primitive: compile and test without exposing a new IPC route.
#[cfg(any(test, target_os = "macos"))]
mod native_delivery;

// Staged protocol contract: no registered native route until platform acceptance.
#[cfg(any(test, target_os = "macos"))]
mod native_route;

// Staged host session contract; no production WebView route.
#[cfg(any(test, target_os = "macos"))]
mod native_session;

#[cfg(all(target_os = "macos", feature = "native-webkit-fixture"))]
pub(crate) mod native_probe;

#[cfg(any(test, target_os = "macos"))]
pub(crate) mod native_host;
