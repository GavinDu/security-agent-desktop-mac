pub mod approvals;
pub mod commands;
pub mod pinned_read;
pub mod registry;

// Staged native delivery primitive: compile and test without exposing a new IPC route.
#[cfg(test)]
mod native_delivery;

// Staged protocol contract: no registered native route until platform acceptance.
#[cfg(test)]
mod native_route;

// Staged host session contract; no production WebView route.
#[cfg(test)]
mod native_session;
