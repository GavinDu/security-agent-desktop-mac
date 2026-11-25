pub mod approvals;
pub mod commands;
pub mod pinned_read;
pub mod registry;

// Staged native delivery primitive: compile and test without exposing a new IPC route.
#[cfg(test)]
mod native_delivery;
