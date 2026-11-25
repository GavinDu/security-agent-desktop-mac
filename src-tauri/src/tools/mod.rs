pub mod approvals;
pub mod commands;
pub mod pinned_read;
pub mod registry;

// Staged protocol contract: no registered native route until platform acceptance.
#[cfg(test)]
mod native_route;
