//! Bounded fixed-window admission for authenticated HTTP tool dispatch.
//! This is keyed by the actual TCP peer IP, never an HTTP forwarding header.
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

pub const REQUESTS_PER_WINDOW: u32 = 60;
/// The unauthenticated readiness probe has an independent, bounded budget.
/// It may not consume the 60/min authenticated tool/catalog allowance.
pub const HEALTH_REQUESTS_PER_WINDOW: u32 = 300;
pub const WINDOW: Duration = Duration::from_secs(60);
const MAX_TRACKED_SOURCES: usize = 256;

#[derive(Clone, Copy)]
struct SourceWindow {
    started: Instant,
    used: u32,
}

/// Shared by all Axum routes served by one AgentState. A std mutex is held
/// for a few in-memory operations only, never across async/tool work.
pub struct SourceRateLimiter {
    windows: Mutex<HashMap<IpAddr, SourceWindow>>,
    max_per_window: u32,
}

impl Default for SourceRateLimiter {
    fn default() -> Self {
        Self::with_limit(REQUESTS_PER_WINDOW)
    }
}

impl SourceRateLimiter {
    /// Use a separate instance for unauthenticated health traffic. A zero
    /// budget denies all requests rather than accidentally allowing them.
    pub(crate) fn with_limit(max_per_window: u32) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            max_per_window,
        }
    }

    pub fn allow(&self, peer: IpAddr) -> bool {
        self.allow_at(peer, Instant::now())
    }

    fn allow_at(&self, peer: IpAddr, now: Instant) -> bool {
        // A poisoned state must not turn a security limit into allow-all.
        let Ok(mut windows) = self.windows.lock() else {
            return false;
        };

        if let Some(window) = windows.get_mut(&peer) {
            if now.saturating_duration_since(window.started) >= WINDOW {
                *window = SourceWindow {
                    started: now,
                    used: 1,
                };
                return true;
            }
            if window.used >= self.max_per_window {
                return false;
            }
            window.used += 1;
            return true;
        }

        if windows.len() >= MAX_TRACKED_SOURCES {
            // Only scan when the capacity is reached; the map can never
            // grow without bound even with many short-lived tunnel peers.
            windows.retain(|_, value| now.saturating_duration_since(value.started) < WINDOW);
            if windows.len() >= MAX_TRACKED_SOURCES {
                return false;
            }
        }

        if self.max_per_window == 0 {
            return false;
        }
        windows.insert(
            peer,
            SourceWindow {
                started: now,
                used: 1,
            },
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn independent_health_budget_is_bounded_and_does_not_spend_tool_allowance() {
        let health = SourceRateLimiter::with_limit(HEALTH_REQUESTS_PER_WINDOW);
        let tools = SourceRateLimiter::default();
        let peer: IpAddr = "10.8.0.2".parse().unwrap();
        let now = Instant::now();
        for _ in 0..HEALTH_REQUESTS_PER_WINDOW {
            assert!(health.allow_at(peer, now));
        }
        assert!(!health.allow_at(peer, now));
        for _ in 0..REQUESTS_PER_WINDOW {
            assert!(tools.allow_at(peer, now));
        }
        assert!(!tools.allow_at(peer, now));
        assert!(health.allow_at(peer, now + WINDOW));
        assert!(tools.allow_at(peer, now + WINDOW));
        let disabled = SourceRateLimiter::with_limit(0);
        assert!(!disabled.allow_at(peer, now));
        assert_eq!(disabled.windows.lock().unwrap().len(), 0);
    }

    #[test]
    fn one_source_gets_exactly_sixty_requests_before_rejection_and_recovers() {
        let limiter = SourceRateLimiter::default();
        let peer: IpAddr = "10.8.0.2".parse().unwrap();
        let now = Instant::now();
        for _ in 0..REQUESTS_PER_WINDOW {
            assert!(limiter.allow_at(peer, now));
        }
        assert!(!limiter.allow_at(peer, now));
        assert!(!limiter.allow_at(peer, now + WINDOW - Duration::from_nanos(1)));
        assert!(limiter.allow_at(peer, now + WINDOW));
        assert!(limiter.allow_at(peer, now + WINDOW));
    }

    #[test]
    fn each_tcp_source_has_its_own_budget() {
        let limiter = SourceRateLimiter::default();
        let now = Instant::now();
        let one: IpAddr = "10.8.0.2".parse().unwrap();
        let two: IpAddr = "10.8.0.3".parse().unwrap();
        for _ in 0..REQUESTS_PER_WINDOW {
            assert!(limiter.allow_at(one, now));
        }
        assert!(!limiter.allow_at(one, now));
        assert!(limiter.allow_at(two, now));
    }

    #[test]
    fn source_table_stays_bounded_and_evicts_only_expired_windows() {
        let limiter = SourceRateLimiter::default();
        let now = Instant::now();
        for n in 0..MAX_TRACKED_SOURCES {
            let peer = IpAddr::V4(Ipv4Addr::new(10, 8, n as u8, 2));
            assert!(limiter.allow_at(peer, now));
        }
        let extra: IpAddr = "10.20.0.1".parse().unwrap();
        assert!(!limiter.allow_at(extra, now));
        assert_eq!(limiter.windows.lock().unwrap().len(), MAX_TRACKED_SOURCES);
        assert!(limiter.allow_at(extra, now + WINDOW));
        assert_eq!(limiter.windows.lock().unwrap().len(), 1);
    }
}
