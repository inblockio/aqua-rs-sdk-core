//! Clock abstraction for deterministic time injection.
//!
//! Audit-template emission paths (signed audit rounds, P2/P3) need access to
//! the wall-clock time when stamping `created_at` / `opens_at` fields. Going
//! through a `Clock` trait instead of `SystemTime::now()` lets tests and
//! determinism-critical paths inject fixed times.
//!
//! Design:
//! - `Clock` is `Send + Sync` so it can live in shared services (`Arc<dyn Clock>`).
//! - `SystemClock` is the production implementation, reading
//!   `std::time::SystemTime::UNIX_EPOCH`.
//! - `FixedClock(u64)` is the test implementation, returning the configured value.
//!
//! Plan: docs/superpowers/plans/2026-05-10-P1-sdk-foundation.md §5 Task 13.

use std::time::{SystemTime, UNIX_EPOCH};

/// Source of monotonic Unix-seconds time for audit-template emission.
pub trait Clock: Send + Sync {
    /// Return the current time as Unix-seconds since 1970-01-01T00:00:00Z.
    fn now_secs(&self) -> u64;
}

/// Production clock — reads `SystemTime::now()`.
///
/// Returns 0 if the system clock is before the Unix epoch (a degenerate state
/// that should never occur in practice; the underlying call returns an error
/// only if the system time is set before 1970-01-01).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Fixed-time clock for tests and determinism-critical paths.
///
/// Returns the wrapped value verbatim from every `now_secs()` call.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_secs(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_returns_configured_value() {
        let c = FixedClock(1_700_000_000);
        assert_eq!(c.now_secs(), 1_700_000_000);

        let c2 = FixedClock(0);
        assert_eq!(c2.now_secs(), 0);
    }

    #[test]
    fn fixed_clock_is_idempotent() {
        let c = FixedClock(42);
        assert_eq!(c.now_secs(), 42);
        assert_eq!(c.now_secs(), 42);
        assert_eq!(c.now_secs(), 42);
    }

    #[test]
    fn system_clock_is_close_to_system_time() {
        let c = SystemClock;
        let reference = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let observed = c.now_secs();
        // ±2 seconds tolerance allows scheduling/IO variance on slow CI hosts.
        assert!(
            observed.abs_diff(reference) <= 2,
            "SystemClock returned {} which is more than 2s from system time {}",
            observed,
            reference
        );
    }

    /// The `Clock` trait must be object-safe so callers can hold
    /// `Arc<dyn Clock>` / `Box<dyn Clock>` and swap implementations at runtime.
    #[test]
    fn clock_trait_is_object_safe() {
        let system: Box<dyn Clock> = Box::new(SystemClock);
        let fixed: Box<dyn Clock> = Box::new(FixedClock(123));
        assert_eq!(fixed.now_secs(), 123);
        // Just confirm SystemClock through the trait object doesn't panic.
        let _ = system.now_secs();
    }
}
