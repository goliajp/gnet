//! Daemon lifecycle hooks consumed by `/local/restart` and the
//! control-channel `restart` op (v1.2-plan §18.A3). The daemon does
//! not manage its own resurrection — it just exits cleanly and lets
//! the supervising launchd / systemd unit (see `deploy/launchd/` and
//! `deploy/systemd/`) bring it back up. Running without a supervisor
//! (e.g. dev invocations) is fine; the daemon just stays down.
//!
//! `request_restart()` is idempotent: a second call after one is in
//! flight is a no-op. Exit is scheduled on a background thread with a
//! short delay so the response that triggered the request (HTTP 202
//! on /local/restart, or the snapshot/ack POST on the control
//! channel) has time to flush + close before the process disappears.

use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(not(test))]
use std::thread;
#[cfg(not(test))]
use std::time::Duration;

static RESTART_PENDING: AtomicBool = AtomicBool::new(false);

/// Schedule a clean exit. Second call while one is pending is a no-op.
#[cfg(not(test))]
pub(crate) fn request_restart() {
    if RESTART_PENDING.swap(true, Ordering::SeqCst) {
        return;
    }
    eprintln!("event=daemon_restart_scheduled delay_ms=500");
    thread::spawn(|| {
        thread::sleep(Duration::from_millis(500));
        eprintln!("event=daemon_restart_exit");
        std::process::exit(0);
    });
}

/// Test mirror — flips the flag so handlers can be exercised without
/// the cargo test process killing itself. Inspect via
/// [`was_restart_requested`].
#[cfg(test)]
pub(crate) fn request_restart() {
    RESTART_PENDING.store(true, Ordering::SeqCst);
    eprintln!("event=daemon_restart_scheduled mode=test");
}

#[cfg(test)]
pub(crate) fn was_restart_requested() -> bool {
    RESTART_PENDING.load(Ordering::SeqCst)
}

#[cfg(test)]
pub(crate) fn reset_restart_for_test() {
    RESTART_PENDING.store(false, Ordering::SeqCst);
}
