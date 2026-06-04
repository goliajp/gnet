//! `gnet` — a secure UDP channel over the in-house gnet stack
//! (`gnet-noise` Noise_IK + `gnet-crypto` + `gnet-rand`). No external
//! dependencies.
//!
//! The library exposes the building blocks; the binary (`main.rs`) is a thin
//! CLI over them.

/// Per-datagram pump buffer for the gnet data plane: one MTU's worth of room
/// (the overlay MTU is well under this). Shared so the node and tunnel pumps
/// size their recv/send buffers identically.
pub(crate) const MTU_BUF: usize = 2048;

pub mod channel;
/// In-place conf rewrite helpers used by both the `gnet rotate-key`
/// CLI and the control-channel `rotate_key` op handler (v1.2-plan
/// §18.A3.2).
pub mod conf_io;
/// `/etc/hosts` block splicing — shared by `gnet join` (one-shot) and the
/// daemon's discovery loop (re-splice on every peer-set change).
pub mod hosts;
pub mod keys;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod node;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod tunnel;
