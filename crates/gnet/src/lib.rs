//! `gnet` — a secure UDP channel over the in-house mesh stack
//! (`mesh-noise` Noise_IK + `mesh-crypto` + `mesh-rand`). No external
//! dependencies.
//!
//! The library exposes the building blocks; the binary (`main.rs`) is a thin
//! CLI over them.

/// Per-datagram pump buffer for the mesh data plane: one MTU's worth of room
/// (the overlay MTU is well under this). Shared so the node and tunnel pumps
/// size their recv/send buffers identically.
pub(crate) const MTU_BUF: usize = 2048;

pub mod channel;
pub mod keys;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod node;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod tunnel;
