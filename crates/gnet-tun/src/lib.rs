//! `gnet-tun` — open and drive an OS TUN device for the gnet data plane.
//!
//! **Zero crates.io dependencies**: FFI to the always-linked system C
//! library (no `libc` crate) plus `std` for fd lifetime management. The
//! device syscalls require `unsafe`; each block carries a `// SAFETY:` note.
//!
//! Both macOS (`utun`) and Linux (`/dev/net/tun`) are implemented.
//!
//! > Opening a TUN device needs elevated privileges (root). This crate
//! > therefore cannot be exercised in unprivileged CI — verify manually
//! > with `sudo` (see `examples/open_tun.rs`).

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::Tun;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Tun;
