//! gnet-discover — standalone coordinator (control plane) for the 0-dep gnet overlay.
//!
//! Independent of the portal-server identity stack. Persists device state in a
//! single JSON file under [`state`]; serves [`api`] via the minimal HTTP/1.1
//! server in [`http`]. Token semantics live in [`auth`].
//!
//! Dependency footprint is intentionally constrained — see memory
//! `[[feedback-gnet-0dep-self-research]]` → "Control plane 边界".

pub mod api;
pub mod auth;
pub mod config;
pub mod http;
pub mod state;
pub mod sync;
pub mod time;
