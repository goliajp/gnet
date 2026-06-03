//! Postgres schema + migrations for the **dispatcher** half of the v1.1
//! control plane (formerly known as `gnet-discover`).
//!
//! Sits next to `gnet-console-schema` (the SaaS-side schema). Each crate
//! owns its own `Migrator` so the two halves can evolve independently —
//! a self-host dispatcher has no reason to learn the console's tables,
//! and vice-versa.
//!
//! Architecture: the dispatcher is the admin **source of truth** (see
//! `docs/v1.1-plan.md` §2). Every table here carries `network_id` so the
//! same binary serves the SaaS multi-tenant case and the self-host
//! single-network case without code-path divergence (§7).

/// Embedded migrations. `sqlx::migrate!` reads `./migrations/*.sql` at
/// compile time; the resulting binary has zero filesystem dependency on
/// the SQL files at runtime.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
