//! Postgres schema + migrations for the gnet control plane (v1.1).
//!
//! This crate exists separately from `gnet-console` so the daemon-side
//! workspace search (`crates/gnet*`) doesn't accidentally pull axum / sqlx
//! into the zero-deps overlay — the schema crate is small, lib-only, and its
//! only dep is `sqlx` (with `migrate` for the embedded `Migrator`).
//!
//! Console binary calls `MIGRATOR.run(&pool).await` once on startup.

/// Embedded migrations. `sqlx::migrate!` reads `./migrations/*.sql` at compile
/// time, so the resulting binary has zero filesystem dependency on the SQL
/// files at runtime — same single-binary deploy shape as `gnet-discover`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
