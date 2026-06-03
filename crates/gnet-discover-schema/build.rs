//! Force a re-compile when any migration file changes. `sqlx::migrate!`
//! reads `./migrations/*.sql` at macro-expand time, but cargo only
//! watches the crate's `.rs` files by default — adding or editing a
//! `.sql` file does NOT bust the build cache. Mirrors the parallel
//! build.rs in `gnet-console-schema`.

fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
