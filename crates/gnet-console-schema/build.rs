//! Force a re-compile when any migration file changes. `sqlx::migrate!`
//! reads `./migrations/*.sql` at macro-expand time, but cargo only
//! watches the crate's `.rs` files by default — adding or editing a
//! `.sql` file does NOT bust the build cache, so a fresh migration
//! silently doesn't ship until something else triggers a rebuild.
//!
//! Hit on the first SaaS deploy: migration 0005 was committed, the
//! image was built, but the binary still ran the pre-0005 schema
//! because the `gnet-console-schema` crate's `lib.rs` hadn't been
//! touched, so its object file was reused from cache.

fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
