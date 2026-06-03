//! Ensures `console/dist/index.html` exists before the `include_dir!` macro
//! ingests it at compile time (plan §3.4 — the SPA is embedded into the
//! console / dispatcher / relay binaries). In a freshly cloned tree the
//! operator may not have run `bun run build` yet; without a fallback the
//! macro would refuse to compile. Writes a tiny "SPA not built" stub
//! whenever the real `index.html` is missing — `bun run build` overwrites
//! it on the next SPA build, and cargo reruns this script when the dist
//! tree changes so the embed always matches what's on disk.

use std::path::PathBuf;

const SPA_STUB: &str = include_str!("../../console/dist-stub.html");

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    // crates/<this>/  ->  ../../console/dist
    let dist = manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root above crates/<crate>")
        .join("console")
        .join("dist");

    println!("cargo:rerun-if-changed={}", dist.display());

    let index = dist.join("index.html");
    if !index.exists() {
        std::fs::create_dir_all(&dist).expect("create console/dist");
        std::fs::write(&index, SPA_STUB).expect("write stub index.html");
    }
}
