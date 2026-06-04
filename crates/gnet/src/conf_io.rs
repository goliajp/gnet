//! Conf file IO helpers shared between the `gnet rotate-key` subcommand
//! (`rotate.rs`, bin-only) and the control-channel `rotate_key` op
//! handler (`node/discovery.rs`, in-process — v1.2-plan §18.A3.2b).
//!
//! Both paths replace the daemon's `private <hex>` directive in place
//! and atomically swap the file via tmp + rename, preserving 0600 perms
//! since the file carries the private key. Lifted out of `rotate.rs` so
//! the library half of the crate can reach the same helpers.

use std::io;
use std::path::Path;

/// Replace the `private <hex>` directive in `text` with the new value.
/// The rest of the file (comments, blank lines, other directives,
/// peers) is preserved byte-for-byte. If no `private` directive exists,
/// returns the original text — callers are expected to have parsed the
/// conf successfully before reaching here, so this is the "no-op when
/// nothing to swap" fallback rather than a real configuration.
pub fn swap_private_directive(text: &str, new_hex: &str) -> String {
    let mut out = String::with_capacity(text.len() + new_hex.len());
    let mut replaced = false;
    for (i, line) in text.lines().enumerate() {
        if !replaced && line.trim_start().starts_with("private ") {
            out.push_str(&format!("private {new_hex}"));
            replaced = true;
        } else {
            out.push_str(line);
        }
        // preserve trailing newline shape — push '\n' after every line,
        // then strip the last one if the original didn't have one.
        if i + 1 < text.lines().count() || text.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

/// Atomic write: stage to a `.{name}.rotate.tmp` sibling, fsync, rename
/// over the target. Preserves the target's permission mode (the file
/// carries the private key — 0600 must survive the swap).
pub fn write_atomic(path: &Path, content: &str) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other(format!("invalid conf path: {}", path.display())))?;
    let final_name = path
        .file_name()
        .ok_or_else(|| io::Error::other("conf path has no filename component"))?
        .to_string_lossy()
        .into_owned();
    let mut tmp = path.to_path_buf();
    tmp.set_file_name(format!(".{final_name}.rotate.tmp"));
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        let _ = parent;
        f.write_all(content.as_bytes())?;
        // preserve 0600 if the target already had it (conf carries the
        // private key, must never be world-readable).
        if let Ok(meta) = std::fs::metadata(path) {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(
                meta.permissions().mode() & 0o7777,
            ));
        }
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_private_keeps_rest_byte_for_byte() {
        let before = "\
# alias gnet-mini
private 0000000000000000000000000000000000000000000000000000000000000001
address  10.42.42.4
address6 fd8d:f090:2ebb::4
listen   0.0.0.0:65432
coordinator http://gnet.golia.jp:65432
device_token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
peer abc def 10.42.42.2 1.2.3.4:65432
";
        let new_hex = "ff".repeat(32);
        let after = swap_private_directive(before, &new_hex);
        assert!(after.contains(&format!("private {new_hex}")));
        assert!(!after.contains("000000000000000000000000000000000000000000000000000000000000000"));
        assert!(after.contains("# alias gnet-mini"));
        assert!(after.contains("device_token aaaaaaaa"));
        assert!(after.contains("peer abc def 10.42.42.2 1.2.3.4:65432"));
        assert_eq!(
            after.matches("\nprivate ").count() + after.starts_with("private ") as usize,
            1
        );
    }

    #[test]
    fn swap_private_replaces_only_first_match() {
        let before = "private 01\nprivate 02\n";
        let after = swap_private_directive(before, "ee");
        assert_eq!(after, "private ee\nprivate 02\n");
    }

    #[test]
    fn swap_private_no_match_returns_unchanged() {
        let before = "address 10.0.0.1\nlisten 0.0.0.0:1\n";
        let after = swap_private_directive(before, "ff");
        assert_eq!(after, before);
    }

    #[test]
    fn swap_private_preserves_trailing_newline_shape() {
        let with_nl = "private 01\n";
        assert_eq!(swap_private_directive(with_nl, "ff"), "private ff\n");
        let no_nl = "private 01";
        assert_eq!(swap_private_directive(no_nl, "ff"), "private ff");
    }

    #[test]
    fn write_atomic_preserves_0600_perms() {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::env::temp_dir();
        let mut r = [0u8; 8];
        gnet_rand::fill(&mut r);
        p.push(format!("gnet-conf-io-test-{}.conf", gnet_hex::encode(&r)));
        std::fs::write(&p, "old\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();

        write_atomic(&p, "new\n").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "new\n");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600, "0600 must survive the tmp+rename dance");
        let _ = std::fs::remove_file(&p);
    }
}
