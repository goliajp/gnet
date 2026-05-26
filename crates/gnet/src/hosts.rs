//! Splice a gnet-managed block into an `/etc/hosts`-style file.
//!
//! The block is delimited by `# ---BEGIN gnet---` / `# ---END gnet---`
//! so the daemon (via `gnet join`) can re-write its overlay alias→IP
//! mappings idempotently without disturbing hand-edited entries that
//! live outside the markers. Re-joining is the unit of update: a fresh
//! block replaces the old one in place.
//!
//! Format inside the block (one host per address family):
//!
//! ```text
//! # ---BEGIN gnet---
//! 10.42.42.7        gnet-mini
//! fd8d:f090:2ebb::7 gnet-mini
//! 10.42.42.8        gnet-lx64
//! fd8d:f090:2ebb::8 gnet-lx64
//! # ---END gnet---
//! ```
//!
//! Pure functions — no I/O. The caller decides where the file lives
//! and how to write it atomically (see `join.rs`).

const BEGIN_MARKER: &str = "# ---BEGIN gnet---";
const END_MARKER: &str = "# ---END gnet---";

/// Hostname prefix applied to every alias when written into `/etc/hosts`.
/// Keeps the gnet overlay's name-space distinct from anything else the
/// system resolver might already know about (Tailscale MagicDNS, mDNS,
/// other VPN clients, etc.). Coordinator-side aliases stay short
/// (e.g. `lx64`) — the prefix is a splice-time decoration only.
pub const HOST_PREFIX: &str = "gnet-";

/// One overlay host: an alias plus its v4 and/or v6 overlay address.
/// Either family may be absent (e.g. a v4-only peer), in which case
/// that line is not emitted. `alias` is the bare coordinator alias
/// (no `gnet-` prefix) — the prefix is added on splice.
pub struct Entry {
    pub alias: String,
    pub v4: Option<String>,
    pub v6: Option<String>,
}

/// Render the body of the gnet block — no outer markers (those are
/// added by [`splice_block`]). Each entry contributes up to two lines
/// (one A, one AAAA); a missing family contributes none.
pub fn format_block(self_e: &Entry, peers: &[Entry]) -> String {
    let mut out = String::new();
    push_entry(&mut out, self_e);
    for p in peers {
        push_entry(&mut out, p);
    }
    out
}

fn push_entry(out: &mut String, e: &Entry) {
    let host = format!("{HOST_PREFIX}{}", e.alias);
    if let Some(v4) = &e.v4 {
        out.push_str(&format!("{v4}\t{host}\n"));
    }
    if let Some(v6) = &e.v6 {
        out.push_str(&format!("{v6}\t{host}\n"));
    }
}

/// Replace the existing gnet-managed block in `existing` with a fresh
/// one wrapping `body`. If no marker pair is present, append the block
/// (with a blank-line separator). Idempotent: splicing the same body
/// twice yields the same output.
pub fn splice_block(existing: &str, body: &str) -> String {
    let block = format!("{BEGIN_MARKER}\n{body}{END_MARKER}\n");
    if let Some(begin) = existing.find(BEGIN_MARKER)
        && let Some(end_rel) = existing[begin..].find(END_MARKER)
    {
        let end = begin + end_rel;
        // include the END marker's trailing newline so we don't leave a
        // stray blank line behind when the replacement also ends with \n.
        let end_line_end = existing[end..]
            .find('\n')
            .map(|n| end + n + 1)
            .unwrap_or(existing.len());
        let mut out = String::with_capacity(existing.len() + body.len());
        out.push_str(&existing[..begin]);
        out.push_str(&block);
        out.push_str(&existing[end_line_end..]);
        return out;
    }
    // no marker pair — append with a one-line visual separator
    let mut out = String::with_capacity(existing.len() + body.len() + block.len() + 2);
    out.push_str(existing);
    if !existing.is_empty() && !existing.ends_with('\n') {
        out.push('\n');
    }
    if !existing.is_empty() {
        out.push('\n');
    }
    out.push_str(&block);
    out
}

/// Remove the gnet-managed block from `existing`. Idempotent: a hosts
/// file with no marker pair is returned unchanged. Used by
/// `gnet purge-hosts` to give "I don't want gnet touching this any
/// more" a one-command recovery path.
pub fn remove_block(existing: &str) -> String {
    let Some(begin) = existing.find(BEGIN_MARKER) else {
        return existing.to_string();
    };
    let Some(end_rel) = existing[begin..].find(END_MARKER) else {
        return existing.to_string();
    };
    let end = begin + end_rel;
    let end_line_end = existing[end..]
        .find('\n')
        .map(|n| end + n + 1)
        .unwrap_or(existing.len());

    // collapse one blank-line separator that splice_block may have
    // inserted before the block, so the file shape after remove + splice
    // is the same as after splice on a file that never had a block.
    let mut prefix_end = begin;
    let bytes = existing.as_bytes();
    if prefix_end >= 2 && bytes[prefix_end - 1] == b'\n' && bytes[prefix_end - 2] == b'\n' {
        prefix_end -= 1;
    }
    let mut out = String::with_capacity(existing.len());
    out.push_str(&existing[..prefix_end]);
    out.push_str(&existing[end_line_end..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(alias: &str, v4: Option<&str>, v6: Option<&str>) -> Entry {
        Entry {
            alias: alias.into(),
            v4: v4.map(String::from),
            v6: v6.map(String::from),
        }
    }

    #[test]
    fn format_block_emits_both_families_per_entry() {
        // entries carry bare aliases; the splice automatically prefixes them
        // with `gnet-` so they don't collide with Tailscale MagicDNS / mDNS.
        let body = format_block(
            &e("mini", Some("10.42.42.7"), Some("fd8d:f090:2ebb::7")),
            &[e("lx64", Some("10.42.42.8"), Some("fd8d:f090:2ebb::8"))],
        );
        assert_eq!(body.lines().count(), 4);
        assert!(body.contains("10.42.42.7\tgnet-mini"));
        assert!(body.contains("fd8d:f090:2ebb::7\tgnet-mini"));
        assert!(body.contains("10.42.42.8\tgnet-lx64"));
        assert!(body.contains("fd8d:f090:2ebb::8\tgnet-lx64"));
        // and not the bare form (that would shadow Tailscale's `lx64`)
        assert!(!body.contains("10.42.42.7\tmini\n"));
        assert!(!body.contains("10.42.42.8\tlx64\n"));
    }

    #[test]
    fn format_block_skips_absent_family() {
        let body = format_block(
            &e("self", Some("10.0.0.1"), None),
            &[
                e("v4only", Some("10.0.0.2"), None),
                e("v6only", None, Some("fd00::3")),
            ],
        );
        assert_eq!(body.lines().count(), 3);
        assert!(body.contains("10.0.0.1\tgnet-self"));
        assert!(body.contains("10.0.0.2\tgnet-v4only"));
        assert!(body.contains("fd00::3\tgnet-v6only"));
    }

    #[test]
    fn splice_into_empty_appends_block_with_markers() {
        let out = splice_block("", "10.0.0.1\tfoo\n");
        assert!(out.starts_with(BEGIN_MARKER));
        assert!(out.contains("10.0.0.1\tfoo"));
        assert!(out.contains(END_MARKER));
    }

    #[test]
    fn splice_into_unmarked_hosts_appends_after_blank_line() {
        let existing = "127.0.0.1\tlocalhost\n::1\tlocalhost\n";
        let out = splice_block(existing, "10.0.0.1\tfoo\n");
        // original lines preserved
        assert!(out.starts_with("127.0.0.1\tlocalhost\n"));
        assert!(out.contains("::1\tlocalhost\n"));
        // gnet block appended after a visual separator
        assert!(out.contains("\n\n# ---BEGIN gnet---\n"));
        assert!(out.trim_end().ends_with(END_MARKER));
    }

    #[test]
    fn splice_is_idempotent() {
        let existing = "127.0.0.1\tlocalhost\n";
        let once = splice_block(existing, "10.0.0.1\tfoo\n");
        let twice = splice_block(&once, "10.0.0.1\tfoo\n");
        assert_eq!(once, twice, "second splice must produce same bytes");
    }

    #[test]
    fn splice_replaces_existing_block_in_place() {
        let existing = "127.0.0.1\tlocalhost\n\
                        \n\
                        # ---BEGIN gnet---\n\
                        10.0.0.1\told\n\
                        # ---END gnet---\n\
                        # tail line\n";
        let out = splice_block(existing, "10.0.0.2\tnew\n");
        // old payload gone, new payload present
        assert!(!out.contains("10.0.0.1\told"));
        assert!(out.contains("10.0.0.2\tnew"));
        // surrounding non-block lines preserved
        assert!(out.starts_with("127.0.0.1\tlocalhost\n"));
        assert!(out.contains("# tail line\n"));
        // exactly one marker pair
        assert_eq!(out.matches(BEGIN_MARKER).count(), 1);
        assert_eq!(out.matches(END_MARKER).count(), 1);
    }

    #[test]
    fn splice_replaces_when_block_is_at_end_without_trailing_newline() {
        // Edge case: file ends right at END marker with no trailing \n.
        // The splice must still find the block and replace it cleanly.
        let existing = "127.0.0.1\tlocalhost\n\
                        # ---BEGIN gnet---\n\
                        10.0.0.1\told\n\
                        # ---END gnet---";
        let out = splice_block(existing, "10.0.0.2\tnew\n");
        assert!(!out.contains("10.0.0.1\told"));
        assert!(out.contains("10.0.0.2\tnew"));
        assert_eq!(out.matches(BEGIN_MARKER).count(), 1);
        assert_eq!(out.matches(END_MARKER).count(), 1);
    }

    #[test]
    fn remove_block_strips_marker_pair_and_separator() {
        let existing = "127.0.0.1\tlocalhost\n\
                        \n\
                        # ---BEGIN gnet---\n\
                        10.0.0.1\tfoo\n\
                        # ---END gnet---\n\
                        # tail\n";
        let out = remove_block(existing);
        assert_eq!(out, "127.0.0.1\tlocalhost\n# tail\n");
    }

    #[test]
    fn remove_block_is_noop_when_no_marker() {
        let existing = "127.0.0.1\tlocalhost\n";
        assert_eq!(remove_block(existing), existing);
    }

    #[test]
    fn splice_then_remove_returns_to_original() {
        let original = "127.0.0.1\tlocalhost\n";
        let after_splice = splice_block(original, "10.0.0.1\tfoo\n");
        let after_remove = remove_block(&after_splice);
        assert_eq!(after_remove, original);
    }

    #[test]
    fn splice_handles_existing_without_trailing_newline() {
        let existing = "127.0.0.1\tlocalhost"; // no \n
        let out = splice_block(existing, "10.0.0.1\tfoo\n");
        // the missing \n was added before the visual separator + block
        assert!(out.contains("127.0.0.1\tlocalhost\n\n# ---BEGIN gnet---\n"));
    }
}
